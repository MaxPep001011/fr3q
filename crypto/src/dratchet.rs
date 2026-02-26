use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rand_core::OsRng;
use zeroize::{Zeroize};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

pub const MAX_SKIP: usize = 1000; //max amount of allowed skipped msg chain length

//  ID Structures 
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityPair {
    pub sign_secret: SigningKey,
    pub sign_public: VerifyingKey,
    pub dh_secret: StaticSecret, 
    pub dh_public: PublicKey,
}
impl Zeroize for IdentityPair {
    fn zeroize(&mut self) {
        self.dh_public.zeroize();
        todo!()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreKeyBundle {
    pub identity_sign_pub: VerifyingKey,
    pub identity_dh_pub: PublicKey,
    pub signed_prekey_pub: PublicKey,
    pub signed_prekey_sig: Signature,
    pub one_time_prekeys: Vec<PublicKey>, 
}

#[derive(Serialize, Deserialize)]
pub struct X3dhHeader {
    pub sender_dh_pub: PublicKey,
    pub sender_ephemeral_pub: PublicKey,
    pub used_opk: Option<PublicKey>, 
}

//  Main State 
#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub dh_key_pair: StaticSecret,
    pub remote_dh_pub: PublicKey,
    
    pub our_identity: IdentityPair,
    pub remote_identity_dh: PublicKey,
    
    pub send_n: u32,
    pub recv_n: u32,
    pub prev_n: u32,
    pub skipped_msg_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}
impl Zeroize for RatchetState {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
        self.dh_key_pair.zeroize();
        self.remote_dh_pub.zeroize();
        
        self.our_identity.zeroize();
        self.remote_identity_dh.zeroize();

        self.send_n.zeroize();
        self.recv_n.zeroize();
        self.prev_n.zeroize();
        for key in self.skipped_msg_keys.values_mut() {
            key.zeroize();
        }
    }
}

impl RatchetState {
    pub fn new_alice(our_identity: IdentityPair, bob_bundle: PreKeyBundle) -> Result<(Self, X3dhHeader), String> {
        // 1. Verify Bob's Signed PreKey Signature
        bob_bundle.identity_sign_pub.verify(bob_bundle.signed_prekey_pub.as_bytes(), &bob_bundle.signed_prekey_sig)
            .map_err(|_| "Invalid Signed PreKey Signature".to_string())?;

        // Generate Ephemeral Key
        let (ephemeral_sec, ephemeral_pub) = gen_dh_pair();

        // X3DH (DH1, DH2, DH3, DH4)
        let dh1 = dh(&our_identity.dh_secret, &bob_bundle.signed_prekey_pub);
        let dh2 = dh(&ephemeral_sec, &bob_bundle.identity_dh_pub);
        let dh3 = dh(&ephemeral_sec, &bob_bundle.signed_prekey_pub);
        
        let opk_to_use = bob_bundle.one_time_prekeys.first();
        let dh4 = opk_to_use.map(|opk| dh(&ephemeral_sec, opk));

        // Root Key
        let root_key = kdf_x3dh(&dh1, &dh2, &dh3, dh4.as_ref());

        // Initialize
        let remote_dh_start = bob_bundle.signed_prekey_pub; 
        
        let (new_rk, new_send_ck) = kdf_rk(&root_key, &dh(&ephemeral_sec, &remote_dh_start));

        let state = Self {
            root_key: new_rk,
            send_chain_key: new_send_ck,
            recv_chain_key: [0u8; 32],
            dh_key_pair: ephemeral_sec, 
            remote_dh_pub: remote_dh_start,
            our_identity,
            remote_identity_dh: bob_bundle.identity_dh_pub,
            send_n: 0,
            recv_n: 0,
            prev_n: 0,
            skipped_msg_keys: HashMap::new(),
        };

        let x3dh_header = X3dhHeader {
            sender_dh_pub: state.our_identity.dh_public,
            sender_ephemeral_pub: ephemeral_pub,
            used_opk: opk_to_use.cloned(), 
        };

        Ok((state, x3dh_header))
    }

    pub fn new_bob(
        our_identity: IdentityPair, 
        our_signed_prekey: &StaticSecret, 
        our_one_time_prekey: Option<&StaticSecret>,
        header: &X3dhHeader,
        alice_identity_dh_pub: PublicKey
    ) -> Result<Self, String> {
        
        // X3DH
        let dh1 = dh(our_signed_prekey, &alice_identity_dh_pub);
        let dh2 = dh(&our_identity.dh_secret, &header.sender_ephemeral_pub);
        let dh3 = dh(our_signed_prekey, &header.sender_ephemeral_pub);
        
        let dh4 = if let Some(_opk_pub) = &header.used_opk {
            our_one_time_prekey
                .map(|opk_sec| dh(opk_sec, &header.sender_ephemeral_pub))
        } else {
            None
        };

        if header.used_opk.is_some() && dh4.is_none() {
            return Err("Header contains OPK, but matching secret key was not provided to Bob".to_string());
        }

        let root_key = kdf_x3dh(&dh1, &dh2, &dh3, dh4.as_ref());

        let (new_rk, new_recv_ck) = kdf_rk(&root_key, &dh(our_signed_prekey, &header.sender_ephemeral_pub));

        Ok(Self {
            root_key: new_rk,
            send_chain_key: [0u8; 32], 
            recv_chain_key: new_recv_ck,
            dh_key_pair: our_signed_prekey.clone(),
            remote_dh_pub: header.sender_ephemeral_pub,
            our_identity,
            remote_identity_dh: alice_identity_dh_pub,
            send_n: 0,
            recv_n: 0,
            prev_n: 0,
            skipped_msg_keys: HashMap::new(),
        })
    }

    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(MsgHeader, Vec<u8>), String> {
        let (next_ck, mk) = kdf_ck(&self.send_chain_key);
        self.send_chain_key = next_ck;
        
        let head = header(&PublicKey::from(&self.dh_key_pair), self.prev_n, self.send_n);
        let auth_data = concat(ad, &head);
        let ciphertext = encrypt(&mk, plaintext, &auth_data)?;
        
        self.send_n += 1;
        Ok((head, ciphertext))
    }

    pub fn ratchet_decrypt(&mut self, header: &MsgHeader, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(mk) = self.skipped_msg_keys.remove(&(*header.dh_pub.as_bytes(), header.n)) {
            let auth_data = concat(ad, header);
            return decrypt(&mk, ciphertext, &auth_data);
        }

        if header.dh_pub != self.remote_dh_pub {
            let old_key = self.remote_dh_pub.clone();
            self.skip_message_keys(header.pn, &old_key)?;
            self.dh_ratchet(header);
        }

        let current_key = self.remote_dh_pub.clone();
        self.skip_message_keys(header.n, &current_key)?;

        let (next_ck, mk) = kdf_ck(&self.recv_chain_key);
        self.recv_chain_key = next_ck;
        self.recv_n += 1;

        let auth_data = concat(ad, header);
        decrypt(&mk, ciphertext, &auth_data)
    }

    fn dh_ratchet(&mut self, header: &MsgHeader) {
        self.prev_n = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;
        self.remote_dh_pub = header.dh_pub;

        let (rk1, ck_recv) = kdf_rk(&self.root_key, &dh(&self.dh_key_pair, &self.remote_dh_pub));
        self.root_key = rk1;
        self.recv_chain_key = ck_recv;

        let (our_new_secret, _) = gen_dh_pair();
        self.dh_key_pair = our_new_secret;

        let (rk2, ck_send) = kdf_rk(&self.root_key, &dh(&self.dh_key_pair, &self.remote_dh_pub));
        self.root_key = rk2;
        self.send_chain_key = ck_send;
    }

    fn skip_message_keys(&mut self, until: u32, key_to_use: &PublicKey) -> Result<(), String> {
        if (self.recv_n + MAX_SKIP as u32) < until {
            return Err("Too many skipped messages".to_string());
        }
        while self.recv_n < until {
            let (next_ck, mk) = kdf_ck(&self.recv_chain_key);
            self.recv_chain_key = next_ck;
            self.skipped_msg_keys.insert((*key_to_use.as_bytes(), self.recv_n), mk);
            self.recv_n += 1;
        }
        Ok(())
    }
}

//  Helpers 

pub fn gen_dh_pair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn dh(our_secret: &StaticSecret, their_pub: &PublicKey) -> [u8; 32] {
    *our_secret.diffie_hellman(their_pub).as_bytes()
}

pub fn kdf_x3dh(dh1: &[u8;32], dh2: &[u8;32], dh3: &[u8;32], dh4: Option<&[u8;32]>) -> [u8; 32] {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(&[0xFF; 32]);
    input.extend_from_slice(dh1);
    input.extend_from_slice(dh2);
    input.extend_from_slice(dh3);
    if let Some(d4) = dh4 {
        input.extend_from_slice(d4);
    }
    
    let h = Hkdf::<Sha256>::new(None, &input);
    let mut okm = [0u8; 32];
    h.expand(b"freq-x3dh", &mut okm).expect("HKDF expand failed");
    okm
}

pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    h.expand(b"freq-ratchet-rk", &mut okm).expect("HKDF expand failed");
    
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    new_ck.copy_from_slice(&okm[32..64]);
    (new_rk, new_ck)
}

pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = Hkdf::<Sha256>::new(Some(ck), &[0x01]);
    let mut msg_key = [0u8; 32];
    h.expand(b"freq-msg-key", &mut msg_key).expect("HKDF expand failed");

    let h_next = Hkdf::<Sha256>::new(Some(ck), &[0x02]);
    let mut next_ck = [0u8; 32];
    h_next.expand(b"freq-chain-key", &mut next_ck).expect("HKDF expand failed");
    (next_ck, msg_key)
}

pub fn encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(mk));
    let nonce = Nonce::from_slice(&[0u8; 12]); 
    let payload = aes_gcm::aead::Payload { msg: plaintext, aad: ad };
    cipher.encrypt(nonce, payload).map_err(|e| e.to_string())
}

pub fn decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(mk));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let payload = aes_gcm::aead::Payload { msg: ciphertext, aad: ad };
    cipher.decrypt(nonce, payload).map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MsgHeader {
    pub dh_pub: PublicKey,
    pub pn: u32,
    pub n: u32,
}

pub fn header(our_dh: &PublicKey, pn: u32, n: u32) -> MsgHeader {
    MsgHeader { dh_pub: *our_dh, pn, n }
}

pub fn concat(ad: &[u8], header: &MsgHeader) -> Vec<u8> {
    let mut res = ad.to_vec();
    res.extend_from_slice(header.dh_pub.as_bytes());
    res.extend_from_slice(&header.pn.to_be_bytes());
    res.extend_from_slice(&header.n.to_be_bytes());
    res
}

// TESTS MODULE (THX to gemini)
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey}; 
    #[test]
    fn test_x3dh_logic_only() {
        pub fn gen_sign_pair() -> (SigningKey, VerifyingKey) {
            let mut rng = OsRng;
            let signing_key = SigningKey::generate(&mut rng);
            let verifying_key = signing_key.verifying_key();
            (signing_key, verifying_key)
        }
        // 1. Create Alice's Identity
        let (alice_sign_sec, alice_sign_pub) = gen_sign_pair(); // Assuming you have these helpers
        let (alice_dh_sec, alice_dh_pub) = gen_dh_pair();
        let alice_id = IdentityPair {
            sign_public: alice_sign_pub,
            sign_secret: alice_sign_sec,
            dh_public: alice_dh_pub,
            dh_secret: alice_dh_sec,
        };

        // 2. Create Bob's Identity and Bundle
        let (bob_sign_sec, bob_sign_pub) = gen_sign_pair();
        let (bob_dh_sec, bob_dh_pub) = gen_dh_pair();
        let (bob_spk_sec, bob_spk_pub) = gen_dh_pair();
        let bob_spk_sig = bob_sign_sec.sign(bob_spk_pub.as_bytes());

        let bob_id = IdentityPair {
            sign_public: bob_sign_pub,
            sign_secret: bob_sign_sec,
            dh_public: bob_dh_pub,
            dh_secret: bob_dh_sec,
        };

        // 3. Create Bob's PreKey Bundle (Alice gets this from the "server")
        let bob_bundle = PreKeyBundle {
            identity_sign_pub: bob_sign_pub,
            identity_dh_pub: bob_dh_pub,
            signed_prekey_pub: bob_spk_pub,
            signed_prekey_sig: bob_spk_sig,
            one_time_prekeys: Vec::new(), // Testing without OPKs for now
        };

        // 4. ALICE STARTS
        let (mut alice_state, x3dh_header) = RatchetState::new_alice(
            alice_id.clone(), 
            bob_bundle
        ).expect("Alice logic failed");

        // 5. BOB ACCEPTS
        // Note: We use alice_id.dh_public here, NOT her sign_public
        let mut bob_state = RatchetState::new_bob(
            bob_id,
            &bob_spk_sec,
            None, // No OPK secret
            &x3dh_header,
            alice_id.dh_public 
        ).expect("Bob logic failed");

        // 6. THE TRUTH TEST: DERIVED KEYS
        assert_eq!(alice_state.root_key, bob_state.root_key, "ROOT KEY MISMATCH");
        
        // Test the first Ratchet step
        let msg = b"Logic Test";
        let (header, ciphertext) = alice_state.ratchet_encrypt(msg, b"").unwrap();
        let decrypted = bob_state.ratchet_decrypt(&header, &ciphertext, b"").unwrap();

        assert_eq!(msg.to_vec(), decrypted, "Decryption failed - keys are not aligned");
        println!("[SUCCESS] X3DH and Ratchet logic is verified.");
    }
    #[test]
    fn debug_x3dh_serialization_mismatch() {
        // 1. Setup Identities
        let alice_sign_sec = SigningKey::generate(&mut OsRng);
        let alice_dh_sec = StaticSecret::random_from_rng(OsRng);
        
        let alice_id = IdentityPair {
            sign_public: alice_sign_sec.verifying_key(),
            sign_secret: alice_sign_sec,
            dh_secret: alice_dh_sec.clone(),
            dh_public: PublicKey::from(&alice_dh_sec),
        };

        let bob_sign_sec = SigningKey::generate(&mut OsRng);
        let bob_dh_sec = StaticSecret::random_from_rng(OsRng);
        let bob_spk_sec = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_sec);
        
        let bob_bundle = PreKeyBundle {
            identity_sign_pub: bob_sign_sec.verifying_key(),
            identity_dh_pub: PublicKey::from(&bob_dh_sec),
            signed_prekey_pub: bob_spk_pub,
            signed_prekey_sig: bob_sign_sec.sign(bob_spk_pub.as_bytes()),
            one_time_prekeys: Vec::new(), 
        };

        // 3. Alice Inits (This generates the header)
        let (_alice, x3dh_header) = RatchetState::new_alice(alice_id.clone(), bob_bundle)
            .expect("Alice init failed");

        // THE DIAGNOSTIC PART
        let json_output = serde_json::to_string_pretty(&x3dh_header)
            .expect("Failed to serialize header");
        
        println!("\n=== ALICE'S GENERATED HEADER JSON ===");
        println!("{}", json_output);
        println!("=====================================\n");

        let deserialized_header: Result<X3dhHeader, _> = serde_json::from_str(&json_output);

        match deserialized_header {
            Ok(h) => {
                println!("[SUCCESS] Header successfully round-tripped.");
                // Ensure the fields match
                assert_eq!(h.sender_dh_pub, x3dh_header.sender_dh_pub);
            },
            Err(e) => {
                println!("[FAILURE] Deserialization Error: {}", e);
                panic!("STRUCT MISMATCH DETECTED: Serde cannot find a field in the JSON it just created. Check field names in X3dhHeader.");
            }
        }
    }

    #[test]
    fn test_x3dh_and_ratchet() {
        // 1. Setup Identities
        let alice_sign_sec = SigningKey::generate(&mut OsRng);
        let alice_dh_sec = StaticSecret::random_from_rng(OsRng);
        let alice_dh_pub = PublicKey::from(&alice_dh_sec);
        
        let alice_id = IdentityPair {
            sign_public: alice_sign_sec.verifying_key(),
            sign_secret: alice_sign_sec,
            dh_secret: alice_dh_sec,
            dh_public: alice_dh_pub,
        };

        // 2. Setup Bob (PreKeys)
        let bob_sign_sec = SigningKey::generate(&mut OsRng);
        let bob_dh_sec = StaticSecret::random_from_rng(OsRng);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);
        
        let bob_spk_sec = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_sec);
        
        let bob_spk_sig = bob_sign_sec.sign(bob_spk_pub.as_bytes());

        // --- Use an empty Vec for testing without OPKs ---
        let bob_bundle = PreKeyBundle {
            identity_sign_pub: bob_sign_sec.verifying_key(),
            identity_dh_pub: bob_dh_pub,
            signed_prekey_pub: bob_spk_pub,
            signed_prekey_sig: bob_spk_sig,
            one_time_prekeys: Vec::new(), 
        };

        let bob_id = IdentityPair {
            sign_secret: bob_sign_sec,
            sign_public: bob_bundle.identity_sign_pub,
            dh_secret: bob_dh_sec,
            dh_public: bob_dh_pub,
        };

        // 3. Alice Inits (X3DH)
        let (mut alice, x3dh_header) = RatchetState::new_alice(alice_id.clone(), bob_bundle).expect("Alice init failed");

        // 4. Bob Inits (X3DH)
        let mut bob = RatchetState::new_bob(
            bob_id, 
            &bob_spk_sec, 
            None, // No OPK secret for this test
            &x3dh_header, 
            alice_id.dh_public
        ).expect("Bob init failed");

        // 5. Chat
        let msg = b"X3DH Works!";
        let (head, cipher) = alice.ratchet_encrypt(msg, b"meta").unwrap();
        let decrypted = bob.ratchet_decrypt(&head, &cipher, b"meta").unwrap();
        
        assert_eq!(msg.to_vec(), decrypted);
    }
}