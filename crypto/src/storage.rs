use crate::dratchet::{RatchetState, IdentityPair};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File};
use std::io::{Read, Write};
use std::path::Path;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{StaticSecret, PublicKey as DhPublicKey};
use ed25519_dalek::{Signer};
use crate::dratchet::{PreKeyBundle};

// Constants
//constant salt for now (useless) TODO: implement random salt
const VAULT_SALT: &str = "FreqSecureSaltV123456789"; 
const MAX_HISTORY: usize = 500;
const MAX_SYSTEM_LOGS: usize = 1000;


//  LOGGING 

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatEntry {
    pub sender: [u8; 32],
    pub timestamp: u64,
    pub text: String,
    pub file_path: Option<String>,
}
impl Zeroize for ChatEntry {
    fn zeroize(&mut self) {
        self.sender.zeroize();
        self.timestamp.zeroize();
        self.text.zeroize();
        self.file_path.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemLogEntry {
    pub timestamp: u64,
    pub level: String, // "INFO", "WARN", "ERROR"
    pub message: String,
}
impl Zeroize for SystemLogEntry {
    fn zeroize(&mut self) {
        self.timestamp.zeroize();
        self.level.zeroize();
        self.message.zeroize();
    }
}

//  PROFILE & POLICY 

#[derive(Serialize, Deserialize, Clone)]
pub struct Policy {
    pub mode: String, // "allow", "whitelist"
    pub whitelist: HashSet<String>, // Set of Hex Public Keys
    pub blacklist: HashSet<String>,
}
impl Zeroize for Policy {
    fn zeroize(&mut self) {
        self.mode.zeroize();
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: "allow".to_string(),
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Profile {
    pub nickname: String,
    // Maps Alias Name -> 1 ident key
    pub aliases: HashMap<String, [u8; 32]>, 
    // Maps Server Name -> "url:port"
    pub servers: HashMap<String, String>,
    // Maps Server -> Alias keys
    pub server_links: HashMap<String, Vec<[u8; 32]>>,

    pub msg_policy: Policy,
    pub file_policy: Policy,
    pub max_msg_size: u64,

    pub download_dir: String,
    pub tor_proxy: String, // "127.0.0.1:9050"
}
impl Zeroize for Profile {
    fn zeroize(&mut self) {
        self.nickname.zeroize();
        for key in self.aliases.values_mut() {
            key.zeroize();
        }
        for url in self.servers.values_mut() {
            url.zeroize();
        }
        for key in self.server_links.values_mut() {
            key.zeroize();
        }
        self.msg_policy.zeroize();// !
        self.file_policy.zeroize();// !
        self.max_msg_size.zeroize();

        self.download_dir.zeroize();
        self.tor_proxy.zeroize();
    }
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            nickname: "Anon".to_string(),
            aliases: HashMap::new(),
            servers: HashMap::new(),
            server_links: HashMap::new(),
            msg_policy: Policy::default(),
            file_policy: Policy { mode: "whitelist".to_string(), ..Default::default() },
            tor_proxy: "127.0.0.1:9050".to_string(),
            max_msg_size: 10_000_000, // 10 MB default
            download_dir: "".to_string(),
        }
    }
}

//  MAIN VAULT 

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Vault {
    pub identity: IdentityPair,
    pub profile: Profile,
    
    pub spk_secret: [u8; 32],
    pub otk_secrets: HashMap<[u8; 32], [u8; 32]>,
    
    pub sessions: HashMap<[u8; 32], RatchetState>,
    pub chats: HashMap<[u8; 32], VecDeque<ChatEntry>>,
    pub system_logs: VecDeque<SystemLogEntry>,
}
impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.identity.zeroize();
        self.profile.zeroize();
        
        self.spk_secret.zeroize();
        self.otk_secrets.clear();

        for state in self.sessions.values_mut() {
            state.zeroize();
        }

        for chat in self.chats.values_mut() {
            for entry in chat.iter_mut() {
                entry.zeroize();
            }
        }

        for entry in self.system_logs.iter_mut() {
            entry.zeroize();
        }

    }
}
impl Vault {
    pub fn new(identity: IdentityPair) -> Self {
        Self {
            identity,
            profile: Profile::default(),
            spk_secret: [0u8; 32], // Generated on first bundle request
            otk_secrets: HashMap::new(),
            sessions: HashMap::new(),
            chats: HashMap::new(),
            system_logs: VecDeque::new(),
        }
    }
    //  OTK PRE KEYGEN 
    pub fn generate_registration_bundle(&mut self, count: usize) -> PreKeyBundle {
        let mut rng = OsRng;

        let spk_sec = StaticSecret::random_from_rng(&mut rng);
        let spk_pub = DhPublicKey::from(&spk_sec);
        self.spk_secret = spk_sec.to_bytes();

        let signature = self.identity.sign_secret.sign(spk_pub.as_bytes());

        let mut bundle_opks = Vec::new();
        
        for _ in 0..count {
            let otk_sec = StaticSecret::random_from_rng(&mut rng);
            let otk_pub = DhPublicKey::from(&otk_sec);
            
            let pub_bytes = *otk_pub.as_bytes();
            let sec_bytes = otk_sec.to_bytes();
            
            self.otk_secrets.insert(pub_bytes, sec_bytes);
            
            // Add public key to the bundle list
            bundle_opks.push(otk_pub);
        }

        PreKeyBundle {
            identity_sign_pub: self.identity.sign_public,
            identity_dh_pub: self.identity.dh_public,
            signed_prekey_pub: spk_pub,
            signed_prekey_sig: signature,
            one_time_prekeys: bundle_opks, // This is now your Vec<PublicKey>
        }
    }
    //  LOGGING HELPERS 
    
    pub fn add_chat_log(
        &mut self, 
        tid: [u8; 32],
        sender: [u8; 32],
        timestamp: u64,
        msg: String,
        file_path: Option<String>
    ) {
        let entry = ChatEntry {
            sender,
            timestamp,
            text: msg,
            file_path,
        };
        
        let log = self.chats.entry(tid).or_insert_with(VecDeque::new);
        log.push_back(entry);
        
        if log.len() > MAX_HISTORY { 
            log.pop_front(); 
        }
    }

    pub fn log_event(&mut self, level: &str, msg: &str) {
        let entry = SystemLogEntry {
            timestamp: get_time(),
            level: level.to_string(),
            message: msg.to_string(),
        };
        self.system_logs.push_back(entry);
        if self.system_logs.len() > MAX_SYSTEM_LOGS { self.system_logs.pop_front(); }
    }

    //  ENCRYPTION IO
    
    pub fn save(&self, path: &str, password: &str) -> Result<(), String> {
        let plaintext = bincode::serialize(self).map_err(|e| e.to_string())?;
        let key = derive_key(password);
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(&key);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| e.to_string())?;

        let mut file = File::create(path).map_err(|e| e.to_string())?;
        file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;
        file.write_all(&ciphertext).map_err(|e| e.to_string())?;
        
        Ok(())
    }

    pub fn load(path: &str, password: &str) -> Result<Self, String> {
        if !Path::new(path).exists() {
            return Err("Vault file not found".to_string());
        }
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        
        let mut nonce_bytes = [0u8; 12];
        if file.read_exact(&mut nonce_bytes).is_err() {
            return Err("Vault file corrupted".to_string());
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext).map_err(|e| e.to_string())?;

        let key = derive_key(password);
        let cipher = Aes256Gcm::new(&key);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Incorrect password or corrupted vault".to_string())?;

        let vault: Vault = bincode::deserialize(&plaintext).map_err(|e| e.to_string())?;
        Ok(vault)
    }
}

// Helpers
fn derive_key(password: &str) -> Key<Aes256Gcm> {
    let salt = SaltString::from_b64(VAULT_SALT).unwrap();
    let argon2 = Argon2::default();
    let output = argon2.hash_password(password.as_bytes(), &salt).unwrap().hash.unwrap();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&output.as_bytes()[0..32]); 
    *Key::<Aes256Gcm>::from_slice(&key_bytes)
}

fn get_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}