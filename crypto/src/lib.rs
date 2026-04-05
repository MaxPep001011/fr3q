#![allow(unsafe_op_in_unsafe_fn)]
use pyo3::prelude::*;
use pyo3::types::PyBytes;
//use to replace PyResult<PyObject>s (deprecated)
//use pyo3::conversion::IntoPyObject;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey};
use rand_core::OsRng;
use zeroize::{Zeroize};
use std::fs::File;
use std::io::{Read};

mod dratchet;
mod storage; 

use crate::dratchet::{RatchetState, PreKeyBundle, X3dhHeader};
use crate::storage::Vault;

#[pyclass]
pub struct PyVault {
    inner: Option<Vault>, 
    file_path: String,
    password: String, 
}

// =========================================================================
//  INTERNAL RUST HELPERS
// =========================================================================
impl PyVault {
    /// Get Immutable Reference
    fn _get_inner(&self) -> PyResult<&Vault> {
        self.inner.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Vault is locked")
        })
    }
    
    /// Get Mutable Reference
    fn _get_inner_mut(&mut self) -> PyResult<&mut Vault> {
        self.inner.as_mut().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Vault is locked")
        })
    }
    /// Turn an alias or hex string into a 32-byte key
    fn resolve_key(&self, alias_or_key_hex: &str) -> PyResult<[u8; 32]> {
        let v = self._get_inner()?;
        if let Some(key) = v.profile.aliases.get(alias_or_key_hex) {
            return Ok(*key);
        }
        // Decode hex str
        match hex::decode(alias_or_key_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            }
            _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Could not resolve '{}' to a valid alias or key", alias_or_key_hex)
            )),
        }
    }

}

// =========================================================================
//  PYTHON API
// =========================================================================
#[pymethods]
impl PyVault {

    //  SETUP 

    #[staticmethod]
    fn create_new(path: String, password: String) -> PyResult<Self> {
        let sign_sec = SigningKey::generate(&mut OsRng);
        let dh_sec = StaticSecret::random_from_rng(OsRng);
        
        let id = dratchet::IdentityPair {
            sign_public: sign_sec.verifying_key(),
            sign_secret: sign_sec,
            dh_secret: dh_sec.clone(),
            dh_public: PublicKey::from(&dh_sec),
        };

        let vault = Vault::new(id);
        vault.save(&path, &password).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;
        
        Ok(Self { inner: Some(vault), file_path: path, password })
    }
    #[staticmethod]
    fn unlock(path: String, password: String) -> PyResult<Self> {
        let vault = Vault::load(&path, &password)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        Ok(Self { inner: Some(vault), file_path: path, password })
    }

    //  LOCKING 

    fn lock(&mut self) -> PyResult<()> {
        // Zeroize ALL
        self.password.zeroize();
        self.file_path.zeroize();
        self.inner = None;
        Ok(())
    }

    //  IDENTITY 

    fn get_my_identity_hex(&self) -> PyResult<String> {
        let v = self._get_inner()?;
        Ok(hex::encode(v.identity.sign_public.to_bytes()))
    }

    //OLD DEPRECATED WAY
    //fn get_prekey_bundle1(&mut self, count: usize) -> PyResult<PyObject> {
    //    let path = self.file_path.clone();
    //    let pwd = self.password.clone();
    //    let v = self._get_inner_mut()?;

          // Generate a bundle with 'count' one-time prekeys
    //    let bundle = v.generate_registration_bundle(count);

          // Commit new secrets to disk immediately
    //    v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;

    //    Python::with_gil(|py| {
    //    let bundle_json = serde_json::to_vec(&bundle)
    //        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    //    Ok(PyBytes::new(py, &bundle_json).to_object(py))
    //    })
    //}
    //NEW WAY, TODO: COMPLETE THE REST OF THESE
    fn get_prekey_bundle(&mut self, count: usize) -> PyResult<PyObject> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;

        let bundle = v.generate_registration_bundle(count);

        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;

        Python::with_gil(|py| {
            let bundle_json = serde_json::to_vec(&bundle)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

            // PyBytes::new returns a Bound<'py, PyBytes>
            let bytes_bound = PyBytes::new(py, &bundle_json);
            // This is the direct replacement for .to_object(py)
            Ok(bytes_bound.into_any().unbind())
        })
    }


    //  PROFILE MANAGEMENT 

    fn get_config_json(&self) -> PyResult<String> {
        let v = self._get_inner()?;
        // Access profile through the inner vault 'v'
        serde_json::to_string(&v.profile)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
    fn set_nickname(&mut self, name: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.nickname = name;
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))

    }
    fn set_tor_proxy(&mut self, proxy: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.tor_proxy = proxy;
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    
    fn set_alias(&mut self, alias: String, key_bytes: [u8; 32]) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.aliases.insert(alias, key_bytes);
        
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    fn remove_alias(&mut self, alias: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.aliases.remove(&alias);
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    
    fn get_contact_pubhex(&self, alias: String) -> PyResult<Option<String>> {
        let v = self._get_inner()?;
        //Get the [u8; 32] array
        let key_bytes = v.profile.aliases.get(&alias);
        //Map to Option<String> using hex::encode
        Ok(key_bytes.map(|bytes| hex::encode(bytes)))
    }
    fn get_contact_name(&self, hex_key: String) -> PyResult<String> {
        let v = self._get_inner()?;
        
        let target_hex = hex_key.to_lowercase();

        let alias_name = v.profile.aliases.iter().find_map(|(name, &key_bytes)| {
            if hex::encode(key_bytes) == target_hex {
                Some(name.clone())
            } else {
                None
            }
        });

        Ok(alias_name.unwrap_or_else(|| {
            if target_hex.len() >= 8 {
                target_hex[..8].to_string()
            } else {
                target_hex
            }
        }))
    }
    fn is_alias(&self, alias_or_key: String) -> PyResult<bool> {
        let v = self._get_inner()?;
        if v.profile.aliases.contains_key(&alias_or_key) {
            return Ok(true);
        }
        
        let target_hex = alias_or_key.to_lowercase();
        if let Ok(bytes) = hex::decode(&target_hex) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(v.profile.aliases.values().any(|&k| k == arr));
            }
        }
        Ok(false)
    }
    //link key to server
    fn link_to_server(&mut self, ident_key: [u8; 32], server_name: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        // Link the key to the server in the profile
        let links = v.profile.server_links.entry(server_name).or_insert_with(Vec::new);
        if !links.contains(&ident_key) {
            links.push(ident_key);
        }

        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    //Get linked keys
    fn get_server_friends(&self, server_name: String) -> PyResult<Vec<[u8; 32]>> {
        let v = self._get_inner()?; // Read-only access is fine here
        Ok(v.profile.server_links.get(&server_name).cloned().unwrap_or_default())
    }
    //  SERVER MANAGEMENT 

    fn set_server(&mut self, name: String, url: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.servers.insert(name, url);
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    fn remove_server(&mut self, name: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.profile.servers.remove(&name);
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    fn get_server_url(&self, name: String) -> PyResult<Option<String>> {
        let v = self._get_inner()?;
        Ok(v.profile.servers.get(&name).cloned())
    }
    fn set_policy_mode(&mut self, type_key: String, mode: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        match type_key.as_str() {
            "message" => v.profile.msg_policy.mode = mode,
            "file" => v.profile.file_policy.mode = mode,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid policy type")),
        }
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
    fn add_to_policy_list(&mut self, type_key: String, list_type: String, key_hex: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        let policy = match type_key.as_str() {
            "message" => &mut v.profile.msg_policy,
            "file" => &mut v.profile.file_policy,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid policy type")),
        };

        match list_type.as_str() {
            "whitelist" => { 
                policy.blacklist.remove(&key_hex); 
                policy.whitelist.insert(key_hex); 
            },
            "blacklist" => {
                policy.whitelist.remove(&key_hex); 
                policy.blacklist.insert(key_hex); 
            },
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid list type")),
        }
        
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }

    fn set_max_msg_size(&mut self, size: u64) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        v.profile.max_msg_size = size;
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }

    //  LOGGING 
    
    fn log(&mut self, level: String, message: String) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        v.log_event(&level, &message);
            if level == "ERROR" {
                let _ = v.save(&path, &pwd);
        }
        Ok(())
    }

    fn get_system_logs(&self) -> PyResult<Vec<(u64, String, String)>> {
        let v = self._get_inner()?;
        let logs = v.system_logs.iter().map(|e| {
            (e.timestamp, e.level.clone(), e.message.clone())
        }).collect();
        Ok(logs)
    }

    //  MESSAGING 

    fn has_session(&self, ident_key: [u8; 32]) -> PyResult<bool> {
        let v = self._get_inner()?;
        Ok(v.sessions.contains_key(&ident_key))
    }
    fn start_session(&mut self, contact_sign_pub: [u8;32], bundle_json: Vec<u8>) -> PyResult<PyObject> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        let bundle: PreKeyBundle = serde_json::from_slice(&bundle_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
        let (state, header) = RatchetState::new_alice(v.identity.clone(), bundle)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
            
        v.sessions.insert(contact_sign_pub, state);
        v.log_event("INFO", &format!("Started session with {}", hex::encode(contact_sign_pub)));
        
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;
        
        let h_bytes = serde_json::to_vec(&header).unwrap();
        Ok(Python::with_gil(|py| PyBytes::new(py, &h_bytes).to_object(py)))
    }
    fn accept_session(&mut self, sender_sign_pub: [u8; 32], x3dh_header_json: Vec<u8>) -> PyResult<()> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;

        // 1. Parse the header to see what keys Alice used
        let header: X3dhHeader = serde_json::from_slice(&x3dh_header_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

        // 2. Load our current Signed PreKey secret
        let spk_secret = StaticSecret::from(v.spk_secret);
        
        // 3. Look up the One-Time PreKey secret if Alice used one
        let mut otk_secret: Option<StaticSecret> = None;
        if let Some(used_opk_pub) = &header.used_opk {
            let pub_bytes = used_opk_pub.as_bytes();
            
            // Try to find the secret in our map
            if let Some(sec_bytes) = v.otk_secrets.get(pub_bytes) {
                otk_secret = Some(StaticSecret::from(*sec_bytes));
                
                // CRITICAL: Consume the key. Once used, it should be deleted 
                // from our vault to maintain forward secrecy.
                let key_to_remove = *pub_bytes;
                v.otk_secrets.remove(&key_to_remove);
            } else {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "No matching One-Time PreKey found in vault. It may have been already used or expired."
                ));
            }
        }

        // 4. Initialize Bob's side of the Ratchet
        let alice_dh = header.sender_dh_pub;
        let state = RatchetState::new_bob(
            v.identity.clone(), 
            &spk_secret, 
            otk_secret.as_ref(), 
            &header, 
            alice_dh
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

        // 5. Save the session and the modified vault (since we removed an OTK)
        v.sessions.insert(sender_sign_pub, state);
        v.log_event("INFO", &format!("Accepted session from {}", hex::encode(sender_sign_pub)));
        
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;
        
        Ok(())
    }
    fn delete_session(&mut self, key_hex: String) -> PyResult<bool> {
        // Use '?' to return early if the alias/hex is invalid
        let ident_key = self.resolve_key(&key_hex)?;

        let path = self.file_path.clone();
        let pwd = self.password.clone();
        
        let v = self._get_inner_mut()?;

        let session_removed = v.sessions.remove(&ident_key).is_some();
        let history_removed = v.chats.remove(&ident_key).is_some();

        let changed = session_removed || history_removed;

        if changed {
            let hex_id = hex::encode(ident_key);
            v.log_event("INFO", &format!("Wiped session and history for {}", hex_id));
            
            // 4. Save the state
            v.save(&path, &pwd)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;
        }

        Ok(changed)
    }
    #[pyo3(signature = (recipients, input, timestamp))]
    fn send_multicast(
        &mut self, 
        py: Python, 
        recipients: Vec<[u8;32]>, 
        input: PyObject,
        timestamp: u64,
    ) -> PyResult<Vec<(PyObject, PyObject)>> {
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;
        
        let mut output = Vec::new();
        
        let (plain_bytes, is_file) = if let Ok(bytes) = input.extract::<Vec<u8>>(py) {
            (bytes, false)
        } else if let Ok(path) = input.extract::<String>(py) {
             if path.starts_with("FILE:") {
                let file_path = &path[5..];
                let mut file = File::open(file_path).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
                (buffer, true)
            } else {
                 (path.into_bytes(), false)
            }
        } else {
             return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("Input must be bytes or string"));
        };

        for recipient in recipients {
            if let Some(session) = v.sessions.get_mut(&recipient) {
                let mut ad = Vec::new();
                ad.extend_from_slice(v.identity.sign_public.as_bytes());
                ad.extend_from_slice(&recipient);
                ad.extend_from_slice(&timestamp.to_le_bytes()); // Bind timestamp to AD

                let (header, ciphertext) = session.ratchet_encrypt(&plain_bytes, &ad)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
                
                let header_bytes = serde_json::to_vec(&header).unwrap();
                let r_obj = PyBytes::new(py, &recipient).to_object(py);
                let h_obj = PyBytes::new(py, &header_bytes).to_object(py);
                let c_obj = PyBytes::new(py, &ciphertext).to_object(py);

                output.push((r_obj, (h_obj, c_obj).to_object(py)));
            }
        }
        
        v.save(&path, &pwd).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))?;
        Ok(output)
    }

    #[pyo3(signature = (sender, header_bytes, ciphertext_input, timestamp))]
    fn receive(
        &mut self, 
        sender: [u8; 32], 
        header_bytes: Vec<u8>, 
        ciphertext_input: PyObject,
        timestamp: u64, // Passed from the packet header
    ) -> PyResult<PyObject> {
        let py = unsafe { Python::assume_gil_acquired() }; 
        let path = self.file_path.clone();
        let pwd = self.password.clone();
        let v = self._get_inner_mut()?;

        let session = v.sessions.get_mut(&sender)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("No session found"))?;

        let header: crate::dratchet::MsgHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

        // Must recreate the EXACT same AD used during encryption
        let mut ad = Vec::new();
        ad.extend_from_slice(&sender);
        ad.extend_from_slice(v.identity.sign_public.as_bytes());
        ad.extend_from_slice(&timestamp.to_le_bytes());

        let (cipher_bytes, is_file_input) = if let Ok(bytes) = ciphertext_input.extract::<Vec<u8>>(py) {
            (bytes, false)
        } else if let Ok(path) = ciphertext_input.extract::<String>(py) {
            if path.starts_with("FILE:") {
                let file_path = &path[5..];
                let mut file = File::open(file_path).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
                (buffer, true)
            } else {
                return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("String input must start with FILE:"));
            }
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("Input must be bytes or string"));
        };

        let plain_bytes = session.ratchet_decrypt(&header, &cipher_bytes, &ad)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
        
        let _ = v.save(&path, &pwd);

        Ok(PyBytes::new(py, &plain_bytes).to_object(py))
    }

    #[pyo3(signature = (tid))]
    fn get_history(&self, tid: [u8; 32]) -> PyResult<Vec<(u64, String, Option<String>, [u8; 32])>> {
        let v = self._get_inner()?;
        if let Some(logs) = v.chats.get(&tid) {
            let result = logs.iter().map(|e| {
                (e.timestamp, e.text.clone(), e.file_path.clone(), e.sender)
            }).collect();
            Ok(result)
        } else {
            Ok(vec![])
        }
    }
    #[pyo3(signature = (tid, sender, timestamp, text, file_path=None))]
    fn add_chat_log(
        &mut self,
        tid: [u8; 32],
        sender: [u8; 32],
        timestamp: u64,
        text: String,
        file_path: Option<String>
    ) -> PyResult<()> {
        let v = self._get_inner_mut()?;
        
        v.add_chat_log(tid, sender, timestamp, text, file_path);
        
        Ok(())
    }

    fn save(&self) -> PyResult<()> {
        let v = self._get_inner()?;
        v.save(&self.file_path, &self.password)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e))
    }
}

#[pymodule]
fn crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVault>()?;
    Ok(())
}