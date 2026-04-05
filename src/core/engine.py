import queue
import time
import socket
import threading
import os
import glob
import json
import struct
import logging
import hashlib
import crypto
import re
from core.network import NetworkManager

# Wire Protocol Constants (SAME AS SERVER)
HEADER_FMT = ">B32s32sQII" # Type, Recip, Sender, HeadLen, DataLen
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CHAT_LOG_LENGTH = 50 #how many log entries to display upon refresh
FILE_CHUNK_SIZE = 1024 * 512 # 512KB chunks

class Engine:
    """
    The Controller.
    Bridges a UI, Vault, and a Network
    """

    def __init__(self, sys_config, Version: str):
        self.acc_name = ""
        self.ptver = Version
        self.sys_config = sys_config
        self.vault = None
        self.network = None
        self.running = True
        
        self.status_msg = "BOOTING"

        self.peers = []
        self.current_server_name: str = None # Name of server, None = not in a server
        self.current_room_key: str = None # None = lobby, Hex String = dm with alias
        self.server_rate_limit_ms = 50 # Default chunk sending delay (ms)
        self.pending_hs = {}
        self.notifications = {}
        self.initial_sync = False # Flag for processing offline messages
        # Events for UI to handle
        self.ui_queue = queue.Queue()
        # State Cache (Read from Vault) JSON
        
        self.profile_cache = {
            "nickname": "Alice",
            "aliases": {
                "NAME":"KEY"
            },
            "servers": {
                "NAME":"URL"
            },
            "server_links": {
                "NAME": [""]
            },
            "msg_policy": {},
            "file_policy": {},
            "max_msg_size": 1000000,
            "download_dir": "",
            "tor_proxy": ""
        }
        # Network Buffering
        self._packet_buffer = b""
        # File Reassembly: { file_id (str): { "path": str, "total": int, "current": int, "name": str } }
        self.file_transfers = {}
        # UI Progress Tracking: { id: { "type": "TX"|"RX", "name": str, "current": int, "total": int } }
        self.transfer_progress = {}
        self.transfer_lock = threading.Lock()

    # STD functions

    def set_account(self, name: str, defaultAcc: bool=False):
        #defaultacc = True updates global config
        if self.vault_exists(name):
            self.acc_name = name
            if defaultAcc:
                self.sys_config["default_acc"] = name
                self.write_sys_config()

    def vault_names(self) -> list[str]:
        """Returns a list of account names (filenames without .dat) in the accounts directory."""
        accounts_path = os.path.expanduser("~/.config/fr3q/accounts")
        if not os.path.exists(accounts_path):
            return []
        dat_files = glob.glob(os.path.join(accounts_path, "*.dat"))
        names = [os.path.basename(f).removesuffix(".dat") for f in dat_files]
        return names
        
    def _get_vault_path(self, name: str=""):
        if name == "":
            name = self.acc_name
        home = os.path.expanduser("~")
        vault_file = name + ".dat"
        path = os.path.join(home, ".config", "fr3q", "accounts", vault_file)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def write_sys_config(self):
        # write self.sys_config to file
        base = os.path.expanduser("~/.config/fr3q")
        sys_conf_path = os.path.join(base, "system.json")
        with open(sys_conf_path, "w") as f:
            json.dump(self.sys_config, f, indent=4)

    def vault_exists(self, name: str="") -> bool:
        """Checks if a vault.dat file exists at the expected path."""
        if name == "":
            name = self.acc_name
        return os.path.exists(self._get_vault_path(name))

    def timestamp(self):
        import time
        return f"[{time.strftime('%H:%M:%S')}]"

    def get_tid(self, ident: str = None, force_global: bool = False):
        """
        Returns a 32-byte TID.
        """
        # dm
        target_dm = ident or (self.current_room_key if not force_global else None)
        
        if target_dm:
            my_key = self.vault.get_my_identity_hex().lower()
            peer_key = target_dm.lower()
            combined_keys = sorted([my_key, peer_key])
            tid_input = "".join(combined_keys).encode('utf-8')
            return hashlib.sha256(tid_input).digest()
            
        # global
        else:
            if self.current_server_name:
                url = self.vault.get_server_url(self.current_server_name) or self.current_server_name
                return hashlib.sha256(url.encode('utf-8')).digest()
        
        logging.debug("get_tid fell back")
        return b"\x00" * 32 # fallback

    def login(self, name: str, password: str) -> bool:
        """Unlock vault, load profile, start network. engine.acc_name must be set"""
        try:
            logging.debug(f"Setting acc:'{name}'")
            self.set_account(name)
            logging.debug(f"Trying password:'{password}'")
            path = self._get_vault_path()
            self.vault = crypto.PyVault.unlock(path, password)
            self.vault.log("INFO", "Unlocked vault")
            logging.debug("Unlocked vault")
            # Load Profile into Memory
            self.refresh_profile()
            self.status_msg = "DISCONNECTED"
            return True
        except Exception as e:
            self.vault = None
            self.status_msg = f"Login Failed"
            logging.error(f"Login error: {e}")
            return False

    def create_account(self, password: str) -> bool:
        """Creates a new Vault and Identity."""
        try:
            path = self._get_vault_path()
            self.vault = crypto.PyVault.create_new(path, password)
            self.refresh_profile()
            self.status_msg = "CREATED"
            self.vault.log("INFO", f"New account created: {self.acc_name}")
            self.vault.set_nickname(self.acc_name)
            return True
        except Exception as e:
            self.status_msg = f"Setup Failed: {e}"
            logging.error(f"Setup error: {e}")
            return False

    def is_tor_running(self, proxy_host: str, proxy_port: int) -> bool:
        """
        Checks if Tor is running/avaliable (SOCKS handshake check)
        """
        try:
            with socket.create_connection((proxy_host, proxy_port), timeout=2) as s:
                #SOCKS Handshake Request
                s.sendall(b'\x05\x01\x00') 
                #Receive SOCKS Resp
                response = s.recv(2)
                #Successful 'No Auth'
                return response == b'\x05\x00'
        except (OSError, ConnectionRefusedError, socket.timeout, socket.error):
            return False

    def connect_to_server(self, server_name: str, num_keys=50):
        """
        Disconnects current network and connects to the specified server name.
        """
        # Get URL
        servers = self.profile_cache.get("servers", {})
        if server_name not in servers:
            self.vault.log("ERROR", f"Server '{server_name}' not found in profile.")
            return

        url_string = servers[server_name]
        # Parse URL
        try:
            server_host, server_port = url_string.split(":")
            server_port = int(server_port)
        except ValueError:
            self.vault.log("ERROR", f"Invalid server URL format: {url_string}")
            return
        # Restart network manager
        if self.network and self.network.is_connected:
            self.network.stop()
        if not self.network:
            self.network = NetworkManager(self)
        # Get proxy
        proxy = self.profile_cache.get("tor_proxy", "127.0.0.1:9050")
        try:
            proxy_ip, proxy_port = proxy.split(":")
            proxy_port = int(proxy_port)
        except ValueError:
            return
        # Connect
        self.status_msg = f"CONNECTING"
        try:
            if self.network.start(proxy_ip, proxy_port, server_host, server_port):
                self.current_server_name = server_name
                #join GLOBAL
                self.current_room_key = None
                self.refresh_logs(50)
                self.vault.log("INFO", f"Connected to server: {server_name}")
                logging.info(f"sending join msg with {num_keys} prekeys")
                self.send_register_msg(num_keys)
            else:
                self.status_msg = "FAILED"
        except Exception as e:
            logging.error(f"Connection Failed: {e}")
            self.status_msg = "FAILED"
    
    def disconnect(self):
        if self.network:
            self.status_msg = "DISCONNECTING"
            self.network.stop()
            my_bytes = bytes.fromhex(self.vault.get_my_identity_hex())
            self.push_chat_ui(self.get_tid(), my_bytes, "Left", time.time(), False, False)
            self.status_msg = "DISCONNECTED"
        self.current_room_key = None
        self.current_server_name = None

    def me(self, ident_hex: str):
        """ Ret true if ident_hex belongs to this client """
        return ident_hex.lower() == self.vault.get_my_identity_hex()

    def shutdown(self):
        """Clean cleanup."""
        self.running = False
        self.lock()

    def lock(self):
        """
        Securely clears memory references to the Vault and Profile.
        """
        self.disconnect()
        if self.vault:
            try:
                self.vault.save()
                self.vault.log("INFO", "Locking vault...")
                self.vault.lock()
                logging.debug("Locked vault")
            except Exception as e:
                print(f"Error locking vault: {e}")
            self.vault = None
        
        self.profile_cache = {}
        self.current_room_key = None
        self.current_server_name = None
        self.status_msg = "LOCKED"

    def is_hex_key(self, string: str):
        """ checks if string is valid hex key and returns bytes, otherwise false """
        try:
            key_bytes = bytes.fromhex(string)
            if len(string) == 64:
                return key_bytes
            else:
                return False
        except:
            return False

    def get_home_dir(self) -> str:
        return os.path.expanduser("~")

    def policy_edit(self, ptype: str, policy: str, ident: str = None):
        type_key = "message" if ptype in ("m", "msg") else "file"
        if ident:
            if policy in ("a", "allow"):
                list_to_add = "whitelist"
                ppolicy = "ALLOW"
            else:
                list_to_add = "blacklist"
                ppolicy = "DENY"
            self.vault.add_to_policy_list(type_key, list_to_add, ident)
            pident = f"{ident[:8]}.." if len(ident) > 8 else ident
            self.ui_queue.put({"print": f"[+] Added rule: {ppolicy} {type_key.upper()} from {pident}"})
        else:
            if policy in ("a", "allow"):
                mode = "allow"
            elif policy in ("d", "deny"):
                mode = "deny"
            else:
                mode = "whitelist"
            self.vault.set_policy_mode(type_key, mode)
            self.ui_queue.put({"print": f"[+] Changed {type_key.upper()} policy to {mode.upper()}"})
        self.refresh_profile()
        
    def rule_query(self, mtype, sender: str):
        if mtype in (0x03, 0x04):
            return True
        elif mtype in (0x01, 0x11):
            #msg
            policy_type = "msg_policy"
        elif mtype in (0x02, 0x12):
            #file
            policy_type = "file_policy"
        else:
            return False
        target_policy = self.profile_cache.get(policy_type, {})
        grule = target_policy.get("mode", "deny")
        if grule == "allow":
            #check blacklist
            blist = target_policy.get("blacklist", [])
            return sender not in blist
        elif grule == "whitelist":
            #check whitelist
            wlist = target_policy.get("whitelist", [])
            return sender in wlist
        else:
            return False

    def ident_color(self, key: str, forceOnline=False):
        if self.me(key):
            return 13
        online = key in self.peers
        blocked = not self.rule_query(0x01, key)
        aliased = self.vault.is_alias(key)
        #logging.debug(f"key: {key[:8]}, online: {online}, blocked: {blocked}, aliased: {aliased}")
        if forceOnline:
            online = True
        if blocked:
            return 15 if online else 9
        else:
            if online:
                return 12 if aliased else 11
            else:
                return 25 if aliased else 2

    def set_max_msg_size(self, sizestr: str):
        size = None
        try:
            match = re.match(r"^(\d+)\s*(b|kb|mb|gb)?$", sizestr.strip().lower())
            
            if match:
                val = int(match.group(1))
                unit = match.group(2)
                
                if unit == "kb":
                    size = val * 1024
                elif unit == "mb":
                    size = val * 1024 * 1024
                elif unit == "gb":
                    size = val * 1024 * 1024 * 1024
                else:
                    size = val
            
            if size:
                #set size
                self.vault.set_max_msg_size(size)
                self.refresh_profile()
                self.ui_queue.put({"print": f"[+] Max message size set to {sizestr}"})
            else:
                self.ui_queue.put({"print": "[i] Usage: /policy limit <size>[b|kb|mb|gb]"})
        except Exception as e:
            self.ui_queue.put({"print": "[i] Usage: /policy limit <size>[b|kb|mb|gb]"})
            logging.debug(f"Invalid size '{sizestr}': {e}")


    def clear_notis(self):
        """ clears the current rooms notifications """
        if self.current_room_key is None:
            #global chat?
            if self.current_server_name is not None:
                #global reset notifications
                self.notifications[self.current_server_name] = 0
            #not in server
        else:
            #dm reset notifications
            alias = self.vault.get_contact_name(self.current_room_key)
            if self.vault.is_alias(self.current_room_key) and alias is not None:
                self.notifications[alias] = 0
            #could not find alias

    #### VAULT CONFIGS
    # Update CONFIGS
    def refresh_profile(self):
        """Reloads the profile JSON from Rust and merges it into the existing cache."""
        if not self.vault:
            return
        try:
            json_str = self.vault.get_config_json()
            new_data = json.loads(json_str)
            if "aliases" in new_data:
                new_data["aliases"] = {
                    name: bytes(key_list).hex() 
                    for name, key_list in new_data["aliases"].items()
                }
            if "server_links" in new_data:
                new_data["server_links"] = {
                    srv: [bytes(k).hex() for k in keys]
                    for srv, keys in new_data["server_links"].items()
                }
            self.profile_cache.update(new_data)
            logging.debug(f"Profile cache updated:{json.dumps(new_data)}")
        except Exception as e:
            logging.error(f"Failed to refresh profile cache: {e}")


    # ENGINE TICK (SYNC networking)
    def tick(self):
        """
        Handles incoming data and updates state.
        """
        if not self.network:
            if self.status_msg == "CONNECTED":
                self.status_msg = "DISCONNECTED"
            return
        # Buffer network data
        try:
            while True:
                chunk = self.network.incoming_queue.get_nowait()
                self._packet_buffer += chunk
        except queue.Empty:
            pass
        # Process
        self.process_buffer()
        # Check network
        if not self.network.is_connected and self.status_msg == "CONNECTED":
            self.status_msg = "DISCONNECTED"

    ############################### PARSER ################################

    def handle_input(self, text: str):
        """Entry point for Chat Screen input."""
        if not text: return
        self.clear_notis()
        if text.startswith('/'):
            self._parse_command(text)
        else:
            self.send_chat_msg(text)
    def _parse_command(self, cmd_str: str):
        #interacted with current room so clear notifications
        
        parts = cmd_str.strip().split(' ')
        cmd = parts[0].lower()
        args = parts[1:]
        #TODO:
        # /dir <type> <path>
        # /log
        try:
            if cmd == "/friend":
                if len(args) >= 2:
                    alias = args[0]
                    hex_key = args[1].lower()
                    if self.is_hex_key(hex_key):
                        if not self.me(hex_key) and alias != self.profile_cache.get('nickname'):
                            if self.vault.get_server_url(alias) is None:
                                if self.vault.get_contact_pubhex(alias) is None:
                                    if alias != "GLOBAL":
                                        self.friend_hs(alias, hex_key)
                                    else:
                                        self.ui_queue.put({"print": "[-] 'GLOBAL' is a reserved room name"})
                                else:
                                    self.ui_queue.put({"print": f"[-] Alias '{alias}' already exists"})
                            else:
                                self.ui_queue.put({"print": f"[-] Server '{alias}' already exists"})
                        else:
                            self.ui_queue.put({"print": f"[-] Cannot use your own ident"})
                    else:
                        self.ui_queue.put({"print": f"[-] Invalid hex key '{hex_key}'"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /friend <name> <hex_key>"})
            elif cmd == "/join":
                if args:
                    if args[0] == "GLOBAL":
                        self.current_room_key = None
                        self.ui_queue.put("room_changed")
                        self.refresh_logs(CHAT_LOG_LENGTH)
                        return
                    hex_key = self.vault.get_contact_pubhex(args[0])
                    if hex_key is not None:
                        # Alias
                        self.current_room_key = hex_key.lower()
                        self.refresh_logs(CHAT_LOG_LENGTH)
                    else:
                        # Maybe key
                        key_bytes = self.is_hex_key(args[0].lower())
                        if key_bytes:
                            if self.vault.has_session(key_bytes):
                                # Valid key
                                self.current_room_key = args[0].lower()
                                self.refresh_logs(CHAT_LOG_LENGTH)
                            else:
                                self.ui_queue.put({"print": f"[-] Could not find session for '{args[0]}'"})
                        else:
                            self.ui_queue.put({"print": f"[-] Invalid key '{args[0]}'"})
                else:           
                    self.ui_queue.put({"print": "[i] Usage: /join <alias|key>"})
            elif cmd == "/leave":
                self.current_room_key = None
                self.ui_queue.put("room_changed")
                self.refresh_logs(CHAT_LOG_LENGTH)
            elif cmd == "/nick":
                if args:
                    nick = args[0]
                    if self.vault.get_server_url(nick) is None:
                        if self.vault.get_contact_pubhex(nick) is None:
                            self.vault.set_nickname(nick)
                            self.refresh_profile()
                        else:
                            self.ui_queue.put({"print": f"[-] Alias '{nick}' already exists"})
                    else:
                        self.ui_queue.put({"print": f"[-] Server '{nick}' already exists"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /nick <nickname>"})
            elif cmd == "/default":
                current_acc = self.profile_cache.get('nickname', False)
                if current_acc:
                    self.set_account(current_acc, True)
                    self.ui_queue.put({"print": f"[+] Set default account to {current_acc}"})
                else:
                    self.ui_queue.put({"print": f"[-] Could not find account"})
            elif cmd == "/del":
                if len(args) >= 1:
                    alias = args[0]
                    # Resolve alias to hex str
                    target_hex = self.vault.get_contact_pubhex(alias).lower()
                    if target_hex:
                        try:
                            # Leave dm if in active to delete
                            if self.current_room_key == target_hex:
                                self.current_room_key = None
                                self.ui_queue.put("room_changed")
                            # Wipe session/chat logs (TODO: do /wipe to do this)
                            #if self.vault.delete_session(target_hex):
                            #    self.vault.log("INFO", f"Deleted session/history for alias '{alias}'")
                            #logging.debug(f"Deleted session/hist {alias}")
                        except Exception as e:
                            self.vault.log("ERROR", f"Session wipe for '{alias}' failed: {e}")
                            logging.error(f"Session wipe failed: {e}")
                    # Remove alias
                    try:
                        self.vault.remove_alias(alias)
                    except Exception as e:
                        self.vault.log("ERROR", f"Alias wipe for '{alias}' failed: {e}")
                        logging.error(f"Alias wipe failed: {e}")
                    self.vault.log("INFO", f"Deleted alias '{alias}'")
                    logging.debug(f"Deleted alias {alias}")
                    
                    # Update
                    self.refresh_profile()
                    self.ui_queue.put({"print": f"[+] Purged all data for '{alias}'"})
                    self.ui_queue.put({"print": f"[i] If you want to chat again, they will have to run /del as well"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /del <alias>"})
            #SEND FILE/DIR        
            elif cmd in ("/file", "/ft"):
                if args:
                    self.send_file(args[0])
            
            elif cmd in ("/connect","/c"):
                if args:
                    server_name = args[0]
                    if self.vault.get_server_url(args[0]) is not None:
                        if len(args) >= 2:
                            num_keys = int(args[1])
                        else:
                            num_keys = 0
                        self.status_msg = "CONNECTING"
                        logging.debug(f"Starting connection thread for {server_name}")
                        self.initial_sync = True
                        threading.Thread(
                            target=self.connect_to_server, 
                            args=(server_name, num_keys), 
                            daemon=True
                        ).start()
                    else:
                        self.ui_queue.put({"print": f"[-] Could not find server named '{server_name}'"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /connect <server> [<key_amount>]"})
            elif cmd in ("/disconnect", "/dc"):
                self.disconnect()
                
            elif cmd == "/whois":
                if args:
                    ident = args[0]
                    key = self.vault.get_contact_pubhex(ident)
                    if key:
                        #ident is alias name
                        alias = ident
                        isalias = True
                    else:
                        #ident is key
                        alias = self.vault.get_contact_name(ident)
                        isalias = self.vault.is_alias(ident)
                        if self.is_hex_key(ident):
                            key = ident
                        else:
                            self.ui_queue.put({"print": f"[-] Ident '{ident}' could not be resolved to hex key"})
                            return
                    self.ui_queue.put({
                        "command": "whois",
                        "key": key,
                        "alias": alias if isalias else None
                    })
                else:
                    self.ui_queue.put({"print": "[i] Usage: /whois <ident>"})
            elif cmd == "/who":
                self.ui_queue.put({
                    "command": "who"
                })
            elif cmd == "/clean":
                self.ui_queue.put({
                    "command": "clean_logs"
                })
            elif cmd in ("/clear","/clr"):
                self.ui_queue.put({
                    "command": "clear_logs"
                })
            elif cmd in ("/refresh","/r"):
                self.refresh_profile()
                if self.current_server_name is not None:
                    if args:
                        try:
                            history = int(args[0])
                            self.refresh_logs(history)
                        except Exception:
                            self.ui_queue.put({"print": "[i] Usage: /refresh [<amount>]"})
                    else:
                        self.refresh_logs(CHAT_LOG_LENGTH)
                else:
                    self.ui_queue.put({
                        "command": "clean_logs"
                    })
            elif cmd in ("/server", "/s"):
                if len(args) >= 1:
                    if args[0] in ("add", "a"):
                        if len(args) >= 3:
                            name, url = args[1], args[2]
                            #Rudementary check (chances are if they typed : they typed a port)
                            if ":" in url:
                                if self.vault.get_server_url(name) is None:
                                    if self.vault.get_contact_pubhex(name) is None:
                                        self.vault.set_server(name, url)
                                        self.refresh_profile()
                                        self.ui_queue.put({"print": f"[+] Added '{name}@{url[:5]}..{url[5:]}'"})
                                    else:
                                        self.ui_queue.put({"print": f"[-] Alias '{name}' already exists"})
                                else:
                                    self.ui_queue.put({"print": f"[-] Server '{name}' already exists"})
                            else:
                                self.ui_queue.put({"print": "[-] URL missing :port"})
                        else:
                            self.ui_queue.put({"print": "[i] Usage: /server add <name> <url:port>"})
                    elif args[0] in ("del", "remove","d","r"):
                        if len(args) >= 2:
                            if args[1] in self.profile_cache["servers"]:
                                self.vault.remove_server(args[1])
                                self.refresh_profile()
                            else:
                                self.ui_queue.put({"print": f"[-] Cannot find '{args[1]}'"})
                        else:
                            self.ui_queue.put({"print": "[i] Usage: /server del <name>"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /server add|del <name> [<url:port>]"})
            
            elif cmd == "/proxy":
                if args:
                    if args[0] in ("def","default"):
                        self.vault.set_tor_proxy("127.0.0.1:9050")
                        self.refresh_profile()
                        self.ui_queue.put({"print": f"[+] Using default proxy at {args[0]}"})
                    elif ":" in args[0]:
                        ip, port = args[0].split(":")
                        try:
                            nothing = int(port)
                            self.vault.set_tor_proxy(args[0])
                            self.refresh_profile()
                            self.ui_queue.put({"print": f"[+] Using proxy at {args[0]}"})
                        except Exception:
                            self.ui_queue.put({"print": f"[-] Invalid port '{port}'"})
                    else:
                        self.ui_queue.put({"print": "[-] Proxy missing :port"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /proxy <ip:port>"})
            elif cmd == "/policy":
                if len(args) >= 2:
                    if args[0] in ("msg","m","f","file"):
                        if len(args) >= 3:
                            if args[1] in ("allow","a","d","deny"):
                                hex_key = self.vault.get_contact_pubhex(args[2])
                                ident = False
                                if hex_key is not None:
                                    #Alias
                                    ident = hex_key
                                elif self.is_hex_key(args[2]):
                                    #Hex key
                                    ident = args[2]
                                if ident:
                                    self.policy_edit(args[0], args[1], ident)
                                else:
                                    self.ui_queue.put({"print": f"[-] Could not resolve {args[2]}"})
                            else:
                                self.ui_queue.put({"print": f"[i] Usage: /policy {args[0]} allow|deny <ident>"})
                        elif args[1] in ("allow","a","d","deny","w","whitelist"):
                            self.policy_edit(args[0], args[1])
                        else:
                            self.ui_queue.put({"print": f"[i] Usage: /policy {args[0]} allow|deny|whitelist"})
                    elif args[0] in ("size","limit","l","s"):
                        self.set_max_msg_size(args[1])
                    else:
                        self.ui_queue.put({"print": "[i] Usage: /policy msg|file|limit <policy> [<ident>]"})
                else:
                    self.ui_queue.put({"print": "[i] Usage: /policy msg|file|limit <policy> [<ident>]"})
            
            elif cmd == "/n":
                #prints empty line
                self.ui_queue.put({"print": " "})
            elif cmd in ("/exit", "/quit", "/q"):
                self.shutdown()
            elif cmd[0] == '/':
                #StartsWith
                self.ui_queue.put({"print": f"[-] '{cmd}' Not found"})
            #SEND MSG
            else:
                #Send plaintext
                self.send_chat_msg(cmd_str)

        except Exception as e:
            self.vault.log("ERROR", f"Command failed: {e}")
            logging.debug(f"parse_command failed: {e}")

    ##### OUTBOUND

    def _dispatch_packets(self, packets, msg_type, timestamp):
        my_id_bytes = bytes.fromhex(self.vault.get_my_identity_hex())
        for recipient, (header, cipher) in packets:
            frame = struct.pack(
                HEADER_FMT,
                msg_type,
                recipient,
                my_id_bytes,
                timestamp,
                len(header),
                len(cipher)
            )
            self.network.send(frame + header + cipher)
    def choose_recipients(self) -> list:
        """
        Resolves targets for a message. 
        If in a specific DM, returns that one person.
        If in a 'Global' room, returns everyone linked to the current server.
        """
        if self.current_room_key:
            #DM
            target_bytes = bytes.fromhex(self.current_room_key)
            return [target_bytes]
        if self.current_server_name:
            #Lobby
            linked_keys = self.vault.get_server_friends(self.current_server_name)
            return [bytes(k) for k in linked_keys]

        return []
    #0x01 (MSG)
    def send_chat_msg(self, plaintext: str):
        # Check if connected
        if self.current_server_name and self.network:
            #Online
            if not self.vault:
                #Logged out
                self.vault.log("WARN", "Tried to send msg without vault")
                return

            recipients = self.choose_recipients()
            if not recipients:
                self.vault.log("WARN", f"Could not resolve recipients with key '{self.current_room_key}'")
                return

            # Encrypt (Fan-Out)
            ts = int(time.time())
            try:
                packets = self.vault.send_multicast(recipients, plaintext.encode('utf-8'), ts)
            except Exception as e:
                logging.error(f"multicast error:{e}")
            
            mtype = 0x01 if self.current_room_key is None else 0x11
            self._dispatch_packets(packets, mtype, ts)

            # Log and show
            my_id_bytes = bytes.fromhex(self.vault.get_my_identity_hex())
            self.vault.add_chat_log(self.get_tid(), my_id_bytes, ts, plaintext)
            
            self.push_chat_ui(self.get_tid(), my_id_bytes, plaintext, ts)
    #0x02 (FILE)
    def send_file(self, filepath: str):
        if self.current_server_name is not None and self.network:
            if not os.path.exists(filepath):
                self.vault.log("WARN", "File not found")
                logging.debug(f"File '{filepath}' not found")
                self.ui_queue.put({"print": f"[-] '{filepath}' not found"})
            else:
                recipients = self.choose_recipients()
                if not recipients: return

                # Chunking Logic
                # Offload to background thread to prevent UI blocking
                threading.Thread(target=self._bg_send_file, args=(filepath, recipients), daemon=True).start()
                self.ui_queue.put({"print": f"[+] Sending '{os.path(filepath)}'"})

    def _bg_send_file(self, filepath, recipients):
        """ Background worker for file sending """
        file_id = None
        try:
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            file_id = hashlib.md5(f"{filename}{time.time()}".encode()).hexdigest()[:16]
            total_chunks = (file_size // FILE_CHUNK_SIZE) + (1 if file_size % FILE_CHUNK_SIZE != 0 else 0)
            ts = int(time.time())
            mtype = 0x2 if self.current_room_key is None else 0x12
            
            my_id_bytes = bytes.fromhex(self.vault.get_my_identity_hex())
            
            # Register Progress
            with self.transfer_lock:
                self.transfer_progress[file_id] = {
                    "type": "TX", 
                    "name": filename, 
                    "current": 0, 
                    "total": total_chunks
                }
            
            # 1. Send Metadata (Start)
            # OpCode 0x01 (Start) | JSON
            meta = json.dumps({"id": file_id, "name": filename, "size": file_size, "chunks": total_chunks}).encode('utf-8')
            payload = b"\x01" + meta
            
            # Encrypt Metadata
            packets = self.vault.send_multicast(recipients, payload, ts)
            self._dispatch_packets(packets, mtype, ts)

            # 2. Stream Chunks
            # OpCode 0x02 (Data) | ID (16s) | Data
            with open(filepath, "rb") as f:
                chunk_seq = 0
                while True:
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk: break
                    
                    # Payload: OpCode(1) + FileID(16) + Data
                    data_payload = b"\x02" + file_id.encode('utf-8') + chunk
                    
                    # Encrypt chunk (advances ratchet per chunk, secure and ordered)
                    c_packets = self.vault.send_multicast(recipients, data_payload, ts)
                    self._dispatch_packets(c_packets, mtype, ts)
                    chunk_seq += 1
                    
                    # Update Progress
                    with self.transfer_lock:
                        if file_id in self.transfer_progress:
                            self.transfer_progress[file_id]["current"] = chunk_seq
                            self.ui_queue.put("update_progress")
                    time.sleep(self.server_rate_limit_ms / 1000.0)

            # Log and show
            self.vault.add_chat_log(self.get_tid(), my_id_bytes, ts, f"SENT '{filepath}'", filepath)
            self.push_chat_ui(self.get_tid(), my_id_bytes, f"SENT '{filepath}'", ts, is_file=True)
            
        except Exception as e:
            self.vault.log("ERROR", f"File send failed: {e}")
            self.ui_queue.put({"print": f"[-] File send error: {e}"})
        finally:
            # Cleanup progress bar
            if file_id:
                with self.transfer_lock:
                    if file_id in self.transfer_progress:
                        del self.transfer_progress[file_id]

    #0x03 (0x00) (CLIENTS)
    def send_register_msg(self, num_keys: int = 50):
        """
        Registers identity. 
        If num_keys > 0, generates and uploads a new X3DH PreKey bundle.
        """
        if not self.vault or not self.network.is_connected:
            return

        try:
            my_id_hex = self.vault.get_my_identity_hex()
            my_id_bytes = bytes.fromhex(my_id_hex)
            server_ident = b"\x00" * 32
            header = b"{}" 
            ts = int(time.time())

            if num_keys > 0:
                data = self.vault.get_prekey_bundle(num_keys)
                log_txt = f"Registered and uploaded {num_keys} PreKeys."
            else:
                data = b"NONE" 
                log_txt = "Registered (reconnected) without updating PreKeys."

            # msg_type 0x00 = JOIN
            join_frame = struct.pack(
                HEADER_FMT,
                0x00,
                server_ident,
                my_id_bytes,
                ts,
                len(header),
                len(data)
            ) + header + data

            self.network.send(join_frame)
            self.vault.log("INFO", log_txt)
            self.status_msg = "SYNCING"
        except Exception as e:
            self.vault.log("ERROR", f"Failed to register (send 0x03) on server: {e}")
    #0x04 (PREKEYS)
    def req_prekey_bundle(self, target_hex):
        """Asks the server for a recipient's X3DH PreKey bundle."""
        if not self.network.is_connected or not self.current_server_name: return
        
        target_bytes = bytes.fromhex(target_hex)
        my_id_bytes = bytes.fromhex(self.vault.get_my_identity_hex())
        server_ident = b"\x00" * 32
        ts = int(time.time())

        # build frame
        req_frame = struct.pack(
            HEADER_FMT,
            0x04,
            server_ident,
            my_id_bytes,
            ts,
            32,
            0
        ) + target_bytes
        
        self.network.send(req_frame)
    def friend_hs(self, alias, hex_key: str):
        try:
            #Obtain key
            target_bytes = bytes.fromhex(hex_key)

            if self.vault.get_contact_pubhex(alias) is None:
                #add alias
                self.vault.set_alias(alias, target_bytes)
                self.refresh_profile()
                self.vault.log("INFO", f"Created new alias {alias}:{hex_key}")
                logging.debug(f"Created new alias {alias}:{hex_key}")
            if self.current_server_name is not None:
                #link to current server
                self.vault.link_to_server(target_bytes, self.current_server_name)
                self.vault.log("INFO", f"Linked {alias} to {self.current_server_name}")
                logging.debug(f"Linked {alias} to {self.current_server_name}")

                self.refresh_profile()

                if hex_key in self.pending_hs:
                    #Responding
                    logging.debug(f"Responding to request session for {hex_key}")
                    # 'ciphertext' is [X3DH_LEN][X3DH_JSON][ACTUAL_CIPHER]
                    header, ciphertext, incoming_ts = self.pending_hs.pop(hex_key)
                    # Extract the X3DH
                    x3dh_len = struct.unpack(">I", ciphertext[:4])[0]
                    x3dh_json = ciphertext[4 : 4 + x3dh_len]
                    actual_cipher = ciphertext[4 + x3dh_len :]
                    #Accept session
                    self.vault.accept_session(target_bytes, x3dh_json)
                    self.vault.log("INFO", f"Created session for {hex_key}")
                    logging.debug(f"Created session for {hex_key}")
                    # Decrypt that first message they sent (dont show just for ratchet step)
                    try:
                        self.vault.receive(target_bytes, header, actual_cipher, incoming_ts)
                    except Exception as e:
                        logging.error(f"Ratchet sync failed: {e}")
                    self.ui_queue.put("added_friend")
                    logging.debug(f"Completed handshake for {hex_key}")
                    return
                #Initiating
                if not self.vault.has_session(target_bytes):
                    #Request prekeys from server (resp handled by handle_bundle_resp)
                    self.req_prekey_bundle(hex_key)
                    self.vault.log("INFO", f"Request session with {hex_key}")
                    logging.debug(f"Requested chat for {hex_key}")
            else:
                self.ui_queue.put({"print": "[i] Offline, alias created, but no request sent"})
        except Exception as e:
            logging.error(f"Friend handshake Error: {e}")
            self.vault.log("ERROR", f"Friend handshake Error: {e}")

    ##### INBOUND

    def process_buffer(self):
        while len(self._packet_buffer) >= HEADER_SIZE:
            try:
                msg_type, recip, sender, ts, h_len, d_len = struct.unpack(
                    HEADER_FMT, self._packet_buffer[:HEADER_SIZE]
                )
                total_len = HEADER_SIZE + h_len + d_len
                #Check policy rules:
                sender_hex = sender.hex()
                if self.rule_query(msg_type, sender_hex) and d_len <= self.profile_cache.get("max_msg_size", 1000000):
                    if len(self._packet_buffer) < total_len:
                        break # Wait for more data
                        
                    packet_data = self._packet_buffer[:total_len]
                    self._packet_buffer = self._packet_buffer[total_len:]
                    
                    header = packet_data[HEADER_SIZE : HEADER_SIZE + h_len]
                    data = packet_data[HEADER_SIZE + h_len :]
                    
                    # Pass the TS into the next stage
                    self.handle_net_buffer(msg_type, sender, header, data, ts)
                else:
                    self.vault.log("WARN", f"type {msg_type} from {sender.hex} blocked by policy")
                    logging.debug(f"type {msg_type} from {sender.hex} blocked by policy")
                    if len(self._packet_buffer) < total_len:
                        break # Wait for more data
                    self._packet_buffer = self._packet_buffer[total_len:]
            except Exception as e:
                logging.debug(f"Critical packet error while processing buffer: {e}")
                logging.error(f"Critical packet error while processing buffer")
                self._packet_buffer = b""
                break
    def handle_net_buffer(self, msg_type, sender, header, data, ts):
        logging.debug(f"Recieved msg type:{msg_type}")
        sender_hex = sender.hex()
        if msg_type == 0x03:   # Peers
            self.handle_list(data)
        elif msg_type == 0x04: # Prekeys
            self.handle_bundle_resp(sender, data)
        elif msg_type == 0x01: # Global Chat
            self.handle_chat_msg(sender, header, data, ts, False)
        elif msg_type == 0x11: # Private Chat
            self.handle_chat_msg(sender, header, data, ts, True)
        elif msg_type == 0x02: # Global File Transfer
            self.handle_file(sender, header, data, ts, False)
        elif msg_type == 0x12: # Private File Transfer
            self.handle_file(sender, header, data, ts, True)
        else:
            self.vault.log("WARN", f"Unknown msg_type {msg_type} from {sender_hex[:8]}")
            logging.debug(f"Unknown msg_type {msg_type} from {sender_hex[:8]}")
    #0x01 (MSG)
    def handle_chat_msg(self, sender, header, data, ts, is_dm):
        sender_hex = sender.hex().lower()
        if not self.vault.has_session(sender):
            #Chat request
            self.pending_hs[sender_hex] = (header, data, ts)
            self.vault.log("INFO", f"Recieved chat request from {sender_hex[:8]}..")
            logging.debug(f"Recieved chat request from {sender_hex[:8]}..")
            self.ui_queue.put({"print": f"[+] Chat Request from {sender_hex[:8]}.."})
            self.ui_queue.put({"print": f"[i] /friend <name> {sender_hex} to accept"})
            return
        try:
            #Decrypt
            decrypted_bytes = self.vault.receive(sender, header, data, ts)
            text = decrypted_bytes.decode('utf-8', errors='replace')
            
            # Tid resolution
            tid = self.get_tid(sender_hex) if is_dm else self.get_tid()
            if is_dm:
                tid = self.get_tid(sender_hex)
            else:
                tid = self.get_tid(ident=None, force_global=True)
            # Log and display
            self.vault.add_chat_log(tid, sender, ts, text)
            self.push_chat_ui(tid, sender, text, ts)
            logging.debug("Recieved and decrypted 0x01")
        except Exception as e:
            logging.error(f"type 0x01 msg decryption failed: {e}")
            self.vault.log("ERROR", f"type 0x01 msg decryption failed: {e}")
    #0x02 (FILE)
    def handle_file(self, sender, header, data, ts, is_dm):
        sender_hex = sender.hex().lower()
        try:
            decrypted_bytes = self.vault.receive(sender, header, data, ts)
            if not decrypted_bytes: return
            
            op_code = decrypted_bytes[0]
            content = decrypted_bytes[1:]
            
            # OpCode 0x01: Metadata / Start
            if op_code == 0x01:
                meta = json.loads(content.decode('utf-8'))
                file_id = meta["id"]
                
                # Prep temp file in cache
                cache_dir = os.path.join(self.get_home_dir(), ".cache", "fr3q", "temp")
                os.makedirs(cache_dir, exist_ok=True)
                temp_path = os.path.join(cache_dir, f"{file_id}.part")
                
                self.file_transfers[file_id] = {
                    "path": temp_path,
                    "total": meta["chunks"],
                    "current": 0,
                    "name": meta["name"]
                }
                # Clear previous temp if exists
                with open(temp_path, "wb") as f:
                    pass
                
                with self.transfer_lock:
                    self.transfer_progress[file_id] = {
                        "type": "RX", 
                        "name": meta["name"], 
                        "current": 0, "total": meta["chunks"]
                    }
                # Notify UI
                if is_dm: tid = self.get_tid(sender_hex)
                else: tid = self.get_tid(ident=None, force_global=True)
                
                display_text = f"SENT '{meta["name"]}'"
                #self.vault.add_chat_log(tid, sender, ts, display_text, final_path)
                self.push_chat_ui(tid, sender, display_text, ts, is_file=True)

            # OpCode 0x02: Data Chunk
            elif op_code == 0x02:
                file_id = content[:16].decode('utf-8')
                chunk_data = content[16:]
                
                if file_id in self.file_transfers:
                    ft = self.file_transfers[file_id]
                    with open(ft["path"], "ab") as f:
                        f.write(chunk_data)
                    ft["current"] += 1
                    
                    with self.transfer_lock:
                        if file_id in self.transfer_progress:
                            self.transfer_progress[file_id]["current"] = ft["current"]
                            self.ui_queue.put("update_progress")

                    # Check Completion
                    if ft["current"] >= ft["total"]:
                        # Move to Downloads
                        final_path = self.save_file(sender_hex, ft["name"], ft["path"])
                        del self.file_transfers[file_id]
                        
                        # Notify UI
                        if is_dm: tid = self.get_tid(sender_hex)
                        else: tid = self.get_tid(ident=None, force_global=True)
                        
                        display_text = f"SAVED '{final_path}'"
                        self.vault.add_chat_log(tid, sender, ts, display_text, final_path)
                        self.push_chat_ui(tid, sender, display_text, ts, is_file=True)
                        
                        with self.transfer_lock:
                            if file_id in self.transfer_progress:
                                del self.transfer_progress[file_id]

        except Exception as e:
            logging.debug(f"type 0x02 file error: {e}")

    def save_file(self, sender_hex, filename, temp_path):
        # Create a downloads folder in your config dir
        home = os.path.expanduser("~")
        download_path = os.path.join(home, "Downloads", "fr3q", self.current_server_name)
        os.makedirs(download_path, exist_ok=True)
        
        # Ensure unique name
        full_path = os.path.join(download_path, filename)
        if os.path.exists(full_path):
            base, ext = os.path.splitext(filename)
            full_path = os.path.join(download_path, f"{base}_{int(time.time())}{ext}")
            
        os.rename(temp_path, full_path)
        return full_path
        
    #0x03 (PEERS)
    def handle_list(self, jsonList):
        try:
            self.refresh_profile()
            old_set = set(self.peers) if self.peers else set()
            
            data = json.loads(jsonList.decode("utf-8"))
            if isinstance(data, dict):
                # New format: {"peers": [...], "rate_limit_ms": 50}
                new_list = data.get("peers", [])
                self.server_rate_limit_ms = data.get("rate_limit_ms", 50)
            else:
                # Old format: [...]
                new_list = data

            new_set = set(new_list)
            links = self.profile_cache.get('server_links',{}).get(self.current_server_name, [])
            joined = new_set - old_set
            left = old_set - new_set
            
            current_ts = time.time()
            
            # left
            for ident in left:
                #local leave messages are handled by disconnect command for now
                if self.me(ident): continue
                self.push_chat_ui(self.get_tid(), bytes.fromhex(ident), "Left", time.time(), False, False)

            # joined
            for ident in joined:
                if ident not in links:
                    self.vault.link_to_server(bytes.fromhex(ident), self.current_server_name)
                    self.refresh_profile()
                    logging.debug(f"Linked '{ident[:8]}..' to {self.current_server_name}")
                self.push_chat_ui(self.get_tid(), bytes.fromhex(ident), "Joined", time.time(), False, False)

            self.peers = new_list
            logging.debug(f"client list update:{str(new_list)}")
            
            
            # If we are in the list, the server has finished sending offline msgs
            if self.initial_sync and self.vault.get_my_identity_hex() in new_set:
                self.initial_sync = False
                self.status_msg = "CONNECTED"

            self.ui_queue.put("peer_list_update")
            
        except Exception as e:
            logging.error(f"type 0x03 parse failed: {e}")
    #0x04 (PREKEYS)
    def handle_bundle_resp(self, target_bytes, bundle_json):
        try:
            # Create session
            x3dh_header_bytes = self.vault.start_session(target_bytes, bundle_json)
            self.vault.log("INFO", f"Created session for {target_bytes.hex()}")
            ts = int(time.time())
            packets = self.vault.send_multicast([target_bytes], "CHAT_REQUEST".encode(), ts)
            # Dispatch with the X3DH header instead of the Ratchet header (OVERRIDE)
            for recipient, (ratchet_header, cipher) in packets:
                # Send BOTH headers
                prefixed_cipher = struct.pack(">I", len(x3dh_header_bytes)) + x3dh_header_bytes + cipher
                frame = struct.pack(
                    HEADER_FMT,
                    0x11, 
                    recipient,
                    bytes.fromhex(self.vault.get_my_identity_hex()),
                    ts,
                    len(ratchet_header),
                    len(prefixed_cipher)
                )
                frame += ratchet_header
                frame += prefixed_cipher
                self.network.send(frame)
            self.vault.log("INFO", f"Chat request sent to {target_bytes.hex()}")
            self.ui_queue.put({"print": f"[+] Chat request sent to {target_bytes.hex()[:8]}.."})
        except Exception as e:
            self.vault.log("ERROR", f"type 0x04 prekey processing failed: {e}")


    ##### UI
    # LIVE
    def push_chat_ui(self, tid: bytes, sender: bytes, text: str, ts: int, is_file=False, colon=True):
        sender_hex = sender.hex().lower()
        
        # get tid
        current_view_tid = self.get_tid() 
        if tid == current_view_tid:
            raw_msg = [(ts, text, "file" if is_file else None, sender)]
            
            formatted = self.format_logs(raw_msg, colon)[0]
            
            # Only clear notifications if we are NOT in the middle of a sync
            if not self.initial_sync:
                self.clear_notis()

            self.ui_queue.put({"chat": formatted})
            logging.debug(f"Pushed msg to UI for TID: {tid.hex()}")
        
        # Background notification logic (OR syncing logic)
        # We increment notifications if:
        # 1. It's not me sending the message AND
        # 2. (It's a background message OR we are currently syncing offline history) AND
        # 3. It's a real message (indicated by `colon` OR `is_file`)
        if not self.me(sender_hex) and (self.initial_sync or tid != current_view_tid) and (colon or is_file):
            alias = self.vault.get_contact_name(sender_hex) or sender_hex[:8]
            target = None
            if tid == self.get_tid(None, True):
                #global notification (room)
                target = self.current_server_name
            else:
                #dm notification
                target = alias
            
            if target:
                if target in self.notifications:
                    self.notifications[target] += 1
                else:
                    self.notifications[target] = 1
                self.ui_queue.put("notification")
            
            logging.debug(f"Background/Sync msg for TID: {tid.hex()[:8]}..")
    
    # MSG LOG
    def format_logs(self, raw_logs, colon=True):
        """Determines 'is_me' on the fly by comparing keys"""
        aliases = self.profile_cache.get("aliases", {})
        rev_aliases = {v.lower(): k for k, v in aliases.items()}
        
        formatted = []
        for ts, text, fpath, sender_raw in raw_logs:
            sender_hex = bytes(sender_raw).hex().lower()
            
            is_me = self.me(sender_hex)
            s_color = self.ident_color(sender_hex, True)
            if is_me:
                name = self.profile_cache.get("nickname", "YOU")
                #s_color = 13 # Cyan
                t_color = 8  # Light Grey
            else:
                name = rev_aliases.get(sender_hex, False)
                #s_color = 12 # Green
                if not name:
                    name = f"{sender_hex[:8]}.."
                    #s_color = 11 # Yellow
                t_color = 16 # White

            formatted.append({
                "time": time.strftime("%H:%M", time.localtime(ts)),
                "nick": name,
                "text": text,
                "sender_color": s_color,
                "text_color": 7 if fpath else t_color,
                "colon": False if fpath else colon
            })
        return formatted
    def get_msg_history(self, limit: int = 50):
        if not self.vault: return []
        try:
            raw_logs = self.vault.get_history(self.get_tid())
            # Slice BEFORE formatting
            recent_raw = raw_logs[-limit:] if len(raw_logs) > limit else raw_logs
            return self.format_logs(recent_raw)
        except Exception as e:
            logging.error(f"Engine: Failed to fetch history: {e}")
            return []
    def refresh_logs(self, limit: int = 50):
        """
        Polls vault history, formats it, and tells ui to refresh.
        """
        history = self.get_msg_history(limit=limit)
        self.ui_queue.put({
            "command": "refresh",
            "data": history
        })

    # VAULT LOGS
    def get_system_logs(self):
        if not self.vault: return []
        # Rust: Vec<(u64, String, String)>
        return self.vault.get_system_logs()
    # STATUS
    def tor_status(self):
        proxy = self.profile_cache.get("tor_proxy", "127.0.0.1:9050")
        try:
            proxy_ip, proxy_port = proxy.split(":")
            proxy_port = int(proxy_port)
        except ValueError:
            return 0
        return self.is_tor_running(proxy_ip, proxy_port)
    def get_status_bar_info(self):
        nick = self.profile_cache.get("nickname", "Unknown")
        if self.current_room_key is not None:
            room = self.vault.get_contact_name(self.current_room_key)
        else:
            room = "GLOBAL"
            
        with self.transfer_lock:
            active_transfers = self.transfer_progress.copy()
            
        return {
            "status": self.status_msg,
            "room": room,
            "server": self.current_server_name if self.current_server_name else "NONE",
            "nick": nick,
            "ver": self.ptver,
            "tor": self.tor_status(),
            "peers": self.peers,
            "notifications": self.notifications, # (name(str): amount(int))
            "transfers": active_transfers
        }