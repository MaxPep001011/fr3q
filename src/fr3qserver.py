# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.0.6"

MAX_INBOX_SIZE = 10*1024*1024 #10MB storage (queue + prekey storage)

import os
import shutil
import socket
import threading
import struct
import json
import signal
import sys
import time

HEADER_FMT = ">B32s32sQII" 
HEADER_SIZE = struct.calcsize(HEADER_FMT)
SERVER_IDENT_HEX = "00" * 32

class StorageManager:
    def __init__(self, base_dir="storage"): # 10MB default
        self.base_dir = base_dir
        self.max_inbox_size = MAX_INBOX_SIZE
        self.inbox_root = os.path.join(base_dir, "inboxes")
        self.bundle_root = os.path.join(base_dir, "bundles")
        os.makedirs(self.inbox_root, exist_ok=True)
        os.makedirs(self.bundle_root, exist_ok=True)

    def save_bundle(self, ident_hex, data):
        with open(os.path.join(self.bundle_root, f"{ident_hex}.bin"), "wb") as f:
            f.write(data)

    def get_bundle(self, ident_hex):
        path = os.path.join(self.bundle_root, f"{ident_hex}.bin")
        return open(path, "rb").read() if os.path.exists(path) else None

    def store_offline(self, recip_hex, full_frame):
        path = os.path.join(self.inbox_root, recip_hex)
        os.makedirs(path, exist_ok=True)
        
        # Quota Check
        current_size = sum(os.path.getsize(os.path.join(path, f)) for f in os.listdir(path))
        if current_size + len(full_frame) > self.max_inbox_size:
            return False
            
        # Save with nanosecond timestamp to preserve order
        with open(os.path.join(path, f"{time.time_ns()}.msg"), "wb") as f:
            f.write(full_frame)
        return True

    def flush_inbox(self, ident_hex):
        path = os.path.join(self.inbox_root, ident_hex)
        if not os.path.exists(path): return []
        
        msgs = []
        # Sort by filename (timestamp)
        for fname in sorted(os.listdir(path)):
            fpath = os.path.join(path, fname)
            with open(fpath, "rb") as f:
                msgs.append(f.read())
            os.remove(fpath) # Delete after reading
        return msgs

def s_timestamp():
    """ Timestamp for server log prints """
    return "[" + time.strftime("%H:%M:%S") + "]"

def pack_frame(msg_type, recipient_bytes, sender_bytes, timestamp, header_bytes, data_bytes):
    """Packs a frame according to the new wire protocol"""
    frame = struct.pack(
        HEADER_FMT,
        msg_type,
        recipient_bytes,
        sender_bytes,
        timestamp,
        len(header_bytes),
        len(data_bytes)
    )
    return frame + header_bytes + data_bytes

def send_client_list(clients):
    """Broadcasts all connected Identity Keys (Hex) to all clients"""
    client_list = list(clients.keys())
    data = json.dumps(client_list).encode("utf-8")
    
    # Empty header for system messages
    header = b"{}"
    server_bytes = bytes.fromhex(SERVER_IDENT_HEX)
    ts = int(time.time())
    for ident_hex, conn in clients.items():
        try:
            recipient_bytes = bytes.fromhex(ident_hex)
            # Type 0x03 = Client List Update
            packed = pack_frame(0x03, recipient_bytes, server_bytes, int(time.time()), header, data)
            conn.sendall(packed)
        except Exception as e:
            print(f"{s_timestamp()}[!] List failed for {ident_hex[:8]}: {e}")

def recv_exact(sock, n):
    buffer = b''
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk: return None
        buffer += chunk
    return buffer

storage = StorageManager()

def client_handler(conn, addr, clients):
    my_ident_hex = None
    try:
        #Join & register prekeys
        head_raw = recv_exact(conn, HEADER_SIZE)
        if not head_raw: return
        msg_type, recip_bytes, sender_bytes, ts, h_len, d_len = struct.unpack(HEADER_FMT, head_raw)
        h_data = recv_exact(conn, h_len) if h_len > 0 else b""
        d_data = recv_exact(conn, d_len) if d_len > 0 else b""
        
        my_ident_hex = sender_bytes.hex()
        if my_ident_hex:
            clients[my_ident_hex] = conn
            # Save prekeys
            if msg_type == 0x00 and not d_data == b"NONE":
                storage.save_bundle(my_ident_hex, d_data)
                print(f"{s_timestamp()}[+] STORED PREKEYS")

            print(f"{s_timestamp()}[+] {my_ident_hex} joined")
            # Send missed messages
            offline_msgs = storage.flush_inbox(my_ident_hex)
            for m in offline_msgs:
                conn.sendall(m)
            if offline_msgs:
                print(f"{s_timestamp()}[+] Delivered {len(offline_msgs)} offline messages to {my_ident_hex[:8]}..")
            # Send updated client list
            send_client_list(clients)
            # Routing loop
            while my_ident_hex:
                head_raw = recv_exact(conn, HEADER_SIZE)
                if not head_raw: break

                msg_type, recip_bytes, sender_bytes, ts, h_len, d_len = struct.unpack(HEADER_FMT, head_raw)
                h_data = recv_exact(conn, h_len) if h_len > 0 else b""
                d_data = recv_exact(conn, d_len) if d_len > 0 else b""
                
                sender_hex = sender_bytes.hex()
                recip_hex = recip_bytes.hex()
                full_frame = head_raw + h_data + d_data

                #Bundle Requests
                if recip_hex == SERVER_IDENT_HEX:
                    if msg_type == 0x04:
                        try:
                            target_hex = h_data.hex() 
                            bundle_raw = storage.get_bundle(target_hex)
                            print(f"{s_timestamp()}[+] Sent {target_hex[:8]} prekey -> {sender_hex[:8]}..")
                            if bundle_raw:
                                bundle_dict = json.loads(bundle_raw)
                                if bundle_dict.get("one_time_prekeys"):
                                    # Pop key
                                    single_opk = bundle_dict["one_time_prekeys"].pop()
                                    alice_bundle = bundle_dict.copy()
                                    alice_bundle["one_time_prekeys"] = [single_opk]
                                    # Save unused keys
                                    storage.save_bundle(target_hex, json.dumps(bundle_dict).encode())
                                    # Fill request
                                    data_to_send = json.dumps(alice_bundle).encode()
                                    resp = pack_frame(0x04, sender_bytes, bytes.fromhex(target_hex), int(time.time()), b"{}", data_to_send)
                                    conn.sendall(resp)
                                    print(f"{s_timestamp()}[>] Sent {target_hex[:8]}.. prekey -> {sender_hex[:8]}..")
                                else:
                                    print(f"{s_timestamp()}[-] No {target_hex[:8]}.. prekey avaliable")
                            else:
                                print(f"{s_timestamp()}[-] No prekeys avaliable")
                        except Exception as e:
                            print(f"{s_timestamp()}[!] Bundle fetch error: {e}")
                #Live Routing
                elif recip_hex in clients:
                    clients[recip_hex].sendall(full_frame)
                    print(f"{s_timestamp()}[>] {sender_hex[:8]}.. -> {recip_hex[:8]}..")
                #Offline Storage
                else:
                    success = storage.store_offline(recip_hex, full_frame)
                    status = "QUEUED" if success else "DROPPED (Queue Full)"
                    print(f"{s_timestamp()}[>] {sender_hex[:8]}.. -> {recip_hex[:8]}.. ({status})")
        else:
            print(f"{s_timestamp()}[-] Could not resovle ident hex, dropping connection")
    except Exception as e:
        print(f"{s_timestamp()}[!] Error: {e}")
    finally:
        if my_ident_hex:
            if my_ident_hex in clients:
                del clients[my_ident_hex]
            print(f"{s_timestamp()}[+] {my_ident_hex[:16]}.. left")
        else:
            print(f"{s_timestamp()}[-] UNKNOWN left")
        conn.close()
        # Send updated client list
        send_client_list(clients)
        

def main():
    print(f"***   FR3Qserver(v{ptversion})   ***\n")
    ip = input("[?] Bind IP [default 0.0.0.0]:").strip() or "0.0.0.0"
    try:
        lport = int(input("[?] Bind port [default 80]:").strip() or "80")
    except ValueError:
        lport = 80
    try:
        pport = int(input("[?] Service port [default 80]:").strip() or "80")
    except ValueError:
        pport = 80
    forwarded = input("[?] Already forwarded onion service in torrc? (y/N): ").lower().strip()
    if forwarded != "y":
        print("\n[+] Add/uncomment the following lines to your torrc and save:")
        print(" - Normal Linux: edit /etc/tor/torrc")
        print(f"    HiddenServiceDir /var/lib/tor/hidden_service/")
        print(f"    HiddenServicePort {pport} {ip}:{lport}")
        print(f"     - Adjust firewall to allow incoming connections at {ip}:{lport}")
        print("     - Then restart tor:")
        print("         sudo systemctl restart tor")
        print(" - Whonix (Qubes): edit /usr/local/etc/torrc.d/50_user.conf (in gatewayVM)")
        print(f"    HiddenServiceDir /var/lib/tor/hidden_service/")
        print(f"    HiddenServicePort {pport} 'whonix-workstation-ip':{lport}")
        print("     - Also edit firewall in the workstation (thisVM) and add the following")
        print(f"         EXTERNAL_OPEN_PORTS+=\" {lport} \"")
        print("     - Restart the firewall:")
        print("         sudo whonix_firewall")
        print("     - Then restart tor (in gatewayVM):")
        print("         sudo systemctl restart tor")
        input("--- PRESS ENTER WHEN COMPLETE AND TOR HAS RESTARTED ---")

    clients = {}
    print(f"{s_timestamp()}[+] Server init...")
    print("              - Starting listener...")

    def cleanup_message():
        print("\n[!] REMINDER:")
        print(f" - Delete the HiddenServiceDir (/var/lib/tor/hidden_service/)")
        print("   so a new onion address is generated next time.")
        print(" - Reset firewall rules.")
        print(" - Comment out or remove the HiddenService lines added to torrc.")
        print(" - Restart Tor after cleanup to restore normal behavior.\n")
        input("--- PRESS ENTER TO EXCUSE ---")

    # Handle Ctrl+C clean exit
    def handle_exit(sig, frame):
        print(f"\n{s_timestamp()}[+] Closing server...")
        server.close()
        print(f"{s_timestamp()}[+] Server closed")
        cleanup_message()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, lport))
    server.listen()
    print(f"              + Listening on {ip}:{lport}")
    print(f"\n{s_timestamp()}[+] Server started, url found at /var/lib/tor/hidden_service/hostname")

    

    while True:
        conn, addr = server.accept()
        threading.Thread(target=client_handler, args=(conn, addr, clients), daemon=True).start()

if __name__ == "__main__":
    main()
