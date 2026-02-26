import socket
import threading
import queue
import struct
import logging
import time

class NetworkManager:
    """
    Dumb Transport Layer.
    Handles raw TCP connections, SOCKS5 Handshakes, and buffering.
    Can connect to a single server at a time.
    """
    def __init__(self, engine):
        self.engine = engine
        self.socket = None
        
        # queues for IO
        self.incoming_queue = queue.Queue()
        self.outgoing_queue = queue.Queue()
        
        self.is_connected = False
        self._shutdown_event = threading.Event()
        
        # Threads
        self._recv_thread = None
        self._send_thread = None

    

    def start(self, proxy_host, proxy_port, server_host, server_port):
        """
        Connects to the SOCKS5 Proxy (Tor) and requests a tunnel to the Server.
        """
        if not self.engine.is_tor_running(proxy_host, proxy_port):
            logging.warning(f"Tried to open new connection while proxy not avaliable:{proxy_host}:{proxy_port}")
            return 0
        if self.is_connected:
            logging.warning("Tried to open new connection while network already connected")
            return 0

        #Debug only as it prints url to plaintext
        logging.debug(f"Connecting with Proxy {proxy_host}:{proxy_port}")
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((proxy_host, proxy_port))
            
            # SOCKS5 Handshake
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if resp != b"\x05\x00":
                raise ConnectionError("SOCKS5 Auth failed")

            # Request Tunnel
            server_bytes = server_host.encode('utf-8')
            req = b"\x05\x01\x00\x03" + bytes([len(server_bytes)]) + server_bytes + struct.pack(">H", server_port)
            sock.sendall(req)
            
            reply = sock.recv(4) 
            if not reply or reply[1] != 0x00:
                raise ConnectionError(f"SOCKS5 Tunnel Refused")
            
            # Drain the rest
            if reply[3] == 0x01: sock.recv(4 + 2) # IPv4
            elif reply[3] == 0x03: sock.recv(sock.recv(1)[0] + 2) # Domain
            elif reply[3] == 0x04: sock.recv(16 + 2) # IPv6

            sock.settimeout(None)
            self.socket = sock
            self._shutdown_event.clear()
            # Start IO Threads only after self.socket is fully ready
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
            self._recv_thread.start()
            self._send_thread.start()
            # Update conn status
            self.is_connected = True
            return 1
        except Exception as e:
            self.is_connected = False
            if sock:
                try:
                    sock.close()
                except:
                    pass
            logging.error(f"Network Connection Failed")
            #Dont possibly print url in plaintext unless debug mode
            logging.debug(f"Network Connection Failed: {e}")
            raise e

    def stop(self):
        """Closes sockets and stops threads."""
        self.is_connected = False
        self._shutdown_event.set()
        
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except Exception:
                pass
            self.socket = None
        
        logging.info("Network stopped")

    def send(self, data: bytes):
        """Adds raw bytes to outgoing queue for the sender thread."""
        if self.is_connected:
            self.outgoing_queue.put(data)

    def _recv_loop(self):
        """Continuously reads bytes from socket and pushes to incoming_queue."""
        while not self._shutdown_event.is_set():
            try:
                if not self.socket: break
                data = self.socket.recv(4096)
                if not data:
                    logging.info("Socket closed by remote")
                    break
                self.incoming_queue.put(data)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logging.error(f"Receive Loop Error: {e}")
                break
        #lost connection
        self.stop()

    def _send_loop(self):
        logging.info("Send loop started")
        while not self._shutdown_event.is_set():
            try:
                try:
                    data = self.outgoing_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                if self.socket:
                    #send
                    self.socket.sendall(data)
                    logging.info(f"Sent {len(data)} bytes")
                else:
                    logging.warn("Send loop: Socket is None, dropping data.")
                    break 

            except (OSError, BrokenPipeError) as e:
                logging.error(f"Socket connection lost in send loop: {e}")
                break
            except Exception as e:
                logging.error(f"Unexpected Send Loop Error: {e}")
                break
        logging.info("Send loop exited")
        self.is_connected = False