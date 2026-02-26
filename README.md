# FR3Q

FR3Q (a nod to phreaking) is an E2EE, cli, chat and file transfer network ran exclusively over the tor network. The zero-trust server runs as a hidden service and sees only the minimal information about the connected clients. Clients can communicate with each other using a custom designed protocol inspired by signal's implementation of the double ratchet encryption algorithm. As of now, this has only been tested on linux environments.


Privacy:

All cryptography is handled client side by a rust library that the python front end can interface with. The crypto library utilizes X3DH + Double Ratchet (ed25519) for messaging, Zeroize for memory security, and AES-256 with Argon2 for persistent storage.
The server acts as a "dumb router" in that it simply routes or caches raw data recieved. All identities are resolved to 32 byte public keys to allow for signature/identity verification client side.

The server is ran as a hidden service so it nor the clients can ever see the source or destination ip addresseses. The server is accessible as an onion url:port.

# CLONE
```
git clone https://github.com/MaxPep001011/fr3q
cd fr3q
```

# BUILD

Need:

1.Maturin 1.12.2+ *Tested with maturin installed via pip into a venv

2.Rustc & Cargo 1.93.1+

Build the rust crypto library
```
maturin develop -m crypto/Cargo.toml --release
```

# RUN

Need:

1.Python 3.13.12+ *Tested with python3.13 installed via pyenv into a venv

2.Tor


Client:
```
python3 src/fr3q.py
```


Server:

If using bind port >= 1024:
```
python3 src/fr3qserver.py
```
If using bind port < 1024 (privleged ports):
```
sudo python3 src/fr3qserver.py
```