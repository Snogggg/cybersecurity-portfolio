## Client Hello (packet 942)
- **Record version TLS 1.0 / Handshake version TLS 1.2:** legacy compatibility values, not the real version
- **supported_versions (TLS 1.3, TLS 1.2):** what the client actually offers. Server picks one
- **Random:** 32 random bytes from the client, mixed into key generation
- **Session ID:** compatibility leftover in TLS 1.3
- **Cipher Suites (20 suites = 40 bytes):** encryption options the client supports. Server picks one
- **Compression Methods:** null only (compression removed after attacks like CRIME)
- **server_name (SNI = Server Name Indication) = example.com:** sent unencrypted, so observers can see which site I'm visiting
- **status_request:** client asks for OCSP (Online Certificate Status Protocol) info = is the certificate revoked?
- **Len 458 = 453 handshake + 5 record header**
- **Ethernet source vendor (AzureWaveTec):** my Wi-Fi card, from the MAC prefix
![[Pasted image 20261104200656.png]]

## Cipher suite anatomy
Example: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral):** key exchange. Agree on a shared secret without sending it. Ephemeral = new keys per session = forward secrecy
- **RSA / ECDSA (Elliptic Curve Digital Signature Algorithm):** authentication. Server proves identity by signing with its certificate's private key. Doesn't encrypt data
- **AES_128 (Advanced Encryption Standard):** the actual encryption of data. 128/256 = key size
- **GCM (Galois/Counter Mode):** how AES is applied, also checks for tampering. CBC (Cipher Block Chaining) = older mode
- **SHA256/SHA384 (Secure Hash Algorithm):** hash for integrity and key derivation. Hashing is not encryption (can't be reversed)

## Reading my list (20 suites)
- First 2 (0x1302, 0x1301) = TLS 1.3. Names skip key exchange/auth because 1.3 always uses ephemeral exchange
- ECDHE suites = TLS 1.2 with forward secrecy
- TLS_RSA_WITH_* at the bottom = no forward secrecy (legacy). CBC and SHA-1 suites also legacy/weak
- Client lists many options for compatibility, server picks one

## Security tie-in
- Weak cipher detection in audits (CBC, SHA-1, RSA key exchange, RC4, 3DES)
- JA3/JA4 fingerprinting: hash of Client Hello fields (cipher list etc.) identifies client software, even malware, in encrypted traffic
![[Pasted image 20261104200930.png]]

## Server Hello (packet 945)
- **Negotiated cipher suite: TLS_AES_256_GCM_SHA384 (0x1302)**, the client's first choice. 0x13xx = TLS 1.3 only
- AES_256 = encryption. GCM = mode that also checks for tampering. SHA384 = hash for key derivation and handshake
- TLS 1.3 suite names drop key exchange and authentication, since 1.3 always uses ephemeral key exchange (forward secrecy) and negotiates it separately
- **key_share extension:** shows the elliptic curve group used for the key exchange
- **Certificate is encrypted in TLS 1.3** (visible in TLS 1.2)
- Change Cipher Spec = compatibility leftover in 1.3, ignore
![[Pasted image 20261104201333.png]]




## Full conversation (tcp.stream eq 38)
- TCP handshake (SYN, SYN-ACK, ACK) on port 443, then Client Hello > Server Hello
- TLS 1.3 encrypts everything after Server Hello, so Wireshark labels the rest Application Data (certificate and Finished included)
- Server's handshake flight was split across 3 TCP segments, reassembled by Wireshark
- Client Change Cipher Spec + Finished = handshake complete, then encrypted GET and response
- Closes with FIN, ACK both ways, same as plain TCP
- TCP Dup ACK (black/red row) = duplicate acknowledgment, harmless here
- SYN to first encrypted data: about 20 ms
![[Pasted image 20261104201642.png]]