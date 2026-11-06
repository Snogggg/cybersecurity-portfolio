

## Three-way handshake
- **SYN:** client asks to open a connection (Seq=0 relative)
- **SYN, ACK:** server agrees and sends its own SYN (Ack=1 = "send byte 1 next")
- **ACK:** client confirms, connection open
- ~15 ms between SYN and SYN-ACK = round-trip time to the server
- **SYN options:** MSS (Maximum Segment Size), WS (Window Scale), SACK_PERM (Selective Acknowledgment permitted). Each side advertises its own

## Data transfer
- GET / HTTP/1.1 = 75 bytes. Server ACKs it (Ack=76)
- Response split over 2 packets (928 + 5 bytes), Wireshark reassembles it into HTTP/1.1 200 OK
- Length column = whole frame. Len = TCP data only (SYN = 0)

## Closing
- FIN, ACK (client) > FIN, ACK (server) > ACK (client)
- A FIN counts as 1 byte, so numbers go up by 1
- Client (curl) closed first in this capture

## Security tie-in
- SYN with no SYN-ACK back = closed or filtered port. Many SYNs to many ports = port scan
- Floods of SYNs that never finish the handshake = SYN flood (DoS attack)