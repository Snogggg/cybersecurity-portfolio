# PacketTrail

PacketTrail: Wireshark network traffic analysis lab, plus a Python analyzer that summarizes DNS and TCP activity in packet captures and flags odd behavior.

**Status:** complete

## What I investigated

| # | Capture | What I found |
|---|---|---|
| 1 | DNS lookup | nslookup example.com returned two A records (CDN-backed), TTL 106 s, rcode 0. The .lan search suffix was tried first and returned NXDOMAIN |
| 2 | TCP handshake | SYN, SYN-ACK, ACK, then HTTP GET and 200 OK, closed with FIN/ACK both ways |
| 3 | HTTPS | TLS 1.3, TLS_AES_256_GCM_SHA384 negotiated. SNI visible in the Client Hello, certificate encrypted |
| 4 | Failed connection | SYNs to port 9999 got no reply: retransmitted at about +1 s and +3 s, a filtered port. Capture in `captures/04-failed-connection.pcapng` |
| 5 | Unexpected DNS query | Random-looking domain returned NXDOMAIN for A and AAAA, with and without the .lan suffix. Capture in `captures/05-unexpected-dns.pcapng` |
| 6 | Impaired connection | Clumsy (WinDivert) dropping 30% of port 80 packets while running `curl.exe http://example.com`. Saw TCP Retransmission (no ACK in time, same segment resent), Dup ACKs (receiver's ACK number didn't advance, so earlier data is missing), and SACK ranges (receiver reports which bytes it did get, so only the missing data is resent). The page still loaded, just slower. Wireshark captures below Clumsy, so it records packets my TCP stack never received. Capture in captures/06-impaired-handshake.pcapng, notes in [notes/06 - Clumsy Packet Drop.md](notes/06%20-%20Clumsy%20Packet%20Drop.md) |

## Analyzer

`packettrail.py` reads .pcap/.pcapng files and reports:

- DNS queries, response codes, NXDOMAIN bursts, and random-looking names (entropy heuristic)
- TCP connection attempts: answered vs unanswered SYNs, retransmissions, RSTs, possible port scans

```powershell
pip install -r requirements.txt
python packettrail.py captures
```

Sample output is in `sample-output.txt`.

## Limitations

- Only DNS and TCP are analyzed. TLS contents are not parsed
- The random-name check is a simple heuristic and will miss some generated domains and flag some legitimate ones
- Captures are small and were taken on my own home network
- Scanning and impairment tests are run only on my own machine and lab traffic

## Security tie-in
- Retransmissions and duplicate ACKs signal loss, congestion, or interference, and can also come from tampering on the path
- Spikes of RST or retransmissions from one host can point to a failing link, a firewall dropping traffic, or a DoS
