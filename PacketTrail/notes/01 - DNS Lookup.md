# DNS Response Fields

- **Flags (0x8180):** a 16-bit field in the DNS header. It's a row of on/off switches (bits) that describe the DNS message: is it a question or an answer, what was asked of the server, and did it work. Wireshark shows it as hex (0x8180) and breaks it into the bits below.
  - **QR (Query/Response) = 1:** this packet is a response (0 = query)
  - **RD (Recursion Desired) = 1:** my computer asked the server to do the whole lookup for me (recursion = the server chases the answer instead of just pointing me elsewhere)
  - **RA (Recursion Available) = 1:** the server says it can do that
  - **AA (Authoritative Answer) = 0:** the answer did NOT come straight from the nameserver that owns the domain, so my router relayed or cached it
  - **rcode (Response Code) = 0:** no error (3 = NXDOMAIN, "name doesn't exist")
  - **Opcode (Operation Code) = 0:** standard query (the kind of request)
  - **TC (Truncated) = 0:** message wasn't cut off (1 = too big for UDP, retry over TCP)
  - **AD (Authenticated Data) = 0:** server didn't validate the answer with DNSSEC (DNS Security Extensions = cryptographic signing of DNS data)
  - **CD (Checking Disabled) = 0:** client didn't turn off DNSSEC checking
  - **Z = 0:** reserved, unused
- **Flags in binary:** 1000 0001 1000 0000 = 0x8180
- **Questions: 1** is a count in the header, not a flag. It means 1 question is included. Responses repeat the question.
- **Think of it like:** the label on a package. It doesn't hold the data itself (that's the answer records), it tells you what kind of message this is and how it went.
- Flags only describe the DNS message. TCP vs UDP is decided a layer lower, in the UDP/TCP header.
![[Pasted image 20261104174411.png]]

![[Pasted image 20261104183246.png]]


-THe name is obviously the domain, the Type, Class means it belongs to the internet, TTL or time to live means how long, in seconds, a resolver or client may cache this answer before asking again, the data length is 4 which means 4 bytes which is the size of a typical IPv4.
-Both Answers of example.com are 2 separate records.
- **Anycast:** the CDN announces the same IP from many data centers, so one IP is not one machine
- **Two layers of addresses in this capture:**
  - **Packet source/destination** (me and my router): who is carrying the DNS message
  - **Answer IPs** (172.66.147.243, 104.20.23.154): data inside the message, the servers where example.com lives. My computer hasn't contacted them yet
- **Why the two answer IPs differ from each other:** two separate A records, because the CDN runs multiple servers for the domain
- **nslookup does not scan, ping, or contact the servers.** It asks a DNS server to translate a domain name into IP addresses and reads the reply. A later connection (browser, curl, ping) picks ONE IP from the answer
- **DNS returns a small set of IPs, not every server.** Big sites like amazon.com have thousands of servers, but the answer varies by location, load, and resolver
- **Next:** the TCP handshake in capture 02 will connect to one of these answer IPs

- **rcode 3 = NXDOMAIN:** seen on example.com.lan (search suffix tried first)
- **RR (Resource Record):** one unit of DNS data
- **Answer RRs: 2** = two A records returned (172.66.147.243, 104.20.23.154)
- **Authority / Additional RRs: 0** = no nameserver info included
- **Response time: 24.12 ms** = delay between query (7435) and response (7437)
- **Src port 53** = DNS server. Client used ephemeral port 56902