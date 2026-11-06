- **Test:** curl.exe http://example.com:9999 --connect-timeout 5. Filter: tcp.port == 9999 - **Result:** SYN sent, no reply, SYN retransmitted at about +1 s and +3 s (exponential backoff), curl gave up at 5 s - - **TCP Retransmission** = Wireshark label for the same segment sent again because no ACK came back. Gray = first SYN, black/red = retransmissions (warning color, not a fault on my PC)
- The OS's TCP stack does the resending, not curl. --connect-timeout 5 only makes curl give up after 5 s
- 4 destinations x 3 SYNs each (original + 2 retransmissions), none got a SYN-ACK- curl tried 4 destinations (2 IPv6 + 2 IPv4, all Cloudflare), each with its own source port - **Port states:** SYN > SYN-ACK = open. SYN > RST = closed (server answers immediately). SYN > retries and silence = filtered (firewall silently drops) - This capture = filtered. No RST seen ## Security tie-in - Port scanners (like Nmap) use these same replies to classify ports as open, closed, or filtered - Silent drops (filtered) give attackers less info than RSTs, which is why firewalls usually drop - Many SYNs to many ports with no handshake completing = scan pattern

The curl command basically says gives up after 5 seconds, without it curl would wait much longer. The point of the timeout is to make the packet capture short.
The 4 attempts at the top are 4 different IPs, 4456,4457, 4459, and 4460 which all had no replys.

In conclusion, since there was no reply sent back to the client, the client will keep retranmitting ( however it does not resend forever). The process is every retranmission waits longer each time, eventually it will run out of retires , and the OS will receive a error or failure report. Afterward curl will return connection timeout meaning no connection was made with the server after several retries. 

## Summary
1. DNS lookup returns the IPs (capture 01)
2. curl asks the OS to open a connection to port 9999
3. OS sends a SYN to each destination IP, no reply
4. OS retransmits the SYNs with growing delays
5. curl's 5 s timeout hits first, curl cancels and reports "Connection timed out"
![](<../screenshots/Pasted image 20261106144615.png>)
