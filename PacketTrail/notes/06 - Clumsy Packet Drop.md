- **Test:** clumsy (WinDivert) dropping 30% of packets on port 80, curl.exe http://example.com a few times, capture on Wi-Fi - **TCP Retransmission** (black/red): sender got no ACK in time, resends the same segment - **TCP Dup ACK:** receiver's ACK number didn't advance = it is missing earlier data - **SACK (SLE/SRE):** receiver says which byte ranges it did get, so only the missing data is resent - Wireshark captures below clumsy, so it records packets my TCP stack never received - TCP recovered by retransmitting, so the page still loaded, just slower ## Security tie-in - Retransmissions and duplicate ACKs are signs of loss, congestion, or interference, and can also come from tampering on the path - Spikes of RST or retransmissions from one host can point to a failing link, a firewall dropping traffic, or a DoS


![](<../screenshots/Pasted image 20261106155017.png>)
![](<../screenshots/Pasted image 20261106154925.png>)
