1. Group Members:
   Craig Kost - ckost
   Raman Buttar - rsbuttar

2. Work Division
   - Extensive use of Pair Programming
   - Data Structures (Packet Queue, ARP Cache) by Craig Kost
   - Protocol Structures (ICMP) by Raman Buttar

3. Known Problems:
   - Packet dropped once in a while when an ARP request is received from VNS server or firewall
   - Problems with the following ICMP messages:
       - ECHO reply for TRACEROUTE when the destination is one of the Router Interfaces (implemented not expected behavior but responding)
       - Host unreachable after sending ARP Request for 5 times (implemented but cannot test it)
       - Host Port unreachable if a TCP/UDP packet is destined for one of Router Interfaces (implemented but cannot test it as Firefox and IE do not display appropriate message)

4. Code Design
   - Use of modularized methods to handle received packet
   - Use of LinkedList data structure to implement Packet Queue and ARP Cache
   - Use of structs to read Ethernet, ARP, ICMP, IP Header data
