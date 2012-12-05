1. Group Members:
   Craig Kost - ckost
   Raman Buttar - rsbuttar

2. Work Division
   - Extensive use of Pair Programming
   - Data Structures (Packet Queue, ARP Cache, LinkedList Database) by Craig
   - Protocol Structures (ICMP, LSU) by Raman
   - Threading, Mutexing by Raman and Craig
   - Debugging via dropping Interface by Craig

3. Known Problems:
   - If more than one router in the topology advertises a default gateway to the Internet, it results in a routing loop.

4. Code Design
   - Use of modularized methods to handle received packet
   - Use of LinkedList data structure to implement Packet Queue, ARP Cache, and PWOSPF Database
   - Use of structs to read Ethernet, ARP, ICMP, IP, Hello, LSU Header data
   - Use of threading and timers for debugging
