### Class 1: SinkholeServer	
Sets up the Sinkhole server, and checks flag for blocklist to decide if the DNS server it starts has the capability to block DNS queries according to presupplied blocklist.

### Class 2: BlockListForDNS		
Extracts names form the blocklist text file, to allow a hash table to quickly decide if DNS names are to be blocked by the server that is searching for them, or not. 

### Class 3: BlockListEnforcer
Recieves the reader created in BlockListForDNS and creates a Hash table to assist the Sinkhole server with quickly deciding membrship to the supplied blocklist text file.

### Class 4: IterativeDNSServer
The server gets started from the SinkholeServer class. Its main job is to orchestrates the translation of valid packets to DNS records the Client recursively requests. It does that through iteratively challengeing other DNS servers.

### Class 5: RecursiveDNSClient
The client receives raw packets and then must extract DNS values from them. It does that through the DNSPacketHandler class. It also uses supplied packets as template for other packets to continue communication with the DNS Sinkhole server.

### Class 6: DNSPackerHandler
This class extracts the necessary information, including flags and labels from the raw UDP package it receives. Its main complexity lies in its navigation around the files, through a packet index, to extract necessary information. This can be done due to standartization.
