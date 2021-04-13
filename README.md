# DNS-Sinkhole-Server

1. SinkholeServer: The main class of the project. creats a DNS server object and run its main logic, handles args.
2. DNSServer: Contains the main logic of the program (the main flow of reciving query, making iterative queries to the DNS servers and returning the answer).
Incharge of handling the DNS packets, editing them, and passing them to the UDPlClient and UDPServer classes.
3. UDPClient: In charge of sending queries to the DNS servers, receving the answers and passing back to DNSServer class.
4. UDPServer: In charge of receving queries from the outside client, and passing to DNSServer class for resolvation. When a query is resolved UDPServer returns the answer packet to the user.
