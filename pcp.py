# import pyshark

# # Function to parse DNS queries from PCAP file
# def parse_dns(pcap_file):
#     cap = pyshark.FileCapture(pcap_file, display_filter="dns", use_json=True)  # Removed sync argument
#     dns_queries = []
    
#     for packet in cap:
#         if hasattr(packet, 'dns'):
#             # Check if it's a DNS query (usually 'qry_name' is in queries)
#             if hasattr(packet.dns, 'qry_name'):
#                 query = packet.dns.qry_name
#                 print(f"DNS Query: {query}")  # Print the DNS query to check
#                 dns_queries.append(query)
#             # Check if it's a DNS response and extract 'a' (IP address) or other response data
#             elif hasattr(packet.dns, 'a'):
#                 response_ip = packet.dns.a
#                 print(f"DNS Response: {response_ip}")  # Print the DNS response to check
#                 dns_queries.append(response_ip)

#     cap.close()  # Ensure the capture is closed properly after processing
#     return dns_queries

# # Function to parse HTTP requests from PCAP file
# def parse_http(pcap_file):
#     cap = pyshark.FileCapture(pcap_file, display_filter="http", use_json=True)  # Removed sync argument
#     http_requests = []
#     for packet in cap:
#         if hasattr(packet, 'http'):  # Check if HTTP layer exists
#             try:
#                 http_method = packet.http.request_method
#                 host = packet.http.host
#                 uri = packet.http.request_uri
#                 print(f"HTTP Request: {http_method} {host} {uri}")  # Print HTTP request to check
#                 http_requests.append({'method': http_method, 'host': host, 'uri': uri})
#             except AttributeError:
#                 continue
#     cap.close()  # Ensure the capture is closed properly after processing
#     return http_requests

# # Function to analyze TCP sessions from PCAP file
# def analyze_tcp(pcap_file):
#     cap = pyshark.FileCapture(pcap_file, display_filter="tcp", use_json=True)  # Removed sync argument
#     tcp_sessions = {}
#     for packet in cap:
#         if hasattr(packet, 'ip'):
#             src_ip = packet.ip.src
#             dst_ip = packet.ip.dst
#             src_port = packet.tcp.srcport
#             dst_port = packet.tcp.dstport
#             session_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
#             print(f"TCP Session: {session_key}")  # Print TCP session to check
#             if session_key not in tcp_sessions:
#                 tcp_sessions[session_key] = {'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port}
#     cap.close()  # Ensure the capture is closed properly after processing
#     return tcp_sessions

# # Function to flag suspicious traffic
# def flag_suspicious_traffic(dns_queries, http_requests, tcp_sessions):
#     print("\nSuspicious DNS Queries/Responses:")
#     for item in dns_queries:
#         if 'unknown' in item.lower():  # Example of a suspicious DNS query
#             print(f"- {item}")
    
#     print("\nSuspicious HTTP Requests:")
#     for req in http_requests:
#         if req['host'] not in ['trusted-domain.com', 'safe-site.com']:  # Example suspicious HTTP
#             print(f"- {req['method']} {req['host']} {req['uri']}")
    
#     print("\nSuspicious TCP Sessions:")
#     for session, details in tcp_sessions.items():
#         if details['src_ip'] == '192.168.1.100' and int(details['src_port']) > 1024:  # Example suspicious TCP
#             print(f"- {session}")

# # Main function to process the PCAP file
# def analyze_pcap(pcap_file):
#     print(f"Analyzing PCAP file: {pcap_file}\n")

#     dns_queries = parse_dns(pcap_file)
#     http_requests = parse_http(pcap_file)
#     tcp_sessions = analyze_tcp(pcap_file)

#     # Flag suspicious traffic based on the analysis
#     flag_suspicious_traffic(dns_queries, http_requests, tcp_sessions)

# # Run the analysis locally
# if __name__ == "__main__":
#     pcap_file = "sample_traffic.pcap"  # Replace with your PCAP file path
#     analyze_pcap(pcap_file)  # Synchronous call



import pyshark

def parse_dns(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="dns")
    dns_queries = []
    for packet in cap:
        try:
            if hasattr(packet, 'dns'):
                query = packet.dns.qry_name
                dns_queries.append(query)
        except AttributeError:
            continue
    cap.close()  # Manually close the capture
    return dns_queries

def parse_http(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http")
    http_requests = []
    for packet in cap:
        try:
            if hasattr(packet, 'http'):
                method = packet.http.request_method
                host = packet.http.host
                uri = packet.http.request_uri
                http_requests.append(f"{method} {uri} Host: {host}")
        except AttributeError:
            continue
    cap.close()  # Manually close the capture
    return http_requests

def parse_tcp_sessions(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp")
    tcp_sessions = []
    for packet in cap:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            sport = packet.tcp.srcport
            dport = packet.tcp.dstport
            session = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
            tcp_sessions.append(session)
        except AttributeError:
            continue
    cap.close()  # Manually close the capture
    return tcp_sessions

def analyze_pcap(pcap_file):
    print(f"Analyzing PCAP file: {pcap_file}")
    
    # Parse DNS
    dns_queries = parse_dns(pcap_file)
    if dns_queries:
        print("Suspicious DNS Queries/Responses:")
        for query in dns_queries:
            print(query)
    else:
        print("No suspicious DNS queries detected.")
    
    # Parse HTTP
    http_requests = parse_http(pcap_file)
    if http_requests:
        print("\nSuspicious HTTP Requests:")
        for request in http_requests:
            print(request)
    else:
        print("No suspicious HTTP requests detected.")
    
    # Parse TCP Sessions
    tcp_sessions = parse_tcp_sessions(pcap_file)
    if tcp_sessions:
        print("\nSuspicious TCP Sessions:")
        for session in tcp_sessions:
            print(session)
    else:
        print("No suspicious TCP sessions detected.")

if __name__ == "__main__":
    pcap_file = "sample_traffic.pcap"  # Replace with your PCAP file path
    analyze_pcap(pcap_file)
