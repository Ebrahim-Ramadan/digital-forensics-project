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
