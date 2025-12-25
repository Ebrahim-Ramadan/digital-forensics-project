import pyshark
from collections import Counter
import math
import re

def calculate_entropy(s):
    """Calculate Shannon entropy to detect potential DNS tunneling."""
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def parse_dns(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="dns")
    all_dns_queries = []
    suspicious_dns = []
    for packet in cap:
        try:
            if hasattr(packet, 'dns'):
                query = packet.dns.qry_name
                all_dns_queries.append(query)
                
                if len(query) > 50 or calculate_entropy(query) > 3.5 or re.search(r'\d{5,}', query) or query.endswith(('.ru', '.cn', '.xyz')):
                    suspicious_dns.append(query)
        except AttributeError:
            continue
    cap.close()
    return all_dns_queries, suspicious_dns

def parse_http(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http")
    all_http_requests = []
    suspicious_http = []
    for packet in cap:
        try:
            if hasattr(packet, 'http'):
                method = packet.http.request_method
                host = packet.http.host
                uri = packet.http.request_uri
                request = f"{method} {uri} Host: {host}"
                all_http_requests.append(request)
                
                if method not in ['GET', 'POST', 'HEAD'] or any(keyword in uri.lower() for keyword in ['/shell', '/cmd', '/admin', '/login', '/upload', '.php', '.asp']) or 'base64' in uri.lower():
                    suspicious_http.append(request)
        except AttributeError:
            continue
    cap.close()
    return all_http_requests, suspicious_http

def parse_tcp_sessions(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tcp")
    sessions = []
    for packet in cap:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            sport = packet.tcp.srcport
            dport = packet.tcp.dstport
            session = f"{ip_src}:{sport} -> {ip_dst}:{dport}"
            sessions.append((ip_src, ip_dst, sport, dport))
        except AttributeError:
            continue
    cap.close()
    
    
    session_counter = Counter(sessions)
    ip_dst_counter = Counter([s[1] for s in sessions])  
    port_counter = Counter([s[3] for s in sessions])   
    
    suspicious_tcp = []
    common_ports = {80, 443, 53, 22, 21, 25, 110, 143, 465, 587, 993, 995}
    
    for session, count in session_counter.items():
        if count > 10:  
            suspicious_tcp.append(f"Suspicious high count ({count}): {session[0]}:{session[2]} -> {session[1]}:{session[3]}")
    
    for ip, count in ip_dst_counter.items():
        if count > 50:  
            suspicious_tcp.append(f"Suspicious high connections to IP {ip}: {count} sessions")
    
    for port, count in port_counter.items():
        if int(port) not in common_ports and count > 5:
            suspicious_tcp.append(f"Suspicious activity on uncommon port {port}: {count} sessions")
    
    all_tcp_sessions = [f"{s[0]}:{s[2]} -> {s[1]}:{s[3]}" for s in set(sessions)]
    return all_tcp_sessions, suspicious_tcp

def analyze_pcap(pcap_file):
    print(f"Analyzing PCAP file: {pcap_file}")
    
    
    all_dns, suspicious_dns = parse_dns(pcap_file)
    print("\nAll DNS Queries:")
    for query in all_dns:
        print(query)
    if suspicious_dns:
        print("\nSuspicious DNS Queries:")
        for query in suspicious_dns:
            print(query)
    else:
        print("\nNo suspicious DNS queries detected.")
    
    
    all_http, suspicious_http = parse_http(pcap_file)
    print("\nAll HTTP Requests:")
    for request in all_http:
        print(request)
    if suspicious_http:
        print("\nSuspicious HTTP Requests:")
        for request in suspicious_http:
            print(request)
    else:
        print("\nNo suspicious HTTP requests detected.")
    
    
    all_tcp, suspicious_tcp = parse_tcp_sessions(pcap_file)
    print("\nAll Unique TCP Sessions:")
    for session in all_tcp:
        print(session)
    if suspicious_tcp:
        print("\nSuspicious TCP Activity:")
        for item in suspicious_tcp:
            print(item)
    else:
        print("\nNo suspicious TCP activity detected.")

if __name__ == "__main__":
    # pcap_file = "sample_traffic.pcap"  
    pcap_file = "test.pcap"  
    analyze_pcap(pcap_file)
