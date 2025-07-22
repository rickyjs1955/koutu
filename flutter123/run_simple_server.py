#!/usr/bin/env python3
import http.server
import socketserver
import socket
import os

PORT = 8085

# Get all IP addresses
def get_ip_addresses():
    hostname = socket.gethostname()
    ips = []
    
    # Try to get all IPs
    try:
        # Get all addresses
        addr_info = socket.getaddrinfo(hostname, None)
        for addr in addr_info:
            ip = addr[4][0]
            if ':' not in ip and ip != '127.0.0.1':  # IPv4 only, not localhost
                ips.append(ip)
    except:
        pass
    
    # Also try this method
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except:
        pass
    
    return list(set(ips))  # Remove duplicates

os.chdir('build/web')

Handler = http.server.SimpleHTTPRequestHandler

print(f"🚀 Starting Koutu Animation Server")
print(f"==================================")
print(f"")
print(f"💻 Local access:")
print(f"   http://localhost:{PORT}")
print(f"")
print(f"📱 Phone access (use one of these):")

ips = get_ip_addresses()
if ips:
    for ip in ips:
        print(f"   http://{ip}:{PORT}")
else:
    print(f"   Could not detect IP addresses")
    print(f"   Run 'ipconfig' in Windows to find your IP")

print(f"")
print(f"Press Ctrl+C to stop")
print(f"")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()