from flask import Flask, request, jsonify
from flask_socketio import SocketIO
import scapy.all as scapy
import requests
import maxminddb
import os
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Load environment variables
if not VIRUSTOTAL_API_KEY:
    raise ValueError("ERROR: VIRUSTOTAL_API_KEY is missing in environment variables")

# Load GeoLite2 database
geo_db = maxminddb.open_database("GeoLite2-Country.mmdb")

dns_stats = {}

def analyze_packet(packet):
    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP):
        dns_layer = packet[scapy.DNS]
        ip_layer = packet[scapy.IP]
        
        if dns_layer.qr == 0:  # Query packet
            domain = dns_layer.qd.qname.decode().strip('.')
            src_ip = ip_layer.src
            
            analyze_dns(domain)
            check_ip_threat(src_ip)
            log_geolocation(src_ip)

def analyze_dns(domain):
    subdomain = domain.split('.')[0]
    if len(subdomain) > 30 or any(c.isdigit() for c in subdomain):
        msg = f"[ALERT] Suspicious DNS: {domain}"
        print(msg)
        socketio.emit('alert', {'message': msg})
    
    dns_stats[domain] = dns_stats.get(domain, 0) + 1
    if dns_stats[domain] > 50:
        msg = f"[ALERT] High DNS volume detected: {domain}"
        print(msg)
        socketio.emit('alert', {'message': msg})

def check_ip_threat(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        
        if malicious_count > 0:
            msg = f"[ALERT] Malicious IP detected: {ip}"
            print(msg)
            socketio.emit('alert', {'message': msg})
    except Exception as e:
        print(f"VirusTotal API error: {e}")

def log_geolocation(ip):
    try:
        geo_data = geo_db.get(ip) or {}
        country = geo_data.get("country", {}).get("names", {}).get("en", "Unknown")
        print(f"IP {ip} is from {country}")
    except Exception as e:
        print(f"GeoLite2 lookup error: {e}")

def start_packet_capture():
    print("Starting packet capture on interface wlp3s0...")
    scapy.sniff(iface="wlp3s0", filter="udp port 53", prn=analyze_packet, store=False)

@app.route('/')
def home():
    return jsonify({"message": "Network Traffic Analyzer is running!"})

if __name__ == '__main__':
    threading.Thread(target=start_packet_capture, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
