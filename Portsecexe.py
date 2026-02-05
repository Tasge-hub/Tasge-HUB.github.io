##This is the code for the Streamlit GUI + appending nmap and scapy on it for the Portsec app Project
import pandas as pd
import nmap
from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_working_if
import streamlit as st
import threading
import time
from collections import defaultdict
from ipwhois import IPWhois

# --- 1. SETTINGS & RISK DEFINITIONS ---
st.set_page_config(page_title="Portsec Security Tool", layout="wide")

RISK_PORTS = {
    21: "FTP (Plaintext)", 23: "Telnet (Insecure)", 25: "SMTP", 
    445: "SMB", 3389: "RDP", 135: "RPC", 139: "NetBIOS"
}

# --- 2. HELPER FUNCTIONS ---
def get_whois_info(ip):
    try:
        if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            return "Local Network"
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        return results.get('asn_description', "Unknown Organization")
    except:
        return "Lookup Failed"

def aggregate_nmap_results(nm):
    open_ports = []
    open_ports_by_host = defaultdict(list)
    for host in nm.all_hosts():
        for proto in ['tcp', 'udp']:
            if proto in nm[host]:
                for port in nm[host][proto]:
                    if nm[host][proto][port].get('state') == 'open':
                        open_ports.append(port)
                        service = nm[host][proto][port].get('name', 'unknown')
                        open_ports_by_host[host].append(f"{port}/{proto.upper()} ({service})")
    return open_ports_by_host, set(open_ports)

def analyze_traffic(packet_list, open_ports_filter):
    patterns = {'raw_data': []}
    
    for pkt in packet_list:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            proto, s_port, d_port = "Other", "-", "-"
            
            if TCP in pkt:
                proto, s_port, d_port = "TCP", pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto, s_port, d_port = "UDP", pkt[UDP].sport, pkt[UDP].dport

            # FILTER: Only include if the source or destination port is in our 'Open Ports' list
            if s_port in open_ports_filter or d_port in open_ports_filter:
                is_abnormal = d_port in RISK_PORTS
                reason = RISK_PORTS.get(d_port, "")
                
                patterns['raw_data'].append({
                    "Source": src, "S-Port": s_port,
                    "Dest": dst, "D-Port": d_port,
                    "Proto": proto, "Abnormal": is_abnormal,
                    "Risk Info": reason
                })
    return patterns

# --- 3. SIDEBAR CONFIG ---
st.sidebar.title("⚙️ System Config")

# Interface Detection
try:
    default_iface_name = get_working_if().name
except:
    default_iface_name = get_if_list()[0]

available_ifs = get_if_list()
selected_iface = st.sidebar.selectbox("Active Network Interface:", available_ifs, 
                                      index=available_ifs.index(default_iface_name) if default_iface_name in available_ifs else 0)

# Scan Time Adjustment
st.sidebar.markdown("---")
st.sidebar.subheader("⏲️ Scan Settings")
scan_duration = st.sidebar.slider("Scan & Sniff Duration (Seconds):", min_value=5, max_value=60, value=15)

st.sidebar.markdown("---")
st.sidebar.header("🆘 Troubleshooting")
st.sidebar.write("1. **Admin Mode:** Run terminal as Admin.\n2. **Npcap:** Ensure Npcap is installed.\n3. **Interface:** Ensure the correct card is selected above.")

# --- 4. MAIN UI ---
st.title("🛡️ Portsec: Open-Port Traffic Monitor")
target_ip = st.text_input("Enter Target IP Address:", placeholder="e.g., 10.0.0.5")

if st.button("Start Analysis"):
    if target_ip:
        packet_data = []
        
        with st.spinner("Fetching WHOIS..."):
            owner = get_whois_info(target_ip)
            st.info(f"**IP Owner:** {owner}")

        # Sniffing Thread
        def run_sniff(target, output, iface, timeout):
            packets = sniff(timeout=timeout, filter=f"host {target}", iface=iface)
            output.extend(packets)

        sniff_thread = threading.Thread(target=run_sniff, args=(target_ip, packet_data, selected_iface, scan_duration))
        sniff_thread.start()

        # Nmap Scan
        with st.spinner(f"Running Nmap & Sniffing for {scan_duration}s..."):
            nm = nmap.PortScanner()
            nm.scan(hosts=target_ip, arguments="-sS -F")
            
            # Progress Bar
            progress = st.progress(0)
            for i in range(100):
                time.sleep(scan_duration / 100)
                progress.progress(i + 1)
        
        sniff_thread.join()
        
        # Process Results
        nmap_res, open_ports_list = aggregate_nmap_results(nm)
        results = analyze_traffic(packet_data, open_ports_list)

        # Display results
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🛠️ Open Ports Found")
            if nmap_res:
                for host, ports in nmap_res.items():
                    for p in ports: st.success(f"Port Open: {p}")
            else: st.write("No open ports found.")

        with col2:
            st.subheader("📡 Traffic Statistics")
            st.write(f"Total Packets Sniffed: {len(packet_data)}")
            st.write(f"Relevant Packets (Open Ports Only): {len(results['raw_data'])}")

        st.markdown("---")
        st.subheader(f"📋 Traffic Log: Filtered by Open Ports ({', '.join(map(str, open_ports_list)) if open_ports_list else 'None'})")
        
        if results['raw_data']:
            df = pd.DataFrame(results['raw_data'])
            def highlight_abnormal(row):
                return ['background-color: #ffcccc' if row.Abnormal else '' for _ in row]
            st.dataframe(df.style.apply(highlight_abnormal, axis=1), use_container_width=True)
        else:
            st.info("No traffic found interacting with the detected open ports.")