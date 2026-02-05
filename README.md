🛡️ Portsec Security Tool
Portsec is a real-time network security dashboard built with Python, Streamlit, and Scapy. 
It combines active vulnerability scanning (via Nmap) with passive traffic analysis and WHOIS
 enrichment to provide a comprehensive view of local and external network activity.

📋 Prerequisites
Before running the application, you must install the following system-level dependencies.

1. System Dependencies
Windows: * Download and install Nmap from the official site https://nmap.org/download.html#windows .

Ensure Npcap is installed (included in the Nmap installer). 
Critical: Check the box "Install Npcap in WinPcap API-compatible Mode" during setup.

Linux (Debian/Ubuntu): ```bash sudo apt update && sudo apt install nmap tcpdump libpcap-dev

macOS:
Bash
brew install nmap libpcap

2. Python Libraries
Install the required Python packages using pip:

Bash or cmd
pip install pandas python-nmap scapy streamlit ipwhois

🚀 Getting Started
Running the Application
Since this is a Streamlit application, it must be launched via the Streamlit CLI.

Note: Because the tool accesses raw network sockets for sniffing and scanning, 
you MUST run your terminal as an Administrator (Windows) or use sudo (Linux/macOS).

Bash
# Navigate to the project directory
cd path/to/your/project

# Launch the app
streamlit run Portsec+Whois.py

# You could also copy the full path by clicking the file
streamlit run "C:\Users\user\Desktop\Portsec\Portsecexe.py"

This allows you to run Portsec without being in the file
for advanced users it can be used to automate the process to 
only need one click

# To use Portsec you need your local ip, 
the moment you run the streamlit run command, you should receive this response in the cmd or powershell

  You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://198.exampleip:8501

198.example ip is your local ip and what you will imput in the "Enter Target IP Address" field

## WARNING ONLY USE YOUR OWN IP ##
## WARNING DO NOT USE VPN WHILE RUNNING THAT COMMAND ## 
OR ELSE YOU WILL BE SCANNING SOMEONE ELSES IP AND THEREFORE IS MALICIOUS ACTIVITY

🛠️ Features
Active Port Scanning: Uses Nmap to identify open ports on a target IP.

Real-time Sniffing: Captures live TCP/UDP traffic using Scapy.

WHOIS Enrichment: Automatically identifies the organization behind external IP addresses.

Risk Detection: Flags insecure protocols like FTP, Telnet, and SMB.

Visual Dashboard: Clean, interactive UI for filtering and analyzing traffic logs.

⚠️ Safety Warning
This tool is intended for authorized security testing and educational purposes only. 
Ensure you have explicit permission to scan and sniff traffic on the network you are testing. 
Unauthorized network scanning can be flagged as malicious activity by IT departments or ISPs.