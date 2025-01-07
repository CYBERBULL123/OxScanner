import streamlit as st
from ipaddress import IPv4Network, AddressValueError
import pandas as pd
import requests
import math
import folium
from streamlit_folium import folium_static
import altair as alt
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
import tempfile



def run():

    # Load Custom CSS
    def load_css(file_name):
        with open(file_name) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

    load_css("ui/Style.css")

    # Function to Fetch Geolocation Information
    def fetch_geolocation(ip_address):
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        return response.json() if response.status_code == 200 else None

    # Function to Perform DNS Lookup
    def fetch_dns(domain):
        try:
            response = requests.get(f"https://dns.google/resolve?name={domain}")
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None

    # Function to Calculate VLSM Subnetting
    def subnet_vlsm(network, subnetworks):
        subnetworks.sort(reverse=True)
        sub_networks = []
        available_subnets = list(network.subnets())
        for subnet in subnetworks:
            for available_subnet in available_subnets:
                if available_subnet.num_addresses >= subnet + 2:
                    sub_networks.append(str(available_subnet))
                    available_subnets.remove(available_subnet)
                    break
        return sub_networks

    # Function to Generate Charts for Subnetting
    def generate_subnet_chart(data):
        chart_data = pd.DataFrame({
            "Subnet": [f"Subnet {i+1}" for i in range(len(data))],
            "Hosts": [int(str(network).split("/")[1]) for network in data]
        })
        chart = alt.Chart(chart_data).mark_bar().encode(
            x="Subnet",
            y="Hosts",
            color="Subnet",
            tooltip=["Subnet", "Hosts"]
        ).properties(title="Subnet Utilization Chart")
        return chart

    # Dashboard Layout
    st.markdown("**Empower your cybersecurity and networking tasks with a robust, professional toolkit.**")

    # Tab Setup
    tabs = st.tabs(["🌐 Subnetting Dashboard", "📍 Geolocation Insights", "🔍 Advanced OSINT Tools"])

    # Tab 1: Subnetting Dashboard
    with tabs[0]:
        st.header("🌐 Subnetting Dashboard")
        st.markdown("**Visualize your subnetting results with dynamic charts.**")

        cidr_input = st.text_input("📝 Enter CIDR Notation (e.g., `192.168.1.0/24`):")
        subnetworks_input = st.text_input("🔢 Enter Host Requirements (space-separated, e.g., `50 100 150`):")
        subnetting_method = st.radio("📊 Choose Subnetting Technique:", ["VLSM (Variable Length)", "FLSM (Fixed Length)"])

        if st.button("⚙️ Generate Subnets and Visualize"):
            if cidr_input and subnetworks_input:
                try:
                    net = IPv4Network(cidr_input, strict=False)
                    subnetworks = list(map(int, subnetworks_input.split()))

                    if subnetting_method.startswith("VLSM"):
                        results = subnet_vlsm(net, subnetworks)
                    else:
                        results = list(net.subnets(new_prefix=(32 - int(math.log2(max(subnetworks) + 2)))))

                    st.success("✅ Subnets Calculated Successfully!")
                    st.subheader("🔍 Generated Subnets")
                    for idx, subnet in enumerate(results, start=1):
                        st.write(f"{idx}. {subnet}")

                    st.subheader("📊 Subnet Visualization")
                    subnet_chart = generate_subnet_chart(results)
                    st.altair_chart(subnet_chart, use_container_width=True)

                except AddressValueError:
                    st.error("🚫 Invalid CIDR notation! Please check your input.")
                except Exception as e:
                    st.error(f"⚠️ An error occurred: {e}")
            else:
                st.error("⚠️ Please fill in all the required fields!")

    # Tab 2: Geolocation Insights
    with tabs[1]:
        st.header("📍 Geolocation Insights")
        st.markdown("**Track and visualize geolocation data for IP addresses.**")

        ip_to_lookup = st.text_input("🔎 Enter IP Address:")
        if st.button("🌍 Fetch Geolocation"):
            if ip_to_lookup:
                geo_info = fetch_geolocation(ip_to_lookup)
                if geo_info:
                    st.success("✅ Geolocation Data Fetched Successfully!")
                    st.subheader("📍 Geolocation Information")
                    st.json(geo_info)

                    if "loc" in geo_info:
                        latitude, longitude = map(float, geo_info["loc"].split(","))
                        map_geo = folium.Map(location=[latitude, longitude], zoom_start=10)
                        folium.Marker([latitude, longitude], tooltip=f"{ip_to_lookup} Location").add_to(map_geo)
                        st.markdown("### 🌍 Geolocation Map")
                        folium_static(map_geo)
                else:
                    st.error("🚫 Unable to fetch geolocation data.")
            else:
                st.error("⚠️ Please enter a valid IP address.")


    # Tab 3: Advanced Network Inspection Tools
    with tabs[2]:
        # PCAP File Analysis Section
        st.subheader("📂 Upload PCAP File for Traffic Analysis")
        uploaded_file = st.file_uploader("Upload a PCAP file to analyze network traffic", type=["pcap", "pcapng"], key="pcap_file_uploader")

        # Function to process PCAP file
        def process_pcap(file_path):
            """
            Processes the PCAP file using Scapy and extracts key fields into a DataFrame.
            """
            packets = rdpcap(file_path)  # Read the PCAP file
            packet_data = []

            for packet in packets:
                if IP in packet:
                    packet_info = {
                        "Time": packet.time,
                        "Source": packet[IP].src,
                        "Destination": packet[IP].dst,
                        "Protocol": packet[IP].proto,
                        "Length": len(packet),
                    }
                    
                    # Check for various protocols and capture relevant details
                    if TCP in packet:
                        packet_info["Protocol"] = "TCP"
                        packet_info["Source Port"] = packet[TCP].sport
                        packet_info["Destination Port"] = packet[TCP].dport
                    elif UDP in packet:
                        packet_info["Protocol"] = "UDP"
                        packet_info["Source Port"] = packet[UDP].sport
                        packet_info["Destination Port"] = packet[UDP].dport
                    elif ICMP in packet:
                        packet_info["Protocol"] = "ICMP"
                        packet_info["Source Port"] = None
                        packet_info["Destination Port"] = None
                    elif ARP in packet:
                        packet_info["Protocol"] = "ARP"
                        packet_info["Source Port"] = None
                        packet_info["Destination Port"] = None
                    elif DNS in packet:
                        packet_info["Protocol"] = "DNS"
                        packet_info["Source Port"] = packet[UDP].sport if UDP in packet else None
                        packet_info["Destination Port"] = packet[UDP].dport if UDP in packet else None
                    elif HTTP in packet:
                        packet_info["Protocol"] = "HTTP"
                        packet_info["Source Port"] = packet[TCP].sport
                        packet_info["Destination Port"] = packet[TCP].dport
                    else:
                        packet_info["Source Port"] = None
                        packet_info["Destination Port"] = None

                    packet_data.append(packet_info)

            return pd.DataFrame(packet_data)

        if uploaded_file:
            try:
                # Save uploaded file to a temporary location
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
                    temp_file.write(uploaded_file.getbuffer())
                    temp_file_path = temp_file.name

                st.success("✅ PCAP File Uploaded Successfully!")
                st.markdown("### Extracting Network Traffic Data...")

                # Process the PCAP file and convert it to a DataFrame
                packets_df = process_pcap(temp_file_path)

                if not packets_df.empty:
                    # Display the DataFrame
                    st.subheader("📜 Captured Packets Summary")
                    st.dataframe(packets_df.head(10))

                    # Visualizations
                    st.subheader("📊 Traffic Analysis Charts")
                    st.divider()
                    
                    # Create two columns for responsiveness
                    col1, col2 = st.columns(2)

                    # Protocol Distribution (in column 1)
                    with col1:
                        protocol_distribution = packets_df['Protocol'].value_counts().reset_index()
                        protocol_distribution.columns = ['Protocol', 'Count']
                        
                        protocol_chart = alt.Chart(protocol_distribution).mark_bar().encode(
                            x=alt.X('Protocol:N', title='Protocol'),
                            y=alt.Y('Count:Q', title='Packet Count'),
                            color='Protocol:N',
                            tooltip=['Protocol:N', 'Count:Q']
                        ).properties(title="Protocol Distribution")
                        
                        st.altair_chart(protocol_chart, use_container_width=True)

                    # Top Talkers (Source IPs) (in column 2)
                    with col2:
                        top_talkers = packets_df['Source'].value_counts().head(-1).reset_index()
                        top_talkers.columns = ['Source IP', 'Count']
                        
                        top_talkers_chart = alt.Chart(top_talkers).mark_bar().encode(
                            x=alt.X('Source IP:N', title='Source IP'),
                            y=alt.Y('Count:Q', title='Packet Count'),
                            color='Source IP:N',
                            tooltip=['Source IP:N', 'Count:Q']
                        ).properties(title="Top 10 Source IPs")
                        
                        st.altair_chart(top_talkers_chart, use_container_width=True)

                    # Length Distribution (Packet Size) (in column 1)
                    with col1:
                        
                        length_distribution = packets_df[['Length', 'Protocol']].head(-1)  # Show first 100 packets for better visualization
                        length_chart = alt.Chart(length_distribution).mark_point().encode(
                            x='Length:Q',
                            y='Protocol:N',
                            color='Protocol:N',
                            tooltip=['Length:Q', 'Protocol:N']
                        ).properties(title="Packet Length vs Protocol")
                        
                        st.altair_chart(length_chart, use_container_width=True)

                    # TCP vs UDP Traffic Distribution (in column 2)
                    with col2:
                        tcp_udp = packets_df['Protocol'].value_counts().reset_index()
                        tcp_udp.columns = ['Protocol', 'Count']
                        
                        tcp_udp_chart = alt.Chart(tcp_udp).mark_bar().encode(
                            x=alt.X('Protocol:N', title='Protocol'),
                            y=alt.Y('Count:Q', title='Packet Count'),
                            color='Protocol:N',
                            tooltip=['Protocol:N', 'Count:Q']
                        ).properties(title="TCP vs UDP Traffic Distribution")
                        
                        st.altair_chart(tcp_udp_chart, use_container_width=True)

                    # Detailed Protocol-wise Traffic (TCP, UDP, ICMP) (in column 1)
                    with col1:
                        detailed_protocol = packets_df.groupby('Protocol')['Length'].sum().reset_index()
                        
                        detailed_protocol_chart = alt.Chart(detailed_protocol).mark_bar().encode(
                            x=alt.X('Protocol:N', title='Protocol'),
                            y=alt.Y('Length:Q', title='Total Packet Size (Bytes)'),
                            color='Protocol:N',
                            tooltip=['Protocol:N', 'Length:Q']
                        ).properties(title="Total Packet Size by Protocol")
                        
                        st.altair_chart(detailed_protocol_chart, use_container_width=True)

                        # 2. Protocol-wise Distribution (within the first 10 packets)
                        protocol_chart = alt.Chart(packets_df.head(-1)).mark_bar().encode(
                            x='Protocol:N',
                            y='count():Q',
                            color='Protocol:N',
                            tooltip=['Protocol:N', 'count():Q']
                        ).properties(title="Protocol Distribution")

                        st.altair_chart(protocol_chart, use_container_width=True)

                    # Optional: Display packet data for further inspection using Altair
                    with col2:
                        # Visualize the first 10 packets using Altair
                        # 1. Packet Length Distribution
                        length_chart = alt.Chart(packets_df.head(-1)).mark_bar().encode(
                            x='Length:Q',
                            y='Source:N',
                            color='Protocol:N',
                            tooltip=['Source:N', 'Length:Q', 'Protocol:N']
                        ).properties(title="Packet Length Distribution")

                        # Display the charts in the column
                        st.altair_chart(length_chart, use_container_width=True)

                else:
                    st.error("🚫 No valid packets found in the PCAP file.")

            except Exception as e:
                st.error(f"🚫 Error processing PCAP file: {e}")

if __name__ == "__main__":
    run()
