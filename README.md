# OxScanner 🚀

**OxScanner** is a powerful cybersecurity tool, part of the **OxSuite**, built using Python and Streamlit. It offers a comprehensive suite of functionalities for network security analysis, including scanning, sniffing, and server setup. Designed for cybersecurity professionals, developers, and enthusiasts, OxScanner empowers users to enhance their network security expertise and test systems against a range of attacks.

---

## Features ✨

OxScanner provides an extensive array of network security and troubleshooting features:

- **Network Scanning**: Identify active hosts, open ports, and services on your network for a comprehensive view.
- **ARP Spoofing and MitM Attacks**: Perform ARP cache poisoning and man-in-the-middle attacks for penetration testing scenarios.
- **DNS and mDNS Server Setup**: Easily configure DNS, mDNS, LLMNR, and NetBIOS servers for various networking scenarios.
- **IKE Scanning**: Analyze Internet Key Exchange (IKE) connections in VPN configurations to assess security.
- **Wireless Sniffing**: Capture and analyze wireless network packets for deep insights into Wi-Fi traffic.
- **Traceroute Capabilities**: Perform TCP SYN, UDP, and DNS traceroutes to analyze network path and latency.
- **Classical Network Attacks**: Execute a range of classic network attack types such as Ping of Death, SYN Flood, UDP Flood, and more.

---

## Requirements 🛠️

Before using OxScanner, ensure the following prerequisites are met:

- **Operating System**:
  - Linux (Ubuntu/Debian preferred) for full network functionality.
  - Windows is supported but may require additional configuration.
  
- **Python 3.7+**: Ensure you have Python installed and updated.

- **Frameworks and Libraries**:
  - **Streamlit**: To build the interactive web interface.
  - **Scapy**: For advanced packet manipulation and crafting.

- **Additional Python Libraries**: Install the required dependencies using:
  ```bash
  pip install -r requirements.txt
  ```

- **Permissions**: Certain functionalities require administrative privileges. Use `sudo` on Linux/macOS or run as Administrator on Windows.

---

## Installation 🥳

Follow these steps to set up OxScanner on your machine:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/CYBERBULL123/OxScanner.git
   ```

2. **Navigate into the project directory**:
   ```bash
   cd OxScanner
   ```

3. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   streamlit run app.py
   ```

5. **Access the application**:
   Once the application is running, open your web browser and go to `http://localhost:8501` to interact with the OxScanner interface.

---

## Usage 📖

The intuitive interface of OxScanner allows for easy navigation and execution of various network security operations.

### Example Commands:

- **ARP Poisoning**: Input the client MAC address and gateway IP to initiate an ARP poisoning attack.
- **IKE Scanning**: Enter the target IP address to scan for IKE vulnerabilities.

Each section of the app includes step-by-step instructions, helping you execute network security tasks effortlessly.


### Wireless Sniffing and Testing:

For wireless testing, make sure your wireless interface (e.g., `wlan0`) is set to monitor mode. Use the following commands to enable monitor mode on a wireless interface:
```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```
Once the interface is in monitor mode, you can capture wireless traffic and perform various wireless security operations.

---

## Contribution 🤝

We welcome contributions from the community! To contribute to OxScanner, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Implement your changes and commit them (`git commit -m 'Add new feature'`).
4. Push to your branch (`git push origin feature/YourFeature`).
5. Open a Pull Request for review.

When contributing, please ensure your code is clean, well-documented, and adheres to best practices.

---

## Contact 📫

For questions, suggestions, or feedback, feel free to reach out:

- **Aditya Pandey** - [📧](mailto:opaadi98@gmail.com)
- **LinkedIn**: [Aditya Pandey](https://www.linkedin.com/in/aditya-pandey-896109224)

---

Thank you for exploring **OxScanner**! We hope you find it useful for all your network security needs. Happy hacking! 🔍💻

---