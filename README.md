# OXSuite 🚀

**OxScanner** is an advanced cybersecurity tool it is part of OxSuite built with Python and Streamlit, providing a range of functionalities including scanning, sniffing, and server setup for security analysis and network troubleshooting. This open-source project aims to facilitate cybersecurity professionals, developers, and enthusiasts in their journey to explore and enhance their network security skills.

## Table of Contents 📚

- [Features](#Features)
- [Requirements](#Requirements)
- [Installation](#Installation)
- [Usage](#Usage)
- [Contribution](#Contribution)
- [License](#License)
- [Contact](#Contact)

## Features ✨

- **Network Scanning**: Discover active hosts, open ports, and services running on your network.
- **ARP Spoofing and MitM Attacks**: Execute ARP cache poisoning and man-in-the-middle attacks for penetration testing.
- **DNS and mDNS Server Setup**: Set up DNS, mDNS, LLMNR, and Netbios servers for various networking scenarios.
- **IKE Scanning**: Analyze IKE (Internet Key Exchange) connections for VPN configurations.
- **Wireless Sniffing**: Capture and analyze wireless network packets.
- **Traceroute Capabilities**: Perform TCP SYN, UDP, and DNS traceroutes to analyze network paths.
- **Classical Attacks**: Execute various classical network attacks for testing purposes.

## Requirements 🛠️

Before using OXSuite, ensure you have the following:

- **Python 3.6+**
- **Streamlit**: For creating the web application interface.
- **Scapy**: For packet manipulation and crafting.
- **Additional Python Libraries**: Install the required packages using the following command:
  
  ```bash
  pip install -r requirements.txt
  ```

- **Permissions**: Some features may require root or administrative permissions to execute properly. Use `sudo` on Linux/macOS, or run as an Administrator on Windows.

## Installation 🥳

1. **Clone the repository**:

   ```bash
   git clone https://github.com/CYBERBULL123/OxScanner.git
   ```

2. **Navigate into the project directory**:

   ```bash
   cd OxScanner
   ```

3. **Install the required packages**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:

   ```bash
   streamlit run oxscanner.py
   ```

5. **Open your web browser** and go to `http://localhost:8501` to access OXSuite.

## Usage 📖

- Follow the prompts in the application to execute various network security functions.
- Each section of the app is designed to be intuitive and guide you through the necessary inputs.
  
### Example Commands

- **ARP Poisoning**: Input the client MAC and gateway IP to start the ARP poisoning.
- **IKE Scanning**: Provide the target IP to scan for IKE vulnerabilities.

## Contribution 🤝

Contributions are welcome! If you want to help improve OXSuite, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Make your changes and commit them (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

Please ensure to write tests for your features and keep your code clean and well-documented.

## License 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact 📫

For questions or feedback, please contact:

- **Aditya Pandey** - [📧](mailto:opaadi98@gmail.com)
- **GitHub**: [CYBERBULL123](https://github.com/CYBERBULL123)

---

Thank you for checking out OxScanner ! Happy hacking! 🔍💻
