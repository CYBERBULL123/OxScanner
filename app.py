import streamlit as st
from pathlib import Path

# Streamlit page configuration
st.set_page_config(
    page_title="OxScanner",
    page_icon="🛡️",
    layout="wide"
)

# Load custom CSS
def load_css(file_name):
    """Load and apply custom CSS from a file."""
    if Path(file_name).exists():
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    else:
        st.error("🚫 CSS file not found")

load_css("ui/Style.css")

# Function to load a page with UTF-8 encoding
def load_page(page_name):
    """Load and execute a Python script dynamically."""
    if Path(page_name).exists():
        with open(page_name, 'r', encoding='utf-8') as f:
            exec(f.read(), globals())
    else:
        st.error("🚫 Page not found")

# Initialize session state for login
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Function to handle login
def login():
    st.session_state.logged_in = True

# Display introduction and login page if not logged in
if not st.session_state.get("logged_in", False):
    st.title("🛡️ OxScanner & OxOSINT: Network and OSINT Security Suite")

    st.write("""
    Welcome to **OxScanner** and **OxOSINT**, your advanced cybersecurity toolkit for 
    **network analysis**, **security testing**, and **open-source intelligence (OSINT)**.

    🚀 **Key Features**:
    - **OxScanner**: Comprehensive tools for network vulnerability assessment and attack simulations.
    - **OxOSINT**: Cutting-edge tools to analyze PCAP files, visualize insights, and provide detailed subnetting.
    
    With this suite, you can secure your network confidently, analyze traffic efficiently, and gather critical insights. Ready to explore?
    """)

    st.divider()

    st.subheader("🔑 Why Choose OxScanner?")
    st.markdown("""
    - **Real-Time Analysis**: Test your network defenses and simulate potential attacks.
    - **Deep Scanning**: Identify vulnerabilities with comprehensive network assessments.
    - **Wireless Insights**: Monitor and analyze wireless traffic seamlessly.
    """)

    st.subheader("🕵️‍♀️ Why Choose OxOSINT?")
    st.markdown("""
    - **PCAP Analysis**: Upload and analyze PCAP files with detailed charts, graphs, and traffic breakdowns.
    - **Subnetting**: Generate **VLSM** and **FLSM** subnetting plans for your network.
    - **Actionable Intelligence**: Transform raw data into insights for informed decision-making.
    """)

    if st.button("🔑 Login to Explore", on_click=login):
        st.success("Welcome! You're now logged in.")

# Footer Func 
def footer():
    # Footer Section
    st.markdown("---")
    st.write("Developed by 🫡 Aditya Pandey")

    # Footer Links
    linkedin_url = "https://www.linkedin.com/in/aditya-pandey-896109224"
    website_url = "https://aadi-web-1.onrender.com/"
    github_url = "https://github.com/CYBERBULL123"
    medium_url = "https://cyberbull.medium.com/"

    # Glassmorphic Footer with 3D Effect and Shadows
    st.markdown(
        """
        <style>
        /* Footer Container with Glass Effect */
        .glass-footer {
            background: rgba(20, 20, 20, 0.85); /* Dark semi-transparent background */
            border-radius: 12px;
            padding: 20px 30px;
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.18);
            box-shadow: 
                0 4px 6px rgba(0, 0, 0, 0.4), /* Base shadow */              
            transform: perspective(1000px) translateZ(5px); /* Simulated depth */
            text-align: center;
            margin: 20px auto;
            width: 100%;
            color: #f2f2f2; /* Light text color */
        }

        /* Social Links Container */
        .social-container {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 18px;
        }

        /* Social Link Styling with Z-Axis Shadow */
        .social-link {
            display: flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            font-size: 1rem;
            color: #ddd; /* Light grey color */
            font-weight: 600;
            padding: 12px 18px;
            border-radius: 8px;
            transition: all 0.4s ease;
            background: rgba(35, 35, 35, 0.85);
            box-shadow: 
                0 4px 6px rgba(0, 0, 0, 0.5), /* Shadow underneath */
                0 6px 10px rgba(255, 255, 255, 0.1) inset; /* Inner glow effect */
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        /* Hover Effect with Depth */
        .social-link:hover {
            color: ##00050d;
            transform: perspective(1000px) translateZ(10px) translateY(-4px);
            box-shadow: 
                0 12px 24px rgba(0, 0, 0, 0.9); /* Depth shadow */
        }

        /* Emojis with Responsive Size */
        .emoji {
            font-size: 1.4rem;
            filter: drop-shadow(0 2px 2px rgba(0, 0, 0, 0.5)); /* Adds subtle shadow */
        }

        /* Footer Responsiveness */
        @media (max-width: 768px) {
            .glass-footer {
                width: 95%;
                padding: 16px;
            }

            .social-link {
                font-size: 0.9rem;
                padding: 10px 14px;
            }
        }
        </style>

        <div class="glass-footer">
            <p style="font-size: 1.3rem; font-weight: 700; margin-bottom: 12px;">Connect with Me</p>
            <div class="social-container">
                <a href="https://www.linkedin.com/in/aditya-pandey-896109224" class="social-link">
                    <span class="emoji">🔗</span> LinkedIn
                </a>
                <a href="https://aadi-web-1.onrender.com/" class="social-link">
                    <span class="emoji">🌐</span> Website
                </a>
                <a href="https://github.com/CYBERBULL123" class="social-link">
                    <span class="emoji">🐙</span> GitHub
                </a>
                <a href="https://cyberbull.medium.com/" class="social-link">
                    <span class="emoji">✍️</span> Medium Blog
                </a>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Load application tabs
def load_app():
    """Load the main application interface."""
    st.markdown("# OxScanner & OxOSINT Security Suite 🛡️")

    tabs = ["🛜 OxScanner", "🕵️‍♂️ OxOSINT"]
    selected_tab = st.tabs(tabs)

    with selected_tab[0]:
        st.header("🔍 OxScanner: Network Analysis Tools")
        st.write("Explore advanced network scanning and security testing tools.")
        load_page("oxscanner.py")

    with selected_tab[1]:
        st.header("🕵️ OxOSINT: Open-Source Intelligence Tools")
        load_page("osint.py")

    footer()

# Load the app
if st.session_state.logged_in:
    load_app()
