
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Configs ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Data Handling ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

store_data = load_data()

# === Custom CSS for UI Styling ===
st.markdown("""
    <style>
        body {
            background: linear-gradient(135deg, #2e004f, #000000);
            color: white;
        }
        .animated-title {
            font-size: 3em;
            font-weight: bold;
            text-align: center;
            background: linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: glow 1.5s infinite alternate;
        }
        @keyframes glow {
            from {
                text-shadow: 0 0 10px #ff00ff, 0 0 20px #ff00ff;
            }
            to {
                text-shadow: 0 0 25px #00ffff, 0 0 30px #ff00ff;
            }
        }
        .stButton>button {
            background: linear-gradient(90deg, #6a00ff, #b300ff);
            border: none;
            border-radius: 10px;
            color: white;
            padding: 10px 20px;
            font-size: 1em;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background: linear-gradient(90deg, #a600ff, #ff00cc);
            transform: scale(1.05);
        }
        .data-box {
            background-color: rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
            border: 1px solid #444;
        }
        input, textarea {
            background-color: #333 !important;
            color: #ffffff !important;
            border-radius: 10px !important;
            border: 1px solid #999 !important;
            padding: 10px !important;
        }
        .css-1d391kg {
            background-color: #1c0033 !important;
        }
        .sidebar-title {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(90deg, #ff00ff, #00ffff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 20px;
            text-align: center;
        }
        .sidebar-nav .nav-link {
            display: block;
            padding: 10px 15px;
            border-radius: 10px;
            background: #240041;
            color: #ffffff;
            text-decoration: none;
            transition: background 0.3s ease, transform 0.2s ease;
            font-weight: 500;
        }
        .sidebar-nav .nav-link:hover {
            background: linear-gradient(90deg, #6a00ff, #b300ff);
            transform: scale(1.03);
            color: #ffffff;
        }
    </style>
""", unsafe_allow_html=True)

# === Title ===
st.markdown('<div class="animated-title">🔐 Secure Data Encryption System</div>', unsafe_allow_html=True)
st.write("")

# === Sidebar Navigation ===
st.sidebar.markdown('<div class="sidebar-title">📂 Menu</div>', unsafe_allow_html=True)

menu = {
    "Home": "🏠 Home",
    "Register": "📝 Register",
    "Login": "🔐 Login",
    "Store Data": "📦 Store Data",
    "Retrieve Data": "🔍 Retrieve Data"
}
choice = st.sidebar.radio("Go to", list(menu.keys()), format_func=lambda x: menu[x])

# === Home ===
if choice == "Home":
    st.subheader("Welcome to the 🔐 Data Encryption System!")
    st.markdown("""
        - Streamlit-based secure data storage and retrieval system.  
        - Users store data with a unique passkey.  
        - Users decrypt data by providing the correct passkey.  
        - Multiple failed attempts result in a lockout.
    """)

# === Register ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    st.markdown('<div class="data-box">', unsafe_allow_html=True)
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in store_data:
                st.warning("⚠️ User already exists.")
            else:
                store_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(store_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")
    

# === Login ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏲️ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in store_data and store_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🎉 Welcome {username}")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("⛔ Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        st.markdown('<div class="data-box">', unsafe_allow_html=True)
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                store_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(store_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("All fields are required.")
        st.markdown('</div>', unsafe_allow_html=True)

# === Retrieve Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = store_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.markdown('<div class="data-box">', unsafe_allow_html=True)
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data, 1):
                st.code(item, language="text")
            st.markdown('</div>', unsafe_allow_html=True)

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
