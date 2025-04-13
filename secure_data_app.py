import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# ========== Global State ==========
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = True

# ========== Helper Functions ==========

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet_key(passkey: str) -> bytes:
    return hashlib.sha256(passkey.encode()).digest()[:32]

def encrypt_text(text: str, passkey: str) -> str:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode(), key.decode()

def decrypt_text(cipher_text: str, key: str) -> str:
    fernet = Fernet(key.encode())
    return fernet.decrypt(cipher_text.encode()).decode()

def reset_failed_attempts(user_id: str):
    st.session_state.failed_attempts[user_id] = 0

# ========== Pages ==========

def home_page():
    st.title("🔐 Secure Data Storage")
    st.write("Welcome! Choose an option:")
    if st.button("Store New Data"):
        st.session_state.page = "insert"
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"

def insert_page():
    st.title("📥 Store Data")
    user_id = st.text_input("User ID")
    text = st.text_area("Enter your text to store")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt and Save"):
        if user_id and text and passkey:
            encrypted_text, fernet_key = encrypt_text(text, passkey)
            st.session_state.stored_data[user_id] = {
                "encrypted_text": encrypted_text,
                "key": fernet_key,
                "passkey_hash": hash_passkey(passkey)
            }
            reset_failed_attempts(user_id)
            st.success("Data stored securely!")
        else:
            st.warning("All fields are required.")

    if st.button("Back"):
        st.session_state.page = "home"

def retrieve_page():
    st.title("📤 Retrieve Data")
    user_id = st.text_input("User ID")
    passkey = st.text_input("Enter your passkey", type="password")

    if user_id in st.session_state.failed_attempts and st.session_state.failed_attempts[user_id] >= 3:
        st.warning("Too many failed attempts. Redirecting to login.")
        st.session_state.is_authenticated = False
        st.session_state.page = "login"
        return

    if st.button("Decrypt"):
        if user_id in st.session_state.stored_data:
            stored = st.session_state.stored_data[user_id]
            if hash_passkey(passkey) == stored["passkey_hash"]:
                try:
                    decrypted = decrypt_text(stored["encrypted_text"], stored["key"])
                    st.success("Decryption successful!")
                    st.text_area("Decrypted Message", decrypted, height=150)
                    reset_failed_attempts(user_id)
                except Exception as e:
                    st.error("Failed to decrypt. Internal error.")
            else:
                st.session_state.failed_attempts[user_id] = st.session_state.failed_attempts.get(user_id, 0) + 1
                remaining = 3 - st.session_state.failed_attempts[user_id]
                st.error(f"Incorrect passkey! Attempts left: {remaining}")
        else:
            st.warning("No data found for this user.")

    if st.button("Back"):
        st.session_state.page = "home"

def login_page():
    st.title("🔒 Re-Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.success("Login successful!")
            st.session_state.is_authenticated = True
            for key in st.session_state.failed_attempts:
                st.session_state.failed_attempts[key] = 0
            st.session_state.page = "home"
        else:
            st.error("Invalid credentials!")

# ========== App Router ==========
def main():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    if not st.session_state.is_authenticated:
        login_page()
        return

    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "insert":
        insert_page()
    elif st.session_state.page == "retrieve":
        retrieve_page()

if __name__ == "__main__":
    main()
