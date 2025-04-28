import streamlit as st
import uuid
import json
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Initialize session state
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    
# Initialize the Fernet cipher
fernet = Fernet(st.session_state.fernet_key)

# Create secrets directory if it doesn't exist
SECRETS_DIR = Path("secrets")
SECRETS_DIR.mkdir(exist_ok=True)

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Generate a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def save_secret(secret: str, password: str = None) -> str:
    """Save a secret and return its unique identifier."""
    secret_id = str(uuid.uuid4())
    salt = Fernet.generate_key()[:16]  # Use first 16 bytes as salt
    
    # If password is provided, encrypt with password
    if password:
        key = generate_key_from_password(password, salt)
        f = Fernet(key)
        encrypted_secret = f.encrypt(secret.encode())
    else:
        encrypted_secret = fernet.encrypt(secret.encode())
    
    secret_data = {
        'secret': encrypted_secret.decode(),
        'created_at': datetime.now().isoformat(),
        'salt': salt.decode() if password else None,
        'has_password': bool(password)
    }
    
    secret_path = SECRETS_DIR / f"{secret_id}.json"
    with open(secret_path, 'w') as f:
        json.dump(secret_data, f)
        
    return secret_id

def get_secret(secret_id: str, password: str = None) -> str:
    """Retrieve and delete a secret."""
    secret_path = SECRETS_DIR / f"{secret_id}.json"
    
    try:
        with open(secret_path, 'r') as f:
            secret_data = json.load(f)
            
        # Delete the secret file immediately
        secret_path.unlink()
        
        encrypted_secret = secret_data['secret'].encode()
        
        if secret_data['has_password']:
            if not password:
                raise ValueError("Password required")
            
            salt = secret_data['salt'].encode()
            key = generate_key_from_password(password, salt)
            f = Fernet(key)
            try:
                decrypted_secret = f.decrypt(encrypted_secret)
            except Exception:
                raise ValueError("Invalid password")
        else:
            decrypted_secret = fernet.decrypt(encrypted_secret)
            
        return decrypted_secret.decode()
        
    except FileNotFoundError:
        return None

# Streamlit UI
st.title("🔒 One-Time Secret Sharing")
st.write("Share sensitive information securely with a self-destructing link")

# Check if we have a secret_id in the URL
current_secret_id = st.query_params.get("secret_id", None)

# Determine which tab should be active
if current_secret_id:
    # If we have a secret_id, default to the View Secret tab
    tab2, tab1 = st.tabs(["View Secret", "Create Secret"])
    active_tab = "view"
else:
    # Otherwise, default to the Create Secret tab
    tab1, tab2 = st.tabs(["Create Secret", "View Secret"])
    active_tab = "create"

# Add base URL input only in create tab
with tab1:
    base_url = st.text_input("Base URL (optional)", value="http://localhost:8501", help="The base URL where this app is hosted. Change this if you're hosting the app somewhere else.")
    
    # Secret creation form
    secret = st.text_area("Enter your secret message", height=150)
    password = st.text_input("Password (optional)", type="password")
    
    if st.button("Generate Secret Link", type="primary"):
        if secret:
            secret_id = save_secret(secret, password)
            st.success("✨ Secret link generated successfully!")
            
            # Display the secret link
            secret_url = f"{base_url}?secret_id={secret_id}"
            st.code(secret_url, language=None)
            
            # Add a copy button
            st.markdown(f"""
            <div style='background-color: #f0f2f6; padding: 10px; border-radius: 5px;'>
                📋 Copy this link to share your secret. 
                <br>⚠️ Remember: The secret will self-destruct after being viewed once!
                {' 🔒 A password is required' if password else ''}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.error("Please enter a secret message")

with tab2:
    # Secret viewing form
    if current_secret_id:
        st.info("🔐 A secret has been shared with you!")
        st.warning("⚠️ Remember: This secret will be destroyed after viewing!")
        
        view_password = st.text_input("Enter password (if required)", type="password", key="view_password")
        
        if st.button("View Secret", type="primary", key="view_button"):
            try:
                revealed_secret = get_secret(current_secret_id, view_password)
                if revealed_secret:
                    st.success("✨ Secret revealed successfully!")
                    st.text_area("Secret message:", value=revealed_secret, height=150, disabled=True)
                    st.error("🗑️ This secret has been destroyed and cannot be viewed again.")
                else:
                    st.error("❌ Secret not found or already viewed")
            except ValueError as e:
                st.error(f"❌ Error: {str(e)}")
    else:
        st.info("💡 To view a secret, you need a secret link. Ask the sender to share one with you.")
        st.write("No secret ID found in the URL. The link should contain a '?secret_id=' parameter.") 