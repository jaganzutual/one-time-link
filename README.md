# One-Time Secret Sharing App

A secure web application for sharing sensitive information through self-destructing links. Built with Streamlit and Python.

## Features

- Create one-time secret links that self-destruct after viewing
- Optional password protection for enhanced security
- Simple and intuitive user interface
- Secure encryption using Fernet (symmetric encryption)
- Automatic secret destruction after viewing

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
streamlit run app.py
```

3. Open your browser and navigate to the URL shown in the terminal (typically http://localhost:8501)

## Usage

### Creating a Secret
1. Go to the "Create Secret" tab
2. Enter your secret message
3. (Optional) Set a password
4. Click "Generate Secret Link"
5. Share the generated link with your recipient

### Viewing a Secret
1. Open the received secret link
2. Enter the password if required
3. Click "View Secret"
4. The secret will be displayed and then permanently destroyed

## Security Features

- Secrets are encrypted using Fernet symmetric encryption
- Optional password protection using PBKDF2 key derivation
- Secrets are stored encrypted and deleted immediately after viewing
- All secrets are stored locally in the `secrets` directory

## Note

This application stores secrets locally. For production use, consider implementing:
- Database storage
- Rate limiting
- Secret expiration
- Additional security measures # one-time-link
