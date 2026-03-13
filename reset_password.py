import json
import os
import sys
import bcrypt
import getpass

CONFIG_FILE = "config.json"

def reset_password():
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: {CONFIG_FILE} not found. Start the scanner once to generate it.")
        return

    # Check write permission
    if not os.access(CONFIG_FILE, os.W_OK):
        print(f"Error: Permission denied writing to {CONFIG_FILE}")
        print("Hint: This file is owned by root. Run with sudo:")
        print(f"  sudo {sys.executable} reset_password.py")
        return

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error reading config: {e}")
        return

    # Get password with confirmation
    while True:
        new_password = getpass.getpass("Enter new administrative password: ").strip()
        if not new_password:
            print("Password cannot be empty.")
            continue
        
        confirm_password = getpass.getpass("Confirm password: ").strip()
        if new_password != confirm_password:
            print("Passwords do not match. Try again.")
            continue
        
        break

    config["password_hash"] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    config["session_token"] = None

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        print("\nSUCCESS: Password has been reset. Please restart the scanner.")
    except Exception as e:
        print(f"Error saving config: {e}")

if __name__ == "__main__":
    reset_password()
