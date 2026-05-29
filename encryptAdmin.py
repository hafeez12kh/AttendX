import json
import os
from cryptography.fernet import Fernet

#key = os.environ.get("APP_SECRET_KEY")
#if not key:
   # raise RuntimeError("APP_SECRET_KEY not set")
key="0ELGC3Wl2GJyMLSxgl26lH0RSEJV1fiFTql0VvLmMd4="
fernet = Fernet(key.encode())

data = {
    "admin": {
        "username": "admin",
        "password": "9400"
    },
    "admin_action_password": "9400"
}

encrypted = fernet.encrypt(json.dumps(data).encode())

os.makedirs("secrets", exist_ok=True)
with open("secrets/users.enc", "wb") as f:
    f.write(encrypted)

print("Encrypted credentials created successfully")
