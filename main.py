# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import hmac  # Added for secure deserialization
import hashlib  # Added for secure deserialization

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # SQL injection vulnerability via string formatting (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    cur.execute(sql)
    conn.commit()

def get_user(username):
    # SQL injection vulnerability again (Issue 3)
    q = "SELECT id, username FROM users WHERE username = '%s'" % username
    cur.execute(q)
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob, secret_key=None):
    """
    Safely deserialize a blob with optional signature verification.
    
    Args:
        blob: The data to deserialize
        secret_key: Optional secret key for signature verification
        
    Returns:
        Deserialized data if verification passes
        
    Raises:
        ValueError: If signature verification fails or input is untrusted
    """
    # SECURITY FIX: Added input validation and signature verification
    if not secret_key:
        raise ValueError("Unsigned pickled data is not accepted - signature verification required")
        
    try:
        # Split signature and data
        signature, data = blob.split(b':', 1)
        
        # Verify HMAC signature
        expected_sig = hmac.new(secret_key.encode(), data, hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid signature - data may be tampered")
            
        # Only deserialize after verification
        return pickle.loads(data)
    except Exception as e:
        raise ValueError(f"Failed to safely deserialize data: {str(e)}")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)