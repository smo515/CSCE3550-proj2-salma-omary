from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import jwt
import uuid
import sqlite3
import base64
import os

app = Flask(__name__)

# In-memory key storage (in production, use a secure key management system)
keys = {}
folder_path = "C:\\Users\\salma\\Downloads\\CSCE3550_Windows_x86_64 (1)"
database_name = "totally_not_my_privateKeys.db"# Specify the absolute path to your database file
db_path = os.path.abspath(f"{folder_path}/{database_name}")

def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(s):
    return datetime.fromisoformat(s.decode('utf-8'))

# sqlite3.register_adapter(datetime, adapt_datetime)
# sqlite3.register_converter("datetime", convert_datetime)

def private_key_to_jwk(kid, private_key):
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    return {
        "kid": str(kid),
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }

def get_valid_keys_from_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    c.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    rows = c.fetchall()
    conn.close()
    
    valid_keys = []
    for row in rows:
        kid, key_bytes, exp = row
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        # valid_keys.append((kid, private_key, datetime.fromtimestamp(exp, tz=timezone.utc)))
        valid_keys.append((kid, private_key, exp))
    
    return valid_keys

def get_key_from_db(expired=False):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    if expired:
        c.execute("SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (current_time,))
    else:
        c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
    
    row = c.fetchone()
    conn.close()
    
    if row:
        kid, key_bytes, exp = row
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        # print(f"kid: {kid}\nprivate key: {private_key} \nexp: {exp}")
        # return kid, private_key, datetime.fromtimestamp(exp, tz=timezone.utc)
        return kid, private_key, exp
    return None, None, None

def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (kid INTEGER PRIMARY KEY AUTOINCREMENT,
                  key BLOB NOT NULL,
                  exp INTEGER NOT NULL)''')
    # c.execute('''CREATE TABLE IF NOT EXISTS auth_logs
    #              (id INTEGER PRIMARY KEY AUTOINCREMENT,
    #               username TEXT NOT NULL,
    #               token TEXT NOT NULL,
    #               exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def generate_key_pair(expiry_days=30):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    kid_og = str(uuid.uuid4())
    # print(f"kid og: {kid_og}")

    exp = datetime.now(timezone.utc) + timedelta(days=expiry_days)
    exp_int = int(exp.timestamp())
    # exp_int = int(exp)
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    kid = c.lastrowid
    # kid = str(kid)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # c.execute("INSERT INTO keys (kid, private_key, public_key, exp) VALUES (?, ?, ?, ?)",
    #           (kid, private_pem, public_pem, exp.isoformat()))
    # c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem, exp))
    # c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem, exp_int))
    c.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (kid, private_pem, exp_int))
    conn.commit()
    # kid = c.lastrowid
    # kid = str(kid)
    
    # kid = kid_og
    # print(f"kid: {kid}")
    conn.close()
    
    return kid

def get_jwk(kid):
    key_data = keys[kid]
    public_key = key_data['public_key']
    numbers = public_key.public_numbers()
    return {
        "kid": str(kid),
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(numbers.n), #modulus
        "e": int_to_base64(numbers.e), #exponent
        "exp": int(key_data['exp'].timestamp())
    }

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return jwt.utils.base64url_encode(value_bytes).decode('ascii')

# Generate initial keys
# current_kid = generate_key_pair()
# expired_kid = generate_key_pair(-30)  # Generate an expired key

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    valid_keys = get_valid_keys_from_db()
    jwks = {
        "keys": [private_key_to_jwk(kid, private_key) for kid, private_key, _ in valid_keys]
    }
    return jsonify(jwks)
    # current_time = datetime.now(timezone.utc)
    # unexpired_keys = []

    # for kid, key_data in keys.items():
    #     if key_data['exp'] > current_time:
    #         jwk = get_jwk(kid)  # Assuming you have a get_jwk function
    #         unexpired_keys.append(jwk)

    # return jsonify({"keys": unexpired_keys})

@app.route('/auth', methods=['POST'])
def authenticate():
    username = request.json.get('username', '')
    use_expired = request.args.get('expired', 'false').lower() == 'true'

    kid, private_key, exp = get_key_from_db(expired=use_expired)
    
    if not private_key:
        return jsonify({"error": "No suitable key found"}), 400

    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": exp,
        "kid": str(kid)  # Include the kid in the payload
    }

    headers = {
        "kid": str(kid)
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers = headers)

    # Use parameterized query for insertion
    # conn = get_db_connection()
    # conn = sqlite3.connect(db_path)
    # c = conn.cursor()
    # c.execute("INSERT INTO auth_logs (username, token, exp) VALUES (?, ?, ?)", 
    #           (username, token, exp))
    # conn.commit()
    # conn.close()

    return jsonify({
        "token": token,
        # "expires": payload['exp'].isoformat(),
        "expires": payload['exp'],
        "used_expired_key": use_expired
    })

def load_keys():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # c.execute("SELECT kid, private_key, public_key, exp FROM keys")
    c.execute("SELECT kid, key, exp FROM keys")
    rows = c.fetchall()
    conn.close()

    for row in rows:
        kid, key_bytes, exp = row
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        keys[kid] = {
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "exp": datetime.fromtimestamp(exp, tz=timezone.utc)
        }
        # kid, private_pem, public_pem, exp_str = row
        # private_key = serialization.load_pem_private_key(private_pem, password=None)
        # public_key = serialization.load_pem_public_key(public_pem)
        # exp = datetime.fromisoformat(exp_str)
        # keys[kid] = {
        #     "private_key": private_key,
        #     "public_key": public_key,
        #     "exp": exp
        # }

if __name__ == '__main__':
    init_db()
    
     # Check if we have valid and expired keys
    valid_kid, _, _ = get_key_from_db(expired=False)
    expired_kid, _, _ = get_key_from_db(expired=True)
    
    if not valid_kid:
        generate_key_pair(30)  # Generate a valid key (30 days expiry)
        print(f"not valid key")
    if not expired_kid:
        generate_key_pair(-30)  # Generate an expired key (30 days in the past)
        print(f"valid key")

    # load_keys()
    # # print(f"um")
    # if not keys:
    #     current_kid = generate_key_pair()
    #     expired_kid = generate_key_pair(-30)
    #     print(f"uwu no keys \nnew key: {current_kid}")
    # else:
    #     current_kid = max(keys, key=lambda k: keys[k]['exp'])
    #     expired_kid = min(keys, key=lambda k: keys[k]['exp'])
    #     print(f"keys true: \n{keys}")
    app.run(host='0.0.0.0', port=8080)
