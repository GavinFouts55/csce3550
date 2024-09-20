from flask import Flask, jsonify, request
import jwt # PyJWT library for handling JWT's
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib

app = Flask(__name__)

# Global variable to store generated keys
KEYS = []
EXPIRY_DURATION = 3600  # 1 hour expiry duration

# #1 Key Generation
def generate_key_pair():
    
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Serialize the private key to bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Get the corresponding public key
    public_key = private_key.public_key()
    # Serialize the public key to bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Generate a kid by hashing the public key bytes
    kid = hashlib.sha256(public_bytes).hexdigest()
    expiry = int(time.time()) + EXPIRY_DURATION
    # Store the key info
    KEYS.append({
        'kid': kid,
        'private_key': private_bytes,
        'public_key': public_bytes,
        'expiry': expiry
    })  
    return kid, private_bytes, public_bytes, expiry
# #2 Web server with two handlers
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    now = int(time.time())
    jwks_keys = []  
    # Iterate through the stored keys and filter valid ones
    for key in KEYS:
        if key['expiry'] > now:
            jwks_keys.append({
                "kty": "RSA",
                "kid": key['kid'],
                "use": "sig",
                "alg": "RS256",
                "n": jwt.utils.base64url_encode(
                    serialization.load_pem_public_key(key['public_key'], backend=default_backend()).public_numbers().n.to_bytes(256, 'big')
                ).decode('utf-8'),
                "e": "AQAB"
            })
    
    return jsonify({"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
def auth():
    
    # Check if the expired param is set
    expired = request.args.get('expired', 'false').lower() == 'true'
    now = int(time.time())

    # Select the appropriate key whether an expired token is requested
    key = None
    for k in KEYS:
        if (expired and k['expiry'] <= now) or (not expired and k['expiry'] > now):
            key = k
            break
    # If no valid key, error return
    if not key:
        return jsonify({"error": "No valid key available"}), 500

    private_key = serialization.load_pem_private_key(key['private_key'], password=None, backend=default_backend())
    # JWT payload
    payload = {
        'sub': 'user123',
        'iat': now,
        'exp': now + 600
    }
    # Encode the JWT using private key
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key['kid']})

    return jsonify({"token": token})
# Generate the inital key pair at startup
generate_key_pair()

if __name__ == '__main__':
    app.run(port=8080) # Run the flask at port 808