# AES-encryption-tool-
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Function to pad plaintext to block size
def pad(data):
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding

# Function to unpad the plaintext
def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Encryption function (AES CBC)
def encrypt(plaintext, key):
    # Convert the key to 32 bytes using SHA256 (if needed)
    key = hashlib.sha256(key.encode()).digest()  # Adjust key length (32 bytes for AES-256)
    
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    
    # Pad plaintext
    plaintext = pad(plaintext.encode())
    
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(plaintext)
    
    # Return IV and ciphertext (Base64 encoded for readability)
    return base64.b64encode(iv + ciphertext).decode()

# Decryption function (AES CBC)
def decrypt(ciphertext, key):
    # Convert the key to 32 bytes
    key = hashlib.sha256(key.encode()).digest()

    # Decode from Base64
    data = base64.b64decode(ciphertext)
    
    # Extract the IV from the beginning
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the data
    plaintext = unpad(cipher.decrypt(ciphertext))
    
    return plaintext.decode()

# Example usage
key = "your_secret_key_here"
plaintext = "This is a secret message!"

ciphertext = encrypt(plaintext, key)
print(f"Encrypted: {ciphertext}")

decrypted_text = decrypt(ciphertext, key)
print(f"Decrypted: {decrypted_text}")
