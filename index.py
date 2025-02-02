import hashlib
import bcrypt
import os
import subprocess
import random
import string
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.context import CryptContext

# Password Hashing (Using hashlib & bcrypt)
def hash_password_hashlib(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password_bcrypt(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

# Brute Force Attack (Basic)
def brute_force_attack(hash_to_crack, wordlist):
    for word in wordlist:
        if hashlib.sha256(word.encode()).hexdigest() == hash_to_crack:
            return word
    return None

# Dictionary Attack (Using wordlist)
def dictionary_attack(hash_to_crack, wordlist_file):
    with open(wordlist_file, 'r') as f:
        for word in f:
            word = word.strip()
            if hashlib.sha256(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

# Brute Force using Hashcat (Requires Hashcat Installed)
def hashcat_brute_force(hash_to_crack, wordlist_file):
    command = ["hashcat", "-m", "0", hash_to_crack, wordlist_file, "--show"]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running Hashcat: {str(e)}"

# Enforcing Strong Password Policy
def enforce_password_policy(password):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)

def password_recommendations():
    return "Use a mix of uppercase, lowercase, numbers, and special characters. Avoid common words."

# AES Encryption
def aes_encrypt(password, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return cipher.nonce + tag + ciphertext

def aes_decrypt(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# RSA Encryption
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(password, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(password.encode())

def rsa_decrypt(encrypted_data, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(encrypted_data).decode()

# Example Usage
if __name__ == "__main__":
    password = "WeakPass123!"
    
    # Hashing Examples
    hash_lib = hash_password_hashlib(password)
    hash_bcrypt = hash_password_bcrypt(password)
    print("SHA256 Hash:", hash_lib)
    print("BCrypt Hash:", hash_bcrypt)
    
    # Brute Force Example
    wordlist = ["password", "123456", "WeakPass123!"]
    cracked_password = brute_force_attack(hash_lib, wordlist)
    print("Cracked Password:", cracked_password)
    
    # AES Encryption Example
    aes_key = get_random_bytes(16)
    encrypted_data = aes_encrypt(password, aes_key)
    decrypted_data = aes_decrypt(encrypted_data, aes_key)
    print("AES Decrypted Password:", decrypted_data)
    
    # RSA Encryption Example
    private_key, public_key = generate_rsa_keys()
    encrypted_rsa = rsa_encrypt(password, public_key)
    decrypted_rsa = rsa_decrypt(encrypted_rsa, private_key)
    print("RSA Decrypted Password:", decrypted_rsa)
    
    # Hashcat Brute Force (if Hashcat is installed)
    wordlist_file = "wordlist.txt"  # Ensure you have a wordlist file
    hashcat_result = hashcat_brute_force(hash_lib, wordlist_file)
    print("Hashcat Brute Force Result:", hashcat_result)
    
    # Password Recommendations
    print("Password Recommendations:", password_recommendations())
