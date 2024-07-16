from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
import os

# AES encryption and decryption
def aes_encrypt(data, key, iv):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Key generation and management
def generate_aes_key():
    return os.urandom(32)  # AES-256 key

def generate_iv():
    return os.urandom(16)  # 16 bytes IV for AES

def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()

# Example usage
if __name__ == "__main__":
    # Read the image file
    with open('example_image.jpg', 'rb') as image_file:
        image_data = image_file.read()

    # Generate key and IV
    aes_key = generate_aes_key()
    iv = generate_iv()

    # Encrypt the image
    encrypted_image = aes_encrypt(image_data, aes_key, iv)

    # Save the encrypted image
    with open('encrypted_image.enc', 'wb') as enc_file:
        enc_file.write(iv + encrypted_image)

    # Save the key
    save_key(aes_key, 'aes_key.key')

    # Decrypt the image
    loaded_key = load_key('aes_key.key')
    with open('encrypted_image.enc', 'rb') as enc_file:
        iv = enc_file.read(16)
        encrypted_image = enc_file.read()

    decrypted_image = aes_decrypt(encrypted_image, loaded_key, iv)

    # Save the decrypted image
    with open('decrypted_image.jpg', 'wb') as dec_file:
        dec_file.write(decrypted_image)

    print("Encryption and decryption completed successfully.")
