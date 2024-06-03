from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(data):
    # Padding to ensure the data is a multiple of 16 bytes
    pad_length = 16 - len(data) % 16
    return data + chr(pad_length) * pad_length

def unpad(data):
    pad_length = ord(data[-1])
    return data[:-pad_length]

def encrypt_aes_cbc(plaintext, key):
    key = key[:32]  # Ensure the key is 32 bytes (256 bits)
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext).encode('utf-8'))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_aes_cbc(ciphertext, key):
    key = key[:32]  # Ensure the key is 32 bytes (256 bits)
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'))
    return plaintext

# Example usage
key = 'thisisaverysecretkeythatshouldbe32bytes'
plaintext = 'This is a secret message.'

encrypted_text = encrypt_aes_cbc(plaintext, key)
print(f'Encrypted (CBC): {encrypted_text}')

decrypted_text = decrypt_aes_cbc(encrypted_text, key)
print(f'Decrypted (CBC): {decrypted_text}')
