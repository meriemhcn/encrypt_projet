from Crypto.Cipher import AES
import base64

def pad(data):
    # Padding to ensure the data is a multiple of 16 bytes
    pad_length = 16 - len(data) % 16
    return data + chr(pad_length) * pad_length

def unpad(data):
    pad_length = ord(data[-1])
    return data[:-pad_length]

def encrypt_aes_ecb(plaintext, key):
    key = key[:32]  # Ensure the key is 32 bytes (256 bits)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext).encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_ecb(ciphertext, key):
    key = key[:32]  # Ensure the key is 32 bytes (256 bits)
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'))
    return plaintext

# Example usage
key = 'thisisaverysecretkeythatshouldbe32bytes'
plaintext = 'This is a secret message.'

encrypted_text = encrypt_aes_ecb(plaintext, key)
print(f'Encrypted (ECB): {encrypted_text}')

decrypted_text = decrypt_aes_ecb(encrypted_text, key)
print(f'Decrypted (ECB): {decrypted_text}')
