from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Générer des clés publique et privée
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def encrypt_rsa(plain_text, public_key):
    encrypted_text = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_text

def decrypt_rsa(encrypted_text, private_key):
    decrypted_text = private_key.decrypt(
        encrypted_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode()

# Exemple d'utilisation
plain_text = "Ceci est un message secret."
encrypted_text = encrypt_rsa(plain_text, public_key)
print("Texte chiffré:", encrypted_text)
decrypted_text = decrypt_rsa(encrypted_text, private_key)
print("Texte déchiffré:", decrypted_text)
