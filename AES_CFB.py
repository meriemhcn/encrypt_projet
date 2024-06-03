from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Fonction pour chiffrer un texte en utilisant AES
def encrypt_aes(plain_text, key):
    # Générer un vecteur d'initialisation (IV) aléatoire
    iv = os.urandom(16)
    # Créer un objet Cipher avec l'algorithme AES en mode CFB
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Chiffrer le texte en clair
    encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    # Retourner le texte chiffré avec l'IV préfixé
    return iv + encrypted_text

# Fonction pour déchiffrer un texte chiffré en utilisant AES
def decrypt_aes(encrypted_text, key):
    # Extraire l'IV du texte chiffré
    iv = encrypted_text[:16]
    # Créer un objet Cipher avec l'algorithme AES en mode CFB
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Déchiffrer le texte chiffré
    decrypted_text = decryptor.update(encrypted_text[16:]) + decryptor.finalize()
    # Retourner le texte déchiffré
    return decrypted_text.decode()

# Exemple d'utilisation
key = os.urandom(32)  # Générer une clé AES de 256 bits
plain_text = "Meriem"
# Chiffrer le texte en clair
encrypted_text = encrypt_aes(plain_text, key)
print("Texte chiffré:", encrypted_text)
# Déchiffrer le texte chiffré
decrypted_text = decrypt_aes(encrypted_text, key)
print("Texte déchiffré:", decrypted_text)
