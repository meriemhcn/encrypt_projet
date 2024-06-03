from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

# Fonction pour chiffrer un texte en utilisant DES
def encrypt_des(plain_text, key):
    # Créer un objet DES en mode ECB
    cipher = DES.new(key, DES.MODE_ECB)
    # Ajouter du padding au texte en clair pour qu'il soit un multiple de 8 octets
    padded_text = pad(plain_text.encode(), DES.block_size)
    # Chiffrer le texte en clair
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text

# Fonction pour déchiffrer un texte chiffré en utilisant DES
def decrypt_des(encrypted_text, key):
    # Créer un objet DES en mode ECB
    cipher = DES.new(key, DES.MODE_ECB)
    # Déchiffrer le texte chiffré
    decrypted_padded_text = cipher.decrypt(encrypted_text)
    # Retirer le padding pour obtenir le texte en clair original
    decrypted_text = unpad(decrypted_padded_text, DES.block_size)
    return decrypted_text.decode()

# Exemple d'utilisation
key = os.urandom(8)  # Générer une clé DES de 8 octets (64 bits)
plain_text = "Ceci est un message secret."
# Chiffrer le texte en clair
encrypted_text = encrypt_des(plain_text, key)
print("Texte chiffré:", encrypted_text)
# Déchiffrer le texte chiffré
decrypted_text = decrypt_des(encrypted_text, key)
print("Texte déchiffré:", decrypted_text)
