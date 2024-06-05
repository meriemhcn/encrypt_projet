import tkinter as tk
from tkinter import ttk, messagebox, font
from datetime import datetime
from PIL import Image, ImageTk
from Crypto.Cipher import AES,DES
from Crypto.Random import get_random_bytes
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import pyperclip
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA

# Initialiser une variable globale pour stocker le dernier bouton cliqué
dernier_bouton_clique = None

# Fonction appelée lors du clic sur le bouton 1
def bouton1_clique(event):
    global dernier_bouton_clique
    dernier_bouton_clique = 1

# Fonction appelée lors du clic sur le bouton 2
def bouton2_clique(event):
    global dernier_bouton_clique
    dernier_bouton_clique = 2  

# Fonction appelée lors du clic sur le bouton 3
def bouton3_clique(event):
    global dernier_bouton_clique
    dernier_bouton_clique = 3 

# Padding functions
def pad(data, block_size):
    pad_length = block_size - len(data) % block_size
    return data + chr(pad_length)* pad_length


def unpad(data):
    pad_length = ord(data[-1])
    return data[:-pad_length]


# Verify the key length
def verify_aes_key(key):
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Erreur de clé", "La clé doit être de 128, 192, ou 256 bits (16, 24, ou 32 octets).")
        return False
    return True

def verify_des_key(key):
    if len(key) != 8:
       messagebox.showerror("Erreur de clé","La clé doit être de 8 octets (64 bits) pour DES.")
       return False
    return True

# Fonction pour copier la clé publique
def copy_public_key():
    public_key_base64 = RSA_result_gen_pb.cget("text")
    pyperclip.copy(public_key_base64)

# Fonction pour copier la clé privée
def copy_private_key():
    private_key_base64 = RSA_result_gen_pv.cget("text")
    pyperclip.copy(private_key_base64)

def generate_keys():
    """Génère une paire de clés RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def key_to_base64(key, is_private=False):

    if is_private:
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        key_bytes = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return base64.b64encode(key_bytes).decode('utf-8')

def base64_to_private_key(b64_key):
    key_bytes = base64.b64decode(b64_key.encode('utf-8'))
    return serialization.load_der_private_key(key_bytes, password=None, backend=default_backend())

def base64_to_public_key(b64_key):
    key_bytes = base64.b64decode(b64_key.encode('utf-8'))
    return serialization.load_der_public_key(key_bytes, backend=default_backend())

def generateur_key():
    global current_frame
    private_key, public_key = generate_keys()
    private_key_b64 = key_to_base64(private_key, is_private=True)
    public_key_b64 = key_to_base64(public_key)
    RSA_result_gen_pb.config(text=public_key_b64) 
    RSA_result_gen_pv.config(text=private_key_b64) 
    current_frame=RSA_gen_frame 
    return None

def encrypt_rsa(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def RSA_run():
    global current_frame
    try:
        public_key_base64 = RSA_enc_entry2.get().strip()
        public_key = base64_to_public_key(public_key_base64)
    except Exception as e:
        messagebox.showerror("Invalid Key", f"Failed to load public key: {str(e)}")
        return None
    
    public_key = base64_to_public_key(public_key_base64)
    
    plaintext = RSA_enc_entry.get().strip().encode()
    encrypted_text = encrypt_rsa(plaintext, public_key)
    
    if encrypted_text:
        RSA_enc_frame.place_forget()
        result2_label_RSA.config(text=encrypted_text.hex(), fg=ACCENT_COLOR)
        result_frame_RSA.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = result_frame_RSA
        encrypted_hex = encrypted_text.hex()
        pyperclip.copy(encrypted_hex)

    return None

def RSA_run_dec():
    global current_frame
    try:
        private_key_base64 = RSA_dec_entry2.get().strip()
        private_key = base64_to_private_key(private_key_base64)
    except Exception as e:
        messagebox.showerror("Invalid Key", f"Failed to load public key: {str(e)}")
        return None
    
    
    ciphertext_hex = RSA_dec_entry.get().strip()
    encrypted_text = bytes.fromhex(ciphertext_hex)
    decrypted_text = decrypt_rsa(encrypted_text, private_key)
    
    if decrypted_text:
        RSA_dec_frame.place_forget()
        result2_label_RSA_dec.config(text=decrypted_text.decode(), fg=ACCENT_COLOR)
        result_frame_RSA_dec.place(relx=0.5, rely=0.5, anchor='center')
        current_frame = result_frame_RSA_dec
    return None

def encrypt_aes(plaintext, key):
    if not verify_aes_key(key):
        return None
    iv = os.urandom(16)
    key_bytes = key.encode('utf-8')
    print(dernier_bouton_clique)
    if dernier_bouton_clique==1:
       cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
       ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
       return base64.b64encode(iv + ciphertext).decode('utf-8')
    elif dernier_bouton_clique==2:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_text).decode('utf-8')
    elif dernier_bouton_clique==3:
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    
def decrypt_aes(ciphertext, key):
    key_bytes = key.encode('utf-8')  
    if not verify_aes_key(key_bytes):
        return None
    if dernier_bouton_clique==1:
       ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
       iv = ciphertext[:16]
       ciphertext = ciphertext[16:]
       cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
       plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'))
       return plaintext
    elif dernier_bouton_clique==2:
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text.decode('utf-8')
    elif dernier_bouton_clique==3:
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'))
        return plaintext


def  AES_run():
    global current_frame
    key = AES_enc_entry2.get().strip()
    plaintext = AES_enc_entry.get().strip()
    encrypted_text = encrypt_aes(plaintext, key)
    if encrypted_text:
      AES_enc_frame.place_forget()
      result2_label_AES.config(text=encrypted_text, fg=ACCENT_COLOR)  
      result_frame_AES.place(relx=0.5, rely=0.5, anchor='center')
      current_frame=result_frame_AES
      pyperclip.copy(encrypted_text)
    return None

def AES_run_dec():
    global current_frame
    key = AES_dec_entry2.get().strip()
    plaintext = AES_dec_entry.get().strip()
    decrypted_text = decrypt_aes(plaintext, key)
    if decrypted_text:
      AES_dec_frame.place_forget()
      result2_label_AES_dec.config(text=decrypted_text, fg=ACCENT_COLOR)  
      result_frame_AES_dec.place(relx=0.5, rely=0.5, anchor='center')
      current_frame=result_frame_AES_dec
      pyperclip.copy(decrypted_text)
    return None

def encrypt_des(plaintext, key):
    if not verify_des_key(key):
        messagebox.showerror("Erreur", "La clé doit être de 8 caractères.")
        return None
    
    key_bytes = key.encode('utf-8')
    iv = os.urandom(8)
    
    if dernier_bouton_clique == 1:
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    elif dernier_bouton_clique == 2:
        cipher = DES.new(key_bytes, DES.MODE_CFB, iv)
    elif dernier_bouton_clique == 3:
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        iv = b''  # Pas d'IV pour ECB

    padded_plaintext = pad(plaintext, DES.block_size)
    ciphertext_bytes = cipher.encrypt(padded_plaintext.encode('utf-8'))
    ciphertext = base64.b64encode(iv + ciphertext_bytes).decode('utf-8')
    
    return ciphertext

# Fonction de déchiffrement DES CBC
def decrypt_des(ciphertext, key):
    key_bytes = key.encode('utf-8')
    if not verify_des_key(key_bytes):
        return None

    ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))

    if dernier_bouton_clique == 1:  # Mode CBC
        iv = ciphertext_bytes[:8]
        ciphertext_bytes = ciphertext_bytes[8:]
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext_bytes).decode('utf-8'))
        return plaintext
    elif dernier_bouton_clique == 2:  # Mode CFB
        iv = ciphertext_bytes[:8]
        ciphertext_bytes = ciphertext_bytes[8:]
        cipher = DES.new(key_bytes, DES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext_bytes)
        return plaintext.decode('utf-8')
    elif dernier_bouton_clique == 3:  # Mode ECB
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext_bytes).decode('utf-8'))
        return plaintext

def DES_run():
    global current_frame
    key = DES_enc_entry2.get().strip()
    plaintext = DES_enc_entry.get().strip()
    encrypted_text = encrypt_des(plaintext, key)
    if encrypted_text:
      DES_enc_frame.place_forget()
      result2_label_DES.config(text=encrypted_text, fg=ACCENT_COLOR)  
      result_frame_DES.place(relx=0.5, rely=0.5, anchor='center')
      current_frame=result_frame_DES
      pyperclip.copy(encrypted_text)

    return None

def DES_run_dec():
    global current_frame
    key = DES_dec_entry2.get().strip()
    plaintext = DES_dec_entry.get().strip()
    decrypted_text = decrypt_des(plaintext, key)
    if decrypted_text:
      DES_dec_frame.place_forget()
      result2_label_DES_dec.config(text=decrypted_text, fg=ACCENT_COLOR)  
      result_frame_DES_dec.place(relx=0.5, rely=0.5, anchor='center')
      current_frame=result_frame_DES_dec
    return None

# Couleurs
BG_COLOR = "#051726"
FG_COLOR = "#051726"
LB_COLOR="#2ede93"
ACCENT_COLOR = "#7EFAD5"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#95a3b3"  # Couleur des boutons
BUTTON_ACTIVE_COLOR = "#bc4749"  # Couleur des boutons lorsqu'ils sont actifs

# Police de caractères
FONT_FAMILY = "Verdana"
FONT_SIZE = 14

current_frame=None

def toggle_frames(hide_frame, show_frame):
    global current_frame
    
    hide_frame.place_forget()
    show_frame.place(relx=0.5, rely=0.5, anchor='center')
    current_frame=show_frame
    toggle_back_button(True)

# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time

# Fonction pour afficher/cacher le bouton "Retour"
def toggle_back_button(show):
    if show:
        back_button.place(relx=0, rely=0, anchor='nw')
    else:
        back_button.place_forget()

def return_to_previous_screen():
    global current_frame
    if current_frame==first_frame:
        first_frame.place_forget()
        zero_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=zero_frame
        toggle_back_button(False)
    elif current_frame == crypt_meth_frame:
        crypt_meth_frame.place_forget()
        first_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=first_frame
    elif current_frame == decrypt_meth_frame:
        decrypt_meth_frame.place_forget()
        first_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=first_frame
    elif current_frame == AES_enc_frame:
        AES_enc_entry.delete(0, 'end')
        AES_enc_entry2.delete(0, 'end')
        AES_enc_frame.place_forget()
        AES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame
    elif current_frame == DES_enc_frame:
        DES_enc_entry.delete(0, 'end')
        DES_enc_entry2.delete(0, 'end')
        DES_enc_frame.place_forget()
        DES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame
    elif current_frame == RSA_enc_frame:
        RSA_enc_entry.delete(0, 'end')
        RSA_enc_entry2.delete(0, 'end')
        RSA_enc_frame.place_forget()
        crypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=crypt_meth_frame
    elif current_frame==AES_mode_frame:
        AES_mode_frame.place_forget()
        crypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=crypt_meth_frame
    elif current_frame==DES_mode_frame:
        DES_mode_frame.place_forget()
        crypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=crypt_meth_frame
    elif current_frame == AES_dec_frame:
        AES_dec_entry.delete(0, 'end')
        AES_dec_entry2.delete(0, 'end')
        AES_dec_frame.place_forget()
        AES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame_dec
    elif current_frame == DES_dec_frame:
        DES_dec_entry.delete(0, 'end')
        DES_dec_entry2.delete(0, 'end')
        DES_dec_frame.place_forget()
        DES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame_dec
    elif current_frame == RSA_dec_frame:
        RSA_dec_entry.delete(0, 'end')
        RSA_dec_entry2.delete(0, 'end')
        RSA_dec_frame.place_forget()
        decrypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=decrypt_meth_frame
    elif current_frame==AES_mode_frame_dec:
        AES_mode_frame_dec.place_forget()
        decrypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=decrypt_meth_frame
    elif current_frame==DES_mode_frame_dec:
        DES_mode_frame_dec.place_forget()
        decrypt_meth_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=decrypt_meth_frame
    elif current_frame== result_frame_DES:
        result_frame_DES.place_forget()
        DES_enc_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_enc_frame
    elif current_frame== result_frame_AES:
        result_frame_AES.place_forget()
        AES_enc_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_enc_frame
    elif current_frame== result_frame_AES_dec:
        result_frame_AES_dec.place_forget()
        AES_dec_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_dec_frame
    elif current_frame== result_frame_DES_dec:
        result_frame_DES_dec.place_forget()
        DES_dec_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_dec_frame
    elif current_frame== result_frame_RSA:
        result_frame_RSA.place_forget()
        RSA_enc_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=RSA_enc_frame
    elif current_frame== result_frame_RSA_dec:
        result_frame_RSA_dec.place_forget()
        RSA_dec_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=RSA_dec_frame
    elif current_frame==RSA_gen_frame:
        RSA_gen_frame.place_forget()
        RSA_enc_frame.place(relx=0.5,rely=0.5,anchor='center')
        RSA_result_gen_pv.config(text="")
        RSA_result_gen_pb.config(text="")
        current_frame=RSA_enc_frame
    elif current_frame == zero_frame:
      pass


# Configuration de la fenêtre principale
window_width=700
window_height=600

root = tk.Tk()
root.title("Cryptography")
root.configure(bg=BG_COLOR)
root.config(highlightbackground="#00f5d4", highlightcolor="#00f5d4", highlightthickness=1)
#root.geometry('550x500')  # Définir la taille de la fenêtre
# Centre the window relative to the dimensions of the screen 
root.geometry('{0:d}x{1}+{2}+{3}'.format(window_width, window_height, root.winfo_screenwidth() // 2 - window_width // 2, root.winfo_screenheight() // 2 - window_height // 2))
# Ajout d'une marge à côté des bordures
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
main_frame = tk.Frame(root, bg=BG_COLOR)
main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

custom_font = font.Font(family=FONT_FAMILY, size=FONT_SIZE)

# Bouton "Retour" en bas à gauche
back_button = tk.Button(main_frame, text="←", command=return_to_previous_screen, fg=FG_COLOR, bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR)
root.bind("<Escape>", lambda event: back_button.invoke())
back_button.place(relx=0, rely=0, anchor='nw')

zero_frame =tk.Frame(main_frame,bg=BG_COLOR)
zero_frame.place(relx=0.5,rely=0.5,anchor='center')

# Texte du paragraphe
texte_paragraphe = """La plateforme permet de sécuriser vos messages en ligne en les chiffrant avec des algorithmes robustes tels que AES, DES et RSA. Elle offre une interface conviviale pour un chiffrement rapide et un déchiffrement facile, garantissant la confidentialité de vos communications professionnelles et personnelles."""

# Créer un widget Label pour afficher le paragraphe
#label_paragraphe = tk.Label(zero_frame, text=texte_paragraphe, justify="center", wraplength=500,bg=BG_COLOR,font=custom_font)
#label_paragraphe.grid(row=0, column=0, pady=(0, 100)) 
image_path = "Frame3.png"
image = Image.open(image_path)
image = image.resize((300, 300), Image.LANCZOS)  # Redimensionner l'image si nécessaire
photo = ImageTk.PhotoImage(image)

# Ajouter l'image à un Label
image_label = tk.Label(zero_frame, image=photo, bg=BG_COLOR)
image_label.grid(row=0, column=0, pady=(0, 70))   # Ajouter un espacement vertical autour de l'image

bienvenue = tk.Button(zero_frame, text=" BIENVENUE ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(zero_frame,first_frame))
bienvenue.grid(row=0, column=0, pady=(140,0)) 

# Boutons dans la nouvelle frame
first_frame=tk.Frame(main_frame,bg=BG_COLOR)
first_frame.place(relx=0.5,rely=0.5,anchor='center')
first_frame.place_forget()
toggle_back_button(False)

# Créer les boutons Encrypt et Decrypt
button_encrypt = tk.Button(first_frame, text="Encrypt Text",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(first_frame,crypt_meth_frame))
button_encrypt.pack(pady=10)

button_decrypt = tk.Button(first_frame, text="Decrypt Text",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(first_frame,decrypt_meth_frame))
button_decrypt.pack(pady=10)

crypt_meth_frame=tk.Frame(main_frame,bg=BG_COLOR)
crypt_meth_frame.place_forget()

text_label=tk.Label(crypt_meth_frame, text="Choisissez l'algorithme de cryptage :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
text_label.pack(pady=10)
AES_button = tk.Button(crypt_meth_frame, text=" AES ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(crypt_meth_frame,AES_mode_frame))
AES_button.pack(pady=10)
DES_button = tk.Button(crypt_meth_frame, text=" DES ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(crypt_meth_frame,DES_mode_frame))
DES_button.pack(pady=10)
RSA_button = tk.Button(crypt_meth_frame, text=" RSA ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(crypt_meth_frame,RSA_enc_frame))
RSA_button.pack(pady=10)

AES_mode_frame=tk.Frame(main_frame,bg=BG_COLOR)
mode_label_AES=tk.Label(AES_mode_frame, text="Choisissez le mode de fonctionnement :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
mode_label_AES.pack(pady=10)
CBC_button_AES=tk.Button(AES_mode_frame, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_enc_frame))
CBC_button_AES.pack(pady=10)
CBC_button_AES.bind("<Button-1>",bouton1_clique)
CFB_button_AES=tk.Button(AES_mode_frame, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_enc_frame))
CFB_button_AES.pack(pady=10)
CFB_button_AES.bind("<Button-1>",bouton2_clique)
ECB_button_AES=tk.Button(AES_mode_frame, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_enc_frame))
ECB_button_AES.pack(pady=10)
ECB_button_AES.bind("<Button-1>",bouton3_clique)

DES_mode_frame=tk.Frame(main_frame,bg=BG_COLOR)
mode_label_DES=tk.Label(DES_mode_frame, text="Choisissez le mode de fonctionnement :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
mode_label_DES.pack(pady=10)
CBC_button_DES=tk.Button(DES_mode_frame, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame,DES_enc_frame))
CBC_button_DES.pack(pady=10)
CBC_button_DES.bind("<Button-1>",bouton1_clique)
CFB_button_DES=tk.Button(DES_mode_frame, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame,DES_enc_frame))
CFB_button_DES.pack(pady=10)
CFB_button_DES.bind("<Button-1>",bouton2_clique)
ECB_button_DES=tk.Button(DES_mode_frame, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame,DES_enc_frame))
ECB_button_DES.pack(pady=10)
ECB_button_DES.bind("<Button-1>",bouton3_clique)

bold_font = (FONT_FAMILY, 15, "bold")


AES_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_enc_label= tk.Label(AES_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_enc_label.pack(pady=10)
AES_enc_label2= tk.Label(AES_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_enc_label2.pack(pady=10)
AES_enc_entry= tk.Entry(AES_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_enc_entry.pack(pady=10)
AES_enc_label3= tk.Label(AES_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_enc_label3.pack(pady=10)
AES_enc_entry2= tk.Entry(AES_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_enc_entry2.pack(pady=10)
AES_enc_button = tk.Button(AES_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command= AES_run)
AES_enc_button.pack(pady=10)


# Frame pour afficher le résultat 
result_frame_AES = tk.Frame(main_frame, bg=BG_COLOR)
result_label_AES = tk.Label(result_frame_AES,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_AES.pack(pady=10)
result2_label_AES= tk.Label(result_frame_AES, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_AES.pack(pady=10)


DES_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_enc_label= tk.Label(DES_enc_frame, text="DES (Data Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_enc_label.pack(pady=10)
DES_enc_label2= tk.Label(DES_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_enc_label2.pack(pady=10)
DES_enc_entry= tk.Entry(DES_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_enc_entry.pack(pady=10)
DES_enc_label3= tk.Label(DES_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_enc_label3.pack(pady=10)
DES_enc_entry2= tk.Entry(DES_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_enc_entry2.pack(pady=10)
DES_enc_button = tk.Button(DES_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=DES_run)
DES_enc_button.pack(pady=10)


# Frame pour afficher le résultat 
result_frame_DES = tk.Frame(main_frame, bg=BG_COLOR)
result_label_DES = tk.Label(result_frame_DES,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_DES.pack(pady=10)
result2_label_DES= tk.Label(result_frame_DES, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_DES.pack(pady=10)


RSA_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
RSA_enc_label= tk.Label(RSA_enc_frame, text="RSA (Rivest–Shamir–Adleman)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
RSA_enc_label.pack(pady=10)
RSA_enc_label2= tk.Label(RSA_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_enc_label2.pack(pady=10)
RSA_enc_entry= tk.Entry(RSA_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
RSA_enc_entry.pack(pady=10)
RSA_enc_label3= tk.Label(RSA_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_enc_label3.pack(pady=10)
RSA_enc_entry2= tk.Entry(RSA_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
RSA_enc_entry2.pack(pady=10)
RSA_enc_button = tk.Button(RSA_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=RSA_run)
RSA_enc_button.pack(pady=10)
RSA_gen_enc_button = tk.Button(RSA_enc_frame, text=" Générateur de clé ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda:toggle_frames(RSA_enc_frame,RSA_gen_frame))
RSA_gen_enc_button.pack(pady=10)

RSA_gen_frame = tk.Frame(main_frame,bg=BG_COLOR)
RSA_gen_label_pb= tk.Label(RSA_gen_frame, text="Clé public", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_gen_label_pb.pack(pady=10)
RSA_result_gen_pb= tk.Label(RSA_gen_frame, bg=BG_COLOR, font=("Courier", 6), fg=ACCENT_COLOR,wraplength=500)
RSA_result_gen_pb.pack(pady=20)
# Assurez-vous d'avoir des boutons dans votre interface pour appeler ces fonctions
copy_public_key_button = tk.Button(RSA_gen_frame, text="Copier",fg=LB_COLOR,bg=BG_COLOR, font=("Courier", 10), activeforeground=ACCENT_COLOR, command=copy_public_key)
copy_public_key_button.pack(pady=10)

RSA_gen_label_pv= tk.Label(RSA_gen_frame, text="Clé privé", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_gen_label_pv.pack(pady=10)
RSA_result_gen_pv= tk.Label(RSA_gen_frame, bg=BG_COLOR, font=("Courier", 6), fg=ACCENT_COLOR,wraplength=500)
RSA_result_gen_pv.pack(pady=20)
copy_private_key_button = tk.Button(RSA_gen_frame, text="Copier",fg=LB_COLOR,bg=BG_COLOR, font=("Courier", 10), activeforeground=ACCENT_COLOR, command=copy_private_key)
copy_private_key_button.pack(pady=10)
RSA_gen_button = tk.Button(RSA_gen_frame, text=" Générer ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=generateur_key)
RSA_gen_button.pack(pady=10)


# Frame pour afficher le résultat 
result_frame_RSA = tk.Frame(main_frame, bg=BG_COLOR)
result_label_RSA = tk.Label(result_frame_RSA,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_RSA.pack(pady=10)
result2_label_RSA= tk.Label(result_frame_RSA, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR,wraplength=500)
result2_label_RSA.pack(pady=10)

decrypt_meth_frame=tk.Frame(main_frame,bg=BG_COLOR)
decrypt_meth_frame.place_forget()

text_label_dec=tk.Label(decrypt_meth_frame, text="Choisissez l'algorithme de decryptage :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
text_label_dec.pack(pady=10)
AES_button_dec = tk.Button(decrypt_meth_frame, text=" AES ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(decrypt_meth_frame,AES_mode_frame_dec))
AES_button_dec.pack(pady=10)
DES_button_dec = tk.Button(decrypt_meth_frame, text=" DES ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(decrypt_meth_frame,DES_mode_frame_dec))
DES_button_dec.pack(pady=10)
RSA_button_dec = tk.Button(decrypt_meth_frame, text=" RSA ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(decrypt_meth_frame,RSA_dec_frame))
RSA_button_dec.pack(pady=10)


AES_mode_frame_dec=tk.Frame(main_frame,bg=BG_COLOR)
mode_label_AES_dec=tk.Label(AES_mode_frame_dec, text="Choisissez le mode de fonctionnement :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
mode_label_AES_dec.pack(pady=10)
CBC_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_dec_frame))
CBC_button_AES_dec.pack(pady=10)
CBC_button_AES_dec.bind("<Button-1>",bouton1_clique)
CFB_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_dec_frame))
CFB_button_AES_dec.pack(pady=10)
CFB_button_AES_dec.bind("<Button-1>",bouton2_clique)
ECB_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_dec_frame))
ECB_button_AES_dec.pack(pady=10)
ECB_button_AES_dec.bind("<Button-1>",bouton3_clique)

DES_mode_frame_dec=tk.Frame(main_frame,bg=BG_COLOR)
mode_label_DES_dec=tk.Label(DES_mode_frame_dec, text="Choisissez le mode de fonctionnement :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
mode_label_DES_dec.pack(pady=10)
CBC_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_dec_frame))
CBC_button_DES_dec.pack(pady=10)
CBC_button_DES_dec.bind("<Button-1>",bouton1_clique)
CFB_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_dec_frame))
CFB_button_DES_dec.pack(pady=10)
CFB_button_DES_dec.bind("<Button-1>",bouton2_clique)
ECB_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_dec_frame))
ECB_button_DES_dec.pack(pady=10)
ECB_button_DES_dec.bind("<Button-1>",bouton3_clique)

bold_font = (FONT_FAMILY, 15, "bold")

AES_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_dec_label= tk.Label(AES_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_dec_label.pack(pady=10)
AES_dec_label2= tk.Label(AES_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_dec_label2.pack(pady=10)
AES_dec_entry= tk.Entry(AES_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_dec_entry.pack(pady=10)
AES_dec_label3= tk.Label(AES_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_dec_label3.pack(pady=10)
AES_dec_entry2= tk.Entry(AES_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_dec_entry2.pack(pady=10)
AES_dec_button = tk.Button(AES_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=AES_run_dec)
AES_dec_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_AES_dec = tk.Frame(main_frame, bg=BG_COLOR)
result_label_AES_dec = tk.Label(result_frame_AES_dec,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_AES_dec.pack(pady=10)
result2_label_AES_dec= tk.Label(result_frame_AES_dec, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_AES_dec.pack(pady=10)


DES_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_dec_label= tk.Label(DES_dec_frame, text="DES (Data Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_dec_label.pack(pady=10)
DES_dec_label2= tk.Label(DES_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_dec_label2.pack(pady=10)
DES_dec_entry= tk.Entry(DES_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_dec_entry.pack(pady=10)
DES_dec_label3= tk.Label(DES_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_dec_label3.pack(pady=10)
DES_dec_entry2= tk.Entry(DES_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_dec_entry2.pack(pady=10)
DES_dec_button = tk.Button(DES_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=DES_run_dec)
DES_dec_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_DES_dec = tk.Frame(main_frame, bg=BG_COLOR)
result_label_DES_dec = tk.Label(result_frame_DES_dec,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_DES_dec.pack(pady=10)
result2_label_DES_dec= tk.Label(result_frame_DES_dec, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_DES_dec.pack(pady=10)

RSA_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
RSA_dec_label= tk.Label(RSA_dec_frame, text="RSA (Rivest–Shamir–Adleman)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
RSA_dec_label.pack(pady=10)
RSA_dec_label2= tk.Label(RSA_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_dec_label2.pack(pady=10)
RSA_dec_entry= tk.Entry(RSA_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
RSA_dec_entry.pack(pady=10)
RSA_dec_label3= tk.Label(RSA_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
RSA_dec_label3.pack(pady=10)
RSA_dec_entry2= tk.Entry(RSA_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
RSA_dec_entry2.pack(pady=10)
RSA_dec_button = tk.Button(RSA_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=RSA_run_dec)
RSA_dec_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_RSA_dec = tk.Frame(main_frame, bg=BG_COLOR)
result_label_RSA_dec = tk.Label(result_frame_RSA_dec,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_RSA_dec.pack(pady=10)
result2_label_RSA_dec= tk.Label(result_frame_RSA_dec, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_RSA_dec.pack(pady=10)

date_label = tk.Label(main_frame, text=get_current_datetime(), fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')

# Lancer la boucle principale de l'application
root.mainloop()