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
    return data + chr(pad_length) * pad_length

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


# Encrypt function with AES CBC mode
def encrypt_aes_cbc(plaintext, key):
    if not verify_aes_key(key):
        return None
    iv = os.urandom(16)
    key_bytes = key.encode('utf-8')  # Convertir la clé en bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Decrypt function with AES CBC mode
def decrypt_aes_cbc(ciphertext, key):
    key_bytes = key.encode('utf-8')  # Convertir la clé en bytes
    if not verify_aes_key(key_bytes):
        return None
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'),AES.block_size)
    return plaintext

def AES_CBC_run():
    key = AES_CBC_enc_entry2.get().strip()
    plaintext = AES_CBC_enc_entry.get().strip()
    encrypted_text = encrypt_aes_cbc(plaintext, key)
    if encrypted_text:
      AES_CBC_enc_frame.place_forget()
      result2_label_AES_CBC.config(text=encrypted_text, fg=ACCENT_COLOR)  
      result_frame_AES_CBC.place(relx=0.5, rely=0.5, anchor='center')

    return None

# Fonction pour chiffrer un texte en utilisant AES
def encrypt_aes_cfb(plain_text, key):
    if not verify_aes_key(key):
        return None
    iv = os.urandom(16)
    key_bytes = key.encode('utf-8')
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return iv + encrypted_text

# Fonction pour déchiffrer un texte chiffré en utilisant AES
def decrypt_aes_cfb(encrypted_text, key):
    key_bytes = key.encode('utf-8')  # Convertir la clé en bytes
    if not verify_aes_key(key_bytes):
        return None
    # Extraire l'IV du texte chiffré
    iv = encrypted_text[:16]
    # Créer un objet Cipher avec l'algorithme AES en mode CFB
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Déchiffrer le texte chiffré
    decrypted_text = decryptor.update(encrypted_text[16:]) + decryptor.finalize()
    # Retourner le texte déchiffré
    return decrypted_text.decode()

def AES_CFB_run():
    key = AES_CFB_enc_entry2.get().strip()
    plaintext = AES_CFB_enc_entry.get().strip()
    encrypted_text = encrypt_aes_cfb(plaintext, key)
    if encrypted_text:
      AES_CFB_enc_frame.place_forget()
      result2_label_AES_CFB.config(text=encrypted_text, fg=ACCENT_COLOR)  
      result_frame_AES_CFB.place(relx=0.5, rely=0.5, anchor='center')
    return None

def encrypt_aes_ecb(plaintext, key):
    if not verify_aes_key(key):
       return None
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes_ecb(ciphertext, key):
    if not verify_aes_key(key):
       return None
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'),AES.block_size)
    return plaintext

def encrypt_aes(plaintext, key):
    if not verify_aes_key(key):
        return None
    iv = os.urandom(16)
    key_bytes = key.encode('utf-8')
    if dernier_bouton_clique==1:
       cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
       ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
       return base64.b64encode(iv + ciphertext).decode('utf-8')
    elif dernier_bouton_clique==2:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return iv + encrypted_text
    elif dernier_bouton_clique==3:
        cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext,AES.block_size).encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')

def  AES_run():
    key = AES_ECB_enc_entry2.get().strip()
    plaintext = AES_ECB_enc_entry.get().strip()
    encrypted_text = encrypt_aes_cfb(plaintext, key)
    if encrypted_text:
      AES_ECB_enc_frame.place_forget()
      result2_label_AES_ECB.config(text=encrypted_text, fg=ACCENT_COLOR)  
      result_frame_AES_ECB.place(relx=0.5, rely=0.5, anchor='center')
    return None

def encrypt_des(plaintext, key):
    if not verify_des_key(key):
        return None
    iv = os.urandom(8)
    if dernier_bouton_clique==1:
       cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    elif dernier_bouton_clique==2:
        cipher = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv)
    elif dernier_bouton_clique==3:
        cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size).encode('utf-8'))
    return ciphertext

# Fonction de déchiffrement DES CBC
def decrypt_des(ciphertext, key):
    if not verify_des_key(key):
        return None
    iv = ciphertext[:8]
    if dernier_bouton_clique==1:
       cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    elif dernier_bouton_clique==2:
        cipher = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv)
    elif dernier_bouton_clique==3:
        cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext).decode('utf-8'), DES.block_size)
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
    elif current_frame == AES_CBC_enc_frame:
        AES_CBC_enc_frame.place_forget()
        AES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame
    elif current_frame == AES_CFB_enc_frame:
        AES_CFB_enc_frame.place_forget()
        AES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame
    elif current_frame == AES_ECB_enc_frame:
        AES_ECB_enc_frame.place_forget()
        AES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame
    elif current_frame == DES_enc_frame:
        DES_enc_frame.place_forget()
        DES_mode_frame.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame
    elif current_frame == RSA_enc_frame:
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
    elif current_frame == AES_CBC_dec_frame:
        AES_CBC_dec_frame.place_forget()
        AES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame_dec
    elif current_frame == AES_CFB_dec_frame:
        AES_CFB_dec_frame.place_forget()
        AES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame_dec
    elif current_frame == AES_ECB_dec_frame:
        AES_ECB_dec_frame.place_forget()
        AES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=AES_mode_frame_dec
    elif current_frame == DES_CBC_dec_frame:
        DES_CBC_dec_frame.place_forget()
        DES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame_dec
    elif current_frame == DES_CFB_dec_frame:
        DES_CFB_dec_frame.place_forget()
        DES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame_dec
    elif current_frame == DES_ECB_dec_frame:
        DES_ECB_dec_frame.place_forget()
        DES_mode_frame_dec.place(relx=0.5,rely=0.5,anchor='center')
        current_frame=DES_mode_frame_dec
    elif current_frame == RSA_dec_frame:
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
    elif current_frame == zero_frame:
      pass


# Configuration de la fenêtre principale
window_width=600
window_height=500

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
CBC_button_AES=tk.Button(AES_mode_frame, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_CBC_enc_frame))
CBC_button_AES.pack(pady=10)
CBC_button_AES.bind("<Button-1>",bouton1_clique)
CFB_button_AES=tk.Button(AES_mode_frame, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_CBC_enc_frame))
CFB_button_AES.pack(pady=10)
CFB_button_AES.bind("<Button-1>",bouton2_clique)
ECB_button_AES=tk.Button(AES_mode_frame, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame,AES_CBC_enc_frame))
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

AES_CBC_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_CBC_enc_label= tk.Label(AES_CBC_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_CBC_enc_label.pack(pady=10)
AES_CBC_enc_label2= tk.Label(AES_CBC_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_enc_label2.pack(pady=10)
AES_CBC_enc_entry= tk.Entry(AES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_enc_entry.pack(pady=10)
AES_CBC_enc_label3= tk.Label(AES_CBC_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_enc_label3.pack(pady=10)
AES_CBC_enc_entry2= tk.Entry(AES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_enc_entry2.pack(pady=10)
'''AES_CBC_enc_label4= tk.Label(AES_CBC_enc_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_enc_label4.pack(pady=10)
AES_CBC_enc_entry3= tk.Entry(AES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_enc_entry3.pack(pady=10)'''
AES_CBC_enc_button = tk.Button(AES_CBC_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command= AES_run)
AES_CBC_enc_button.pack(pady=10)


# Frame pour afficher le résultat 
result_frame_AES_CBC = tk.Frame(main_frame, bg=BG_COLOR)
result_label_AES_CBC = tk.Label(result_frame_AES_CBC,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_AES_CBC.pack(pady=10)
result2_label_AES_CBC= tk.Label(result_frame_AES_CBC, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_AES_CBC.pack(pady=10)

AES_CFB_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_CFB_enc_label= tk.Label(AES_CFB_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_CFB_enc_label.pack(pady=10)
AES_CFB_enc_label2= tk.Label(AES_CFB_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_enc_label2.pack(pady=10)
AES_CFB_enc_entry= tk.Entry(AES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_enc_entry.pack(pady=10)
AES_CFB_enc_label3= tk.Label(AES_CFB_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_enc_label3.pack(pady=10)
AES_CFB_enc_entry2= tk.Entry(AES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_enc_entry2.pack(pady=10)
'''AES_CFB_enc_label4= tk.Label(AES_CFB_enc_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_enc_label4.pack(pady=10)
AES_CFB_enc_entry3= tk.Entry(AES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_enc_entry3.pack(pady=10)'''
AES_CFB_enc_button = tk.Button(AES_CFB_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command= AES_run)
AES_CFB_enc_button.pack(pady=10)


# Frame pour afficher le résultat 
result_frame_AES_CFB = tk.Frame(main_frame, bg=BG_COLOR)
result_label_AES_CFB = tk.Label(result_frame_AES_CFB,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_AES_CFB.pack(pady=10)
result2_label_AES_CFB= tk.Label(result_frame_AES_CFB, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_AES_CFB.pack(pady=10)

AES_ECB_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_ECB_enc_label= tk.Label(AES_ECB_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_ECB_enc_label.pack(pady=10)
AES_ECB_enc_label2= tk.Label(AES_ECB_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_ECB_enc_label2.pack(pady=10)
AES_ECB_enc_entry= tk.Entry(AES_ECB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_ECB_enc_entry.pack(pady=10)
AES_ECB_enc_label3= tk.Label(AES_ECB_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_ECB_enc_label3.pack(pady=10)
AES_ECB_enc_entry2= tk.Entry(AES_ECB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_ECB_enc_entry2.pack(pady=10)
'''AES_ECB_enc_label4= tk.Label(AES_ECB_enc_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_ECB_enc_label4.pack(pady=10)
AES_ECB_enc_entry3= tk.Entry(AES_ECB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_ECB_enc_entry3.pack(pady=10)'''
AES_ECB_enc_button = tk.Button(AES_ECB_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command= AES_run)
AES_ECB_enc_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_AES_ECB = tk.Frame(main_frame, bg=BG_COLOR)    
result_label_AES_ECB = tk.Label(result_frame_AES_ECB,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_AES_ECB.pack(pady=10)
result2_label_AES_ECB= tk.Label(result_frame_AES_ECB, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_AES_ECB.pack(pady=10)

"""******************************************************************************************"""

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


"""***************************************************************************"""


DES_CBC_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_CBC_enc_label= tk.Label(DES_CBC_enc_frame, text="DES (Data Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_CBC_enc_label.pack(pady=10)
DES_CBC_enc_label2= tk.Label(DES_CBC_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_enc_label2.pack(pady=10)
DES_CBC_enc_entry= tk.Entry(DES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_enc_entry.pack(pady=10)
DES_CBC_enc_label3= tk.Label(DES_CBC_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_enc_label3.pack(pady=10)
DES_CBC_enc_entry2= tk.Entry(DES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_enc_entry2.pack(pady=10)
'''DES_CBC_enc_label4= tk.Label(DES_CBC_enc_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_enc_label4.pack(pady=10)
DES_CBC_enc_entry3= tk.Entry(DES_CBC_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_enc_entry3.pack(pady=10)'''
DES_CBC_enc_button = tk.Button(DES_CBC_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=DES_run)
DES_CBC_enc_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_DES_CBC = tk.Frame(main_frame, bg=BG_COLOR)
result_label_DES_CBC = tk.Label(result_frame_DES_CBC,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_DES_CBC.pack(pady=10)
result2_label_DES_CBC= tk.Label(result_frame_DES_CBC, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_DES_CBC.pack(pady=10)

DES_CFB_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_CFB_enc_label= tk.Label(DES_CFB_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_CFB_enc_label.pack(pady=10)
DES_CFB_enc_label2= tk.Label(DES_CFB_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_enc_label2.pack(pady=10)
DES_CFB_enc_entry= tk.Entry(DES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_enc_entry.pack(pady=10)
DES_CFB_enc_label3= tk.Label(DES_CFB_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_enc_label3.pack(pady=10)
DES_CFB_enc_entry2= tk.Entry(DES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_enc_entry2.pack(pady=10)
'''DES_CFB_enc_label4= tk.Label(DES_CFB_enc_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_enc_label4.pack(pady=10)
DES_CFB_enc_entry3= tk.Entry(DES_CFB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_enc_entry3.pack(pady=10)'''
DES_CFB_enc_button = tk.Button(DES_CFB_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=DES_run)
DES_CFB_enc_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_DES_CFB = tk.Frame(main_frame, bg=BG_COLOR)
result_label_DES_CFB = tk.Label(result_frame_DES_CFB,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_DES_CFB.pack(pady=10)
result2_label_DES_CFB= tk.Label(result_frame_DES_CFB, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_DES_CFB.pack(pady=10)

DES_ECB_enc_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_ECB_enc_label= tk.Label(DES_ECB_enc_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_ECB_enc_label.pack(pady=10)
DES_ECB_enc_label2= tk.Label(DES_ECB_enc_frame, text="Entrez votre texte : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_ECB_enc_label2.pack(pady=10)
DES_ECB_enc_entry= tk.Entry(DES_ECB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_ECB_enc_entry.pack(pady=10)
DES_ECB_enc_label3= tk.Label(DES_ECB_enc_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_ECB_enc_label3.pack(pady=10)
DES_ECB_enc_entry2= tk.Entry(DES_ECB_enc_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_ECB_enc_entry2.pack(pady=10)
DES_ECB_enc_button = tk.Button(DES_ECB_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=DES_run)
DES_ECB_enc_button.pack(pady=10)

# Frame pour afficher le résultat 
result_frame_DES_ECB = tk.Frame(main_frame, bg=BG_COLOR)    
result_label_DES_ECB = tk.Label(result_frame_DES_ECB,text="Le résultat est : ", bg=BG_COLOR, font=custom_font, fg=LB_COLOR)
result_label_DES_ECB.pack(pady=10)
result2_label_DES_ECB= tk.Label(result_frame_DES_ECB, bg=BG_COLOR, font=custom_font, fg=ACCENT_COLOR)
result2_label_DES_ECB.pack(pady=10)

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
RSA_enc_button = tk.Button(RSA_enc_frame, text=" crypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_enc_frame,decrypt_meth_frame))
RSA_enc_button.pack(pady=10)

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
CBC_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_CBC_dec_frame))
CBC_button_AES_dec.pack(pady=10)
CFB_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_CBC_dec_frame))
CFB_button_AES_dec.pack(pady=10)
ECB_button_AES_dec=tk.Button(AES_mode_frame_dec, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_mode_frame_dec,AES_CBC_dec_frame))
ECB_button_AES_dec.pack(pady=10)

DES_mode_frame_dec=tk.Frame(main_frame,bg=BG_COLOR)
mode_label_DES_dec=tk.Label(DES_mode_frame_dec, text="Choisissez le mode de fonctionnement :", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 14))
mode_label_DES_dec.pack(pady=10)
CBC_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" CBC ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_CBC_dec_frame))
CBC_button_DES_dec.pack(pady=10)
CFB_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" CFB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_CBC_dec_frame))
CFB_button_DES_dec.pack(pady=10)
ECB_button_DES_dec=tk.Button(DES_mode_frame_dec, text=" ECB ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_mode_frame_dec,DES_CBC_dec_frame))
ECB_button_DES_dec.pack(pady=10)

bold_font = (FONT_FAMILY, 15, "bold")

AES_CBC_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_CBC_dec_label= tk.Label(AES_CBC_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_CBC_dec_label.pack(pady=10)
AES_CBC_dec_label2= tk.Label(AES_CBC_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_dec_label2.pack(pady=10)
AES_CBC_dec_entry= tk.Entry(AES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_dec_entry.pack(pady=10)
AES_CBC_dec_label3= tk.Label(AES_CBC_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_dec_label3.pack(pady=10)
AES_CBC_dec_entry2= tk.Entry(AES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_dec_entry2.pack(pady=10)
'''AES_CBC_dec_label4= tk.Label(AES_CBC_dec_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CBC_dec_label4.pack(pady=10)
AES_CBC_dec_entry3= tk.Entry(AES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CBC_dec_entry3.pack(pady=10)'''
AES_CBC_dec_button = tk.Button(AES_CBC_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_CBC_dec_frame,decrypt_meth_frame))
AES_CBC_dec_button.pack(pady=10)

AES_CFB_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_CFB_dec_label= tk.Label(AES_CFB_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_CFB_dec_label.pack(pady=10)
AES_CFB_dec_label2= tk.Label(AES_CFB_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_dec_label2.pack(pady=10)
AES_CFB_dec_entry= tk.Entry(AES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_dec_entry.pack(pady=10)
AES_CFB_dec_label3= tk.Label(AES_CFB_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_dec_label3.pack(pady=10)
AES_CFB_dec_entry2= tk.Entry(AES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_dec_entry2.pack(pady=10)
'''AES_CFB_dec_label4= tk.Label(AES_CFB_dec_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_CFB_dec_label4.pack(pady=10)
AES_CFB_dec_entry3= tk.Entry(AES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_CFB_dec_entry3.pack(pady=10)'''
AES_CFB_dec_button = tk.Button(AES_CFB_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_CFB_dec_frame,decrypt_meth_frame))
AES_CFB_dec_button.pack(pady=10)

AES_ECB_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
AES_ECB_dec_label= tk.Label(AES_ECB_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
AES_ECB_dec_label.pack(pady=10)
AES_ECB_dec_label2= tk.Label(AES_ECB_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_ECB_dec_label2.pack(pady=10)
AES_ECB_dec_entry= tk.Entry(AES_ECB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_ECB_dec_entry.pack(pady=10)
'''AES_ECB_dec_label3= tk.Label(AES_ECB_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
AES_ECB_dec_label3.pack(pady=10)
AES_ECB_dec_entry2= tk.Entry(AES_ECB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
AES_ECB_dec_entry2.pack(pady=10)'''
AES_ECB_dec_button = tk.Button(AES_ECB_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(AES_ECB_dec_frame,decrypt_meth_frame))
AES_ECB_dec_button.pack(pady=10)

DES_CBC_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_CBC_dec_label= tk.Label(DES_CBC_dec_frame, text="DES (Data Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_CBC_dec_label.pack(pady=10)
DES_CBC_dec_label2= tk.Label(DES_CBC_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_dec_label2.pack(pady=10)
DES_CBC_dec_entry= tk.Entry(DES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_dec_entry.pack(pady=10)
DES_CBC_dec_label3= tk.Label(DES_CBC_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_dec_label3.pack(pady=10)
DES_CBC_dec_entry2= tk.Entry(DES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_dec_entry2.pack(pady=10)
'''DES_CBC_dec_label4= tk.Label(DES_CBC_dec_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CBC_dec_label4.pack(pady=10)
DES_CBC_dec_entry3= tk.Entry(DES_CBC_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CBC_dec_entry3.pack(pady=10)'''
DES_CBC_dec_button = tk.Button(DES_CBC_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_CBC_dec_frame,decrypt_meth_frame))
DES_CBC_dec_button.pack(pady=10)

DES_CFB_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_CFB_dec_label= tk.Label(DES_CFB_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_CFB_dec_label.pack(pady=10)
DES_CFB_dec_label2= tk.Label(DES_CFB_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_dec_label2.pack(pady=10)
DES_CFB_dec_entry= tk.Entry(DES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_dec_entry.pack(pady=10)
DES_CFB_dec_label3= tk.Label(DES_CFB_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_dec_label3.pack(pady=10)
DES_CFB_dec_entry2= tk.Entry(DES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_dec_entry2.pack(pady=10)
'''DES_CFB_dec_label4= tk.Label(DES_CFB_dec_frame, text="Entrez le IV : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_CFB_dec_label4.pack(pady=10)
DES_CFB_dec_entry3= tk.Entry(DES_CFB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_CFB_dec_entry3.pack(pady=10)'''
DES_CFB_dec_button = tk.Button(DES_CFB_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_CFB_dec_frame,decrypt_meth_frame))
DES_CFB_dec_button.pack(pady=10)

DES_ECB_dec_frame = tk.Frame(main_frame,bg=BG_COLOR)
DES_ECB_dec_label= tk.Label(DES_ECB_dec_frame, text="AES (Advanced Encryption Standard)", fg="#7EFAD5", bg=BG_COLOR, font=bold_font)
DES_ECB_dec_label.pack(pady=10)
DES_ECB_dec_label2= tk.Label(DES_ECB_dec_frame, text="Entrez le message crypté : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_ECB_dec_label2.pack(pady=10)
DES_ECB_dec_entry= tk.Entry(DES_ECB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_ECB_dec_entry.pack(pady=10)
DES_ECB_dec_label3= tk.Label(DES_ECB_dec_frame, text="Entrez la clé : ", fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 15))
DES_ECB_dec_label3.pack(pady=10)
DES_ECB_dec_entry2= tk.Entry(DES_ECB_dec_frame,width=40, fg=LB_COLOR, bg=BG_COLOR, font=custom_font)
DES_ECB_dec_entry2.pack(pady=10)
DES_ECB_dec_button = tk.Button(DES_ECB_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(DES_ECB_dec_frame,decrypt_meth_frame))
DES_ECB_dec_button.pack(pady=10)

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
RSA_dec_button = tk.Button(RSA_dec_frame, text=" décrypter ",fg=FG_COLOR,bg=BUTTON_COLOR, font=custom_font, activeforeground=ACCENT_COLOR, command=lambda: toggle_frames(RSA_dec_frame,decrypt_meth_frame))
RSA_dec_button.pack(pady=10)


date_label = tk.Label(main_frame, text=get_current_datetime(), fg=LB_COLOR, bg=BG_COLOR, font=("Courier", 12))
date_label.place(relx=1.0, rely=0, anchor='ne')

# Lancer la boucle principale de l'application
root.mainloop()