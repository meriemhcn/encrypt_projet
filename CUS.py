import customtkinter as ctk
from PIL import Image, ImageTk
from datetime import datetime

# Couleurs
BG_COLOR = "#1b023f"
FG_COLOR = "#1b023f"
LB_COLOR = "#2ede93"
ACCENT_COLOR = "#ff0000"
PROGRESS_COLOR = "#00ff00"
BUTTON_COLOR = "#2ede93"  # Couleur des boutons
BUTTON_ACTIVE_COLOR = "#bc4749"  # Couleur des boutons lorsqu'ils sont actifs

# Police de caractères
FONT_FAMILY = "Verdana"
FONT_SIZE = 14

current_frame = None

def encrypt_click():
    return None

def decrypt_click():
    return None

def toggle_frames(hide_frame, show_frame):
    global current_frame
    hide_frame.pack_forget()
    show_frame.pack(expand=True)
    current_frame = show_frame
    toggle_back_button(True)

# Obtenir la date et l'heure actuelles
def get_current_datetime():
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return date_time

# Fonction pour afficher/cacher le bouton "Retour"
def toggle_back_button(show):
    if show:
        back_button.pack(side="left", padx=10, pady=10)
    else:
        back_button.pack_forget()

def return_to_previous_screen():
    global current_frame
    if current_frame == first_frame:
        first_frame.pack_forget()
        zero_frame.pack(expand=True)
        current_frame = zero_frame
        toggle_back_button(False)
    elif current_frame == crypt_meth_frame:
        crypt_meth_frame.pack_forget()
        first_frame.pack(expand=True)
        current_frame = first_frame
    elif current_frame == decrypt_meth_frame:
        decrypt_meth_frame.pack_forget()
        first_frame.pack(expand=True)
        current_frame = first_frame
    elif current_frame == zero_frame:
        pass

# Configuration de la fenêtre principale
window_width = 550
window_height = 500

root = ctk.CTk()
root.title("Cryptography")
root.geometry(f'{window_width}x{window_height}+{root.winfo_screenwidth() // 2 - window_width // 2}+{root.winfo_screenheight() // 2 - window_height // 2}')
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

main_frame = ctk.CTkFrame(root, fg_color=BG_COLOR)
main_frame.pack(expand=True, padx=20, pady=20)

custom_font = (FONT_FAMILY, FONT_SIZE)

# Bouton "Retour" en bas à gauche
back_button = ctk.CTkButton(main_frame, text="←", command=return_to_previous_screen, fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
root.bind("<Escape>", lambda event: back_button.invoke())
toggle_back_button(False)

zero_frame = ctk.CTkFrame(main_frame, fg_color=BG_COLOR)
zero_frame.pack(expand=True)

# Charger l'image
image_path = "Logo.png"
image = Image.open(image_path)
image = image.resize((300, 300), Image.LANCZOS)  # Redimensionner l'image si nécessaire
photo = ImageTk.PhotoImage(image)

# Ajouter l'image à un Label
image_label = ctk.CTkLabel(zero_frame, image=photo, fg_color=BG_COLOR)
image_label.pack(pady=(0, 10))  # Ajouter un espacement vertical autour de l'image

# Bouton BIENVENUE
bienvenue = ctk.CTkButton(zero_frame, text="BIENVENUE", command=lambda: toggle_frames(zero_frame, first_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
bienvenue.pack(pady=(10, 0))

# Boutons dans la nouvelle frame
first_frame = ctk.CTkFrame(main_frame, fg_color=BG_COLOR)
first_frame.pack_forget()

# Créer les boutons Encrypt et Decrypt
button_encrypt = ctk.CTkButton(first_frame, text="Encrypt Text", command=lambda: toggle_frames(first_frame, crypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
button_encrypt.pack(pady=10)

button_decrypt = ctk.CTkButton(first_frame, text="Decrypt Text", command=lambda: toggle_frames(first_frame, decrypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
button_decrypt.pack(pady=10)

crypt_meth_frame = ctk.CTkFrame(main_frame, fg_color=BG_COLOR)
crypt_meth_frame.pack_forget()

text_label = ctk.CTkLabel(crypt_meth_frame, text="Choisissez l'algorithme de cryptage :", font=("Courier", 14), fg_color=BG_COLOR, text_color=LB_COLOR)
text_label.pack(pady=10)

AES_button = ctk.CTkButton(crypt_meth_frame, text="AES", command=lambda: toggle_frames(first_frame, crypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
AES_button.pack(pady=10)

DES_button = ctk.CTkButton(crypt_meth_frame, text="DES", command=lambda: toggle_frames(first_frame, crypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
DES_button.pack(pady=10)

RSA_button = ctk.CTkButton(crypt_meth_frame, text="RSA", command=lambda: toggle_frames(first_frame, crypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
RSA_button.pack(pady=10)

decrypt_meth_frame = ctk.CTkFrame(main_frame, fg_color=BG_COLOR)
decrypt_meth_frame.pack_forget()

text_label_dec = ctk.CTkLabel(decrypt_meth_frame, text="Choisissez l'algorithme de décryptage :", font=("Courier", 14), fg_color=BG_COLOR, text_color=LB_COLOR)
text_label_dec.pack(pady=10)

AES_button_dec = ctk.CTkButton(decrypt_meth_frame, text="AES", command=lambda: toggle_frames(first_frame, decrypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
AES_button_dec.pack(pady=10)

DES_button_dec = ctk.CTkButton(decrypt_meth_frame, text="DES", command=lambda: toggle_frames(first_frame, decrypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
DES_button_dec.pack(pady=10)

RSA_button_dec = ctk.CTkButton(decrypt_meth_frame, text="RSA", command=lambda: toggle_frames(first_frame, decrypt_meth_frame), fg_color=BUTTON_COLOR, hover_color=BUTTON_ACTIVE_COLOR, text_color=FG_COLOR, font=custom_font)
RSA_button_dec.pack(pady=10)

date_label = ctk.CTkLabel(main_frame, text=get_current_datetime(), font=("Courier", 12), fg_color=BG_COLOR, text_color=LB_COLOR)
date_label.pack(side="right", padx=10, pady=10)

# Masquer les frames supplémentaires au début
first_frame.pack_forget()
crypt_meth_frame.pack_forget()
decrypt_meth_frame.pack_forget()

# Lancer la boucle principale
root.mainloop()
