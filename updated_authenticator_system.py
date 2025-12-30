import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import hashlib
import base64
import os 
import threading
import time


from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA


DES_KEY_FILE = "DES_PRKEY.txt" 
AES_KEYS_FILE = "aes_keys.txt"
RSA_PRKEY_FILE = "RSA_PRKEY.txt"
VAULT_FILE = os.path.join(os.path.dirname(__file__),"user_vault.txt")

DES_KEY = None
AES_KEY = None
AES_IV = None
RSA_PUBLIC_CIPHER = None
RSA_PRIVATE_CIPHER = None


def load_keys():
    global AES_KEY, AES_IV, RSA_PUBLIC_CIPHER, RSA_PRIVATE_CIPHER, DES_KEY
    
    try:
        with open(DES_KEY_FILE, "rb") as d:
            DES_KEY = d.read().strip()
            if len(DES_KEY) != 8:
                print("Error: DES key must be exactly 8 bytes long.")
                return False

        with open(AES_KEYS_FILE, "r") as k:
            AES_KEY = base64.b64decode(k.readline().strip())
            AES_IV  = base64.b64decode(k.readline().strip())
        
        with open(RSA_PRKEY_FILE, 'rb') as f:
            private_key = RSA.import_key(f.read())
            
        public_key = private_key.publickey()
        
        RSA_PRIVATE_CIPHER = PKCS1_OAEP.new(private_key)
        RSA_PUBLIC_CIPHER = PKCS1_OAEP.new(public_key)
        
        return True
    except FileNotFoundError as e:
        print(f"Error: Required key file not found: {e.filename}")
        return False


#Encryption pipeline

def encrypt_pipeline(password):
    
    #Hash Function
    hashed_data = hashlib.sha512(password.encode('utf-8')).digest()
    
    #DES Encryption 
    cipher_des = DES.new(DES_KEY, DES.MODE_ECB)
    padded_des = pad(hashed_data, DES.block_size)
    des_encrypted = cipher_des.encrypt(padded_des)
    
    #AES Encryption
    cipher_aes = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_aes = pad(des_encrypted, AES.block_size)
    aes_encrypted = cipher_aes.encrypt(padded_aes)
    
    #RSA Encryption
    final_ciphertext = RSA_PUBLIC_CIPHER.encrypt(aes_encrypted)
    
    return final_ciphertext


#Decryption pipeline

def decrypt_pipeline(ciphertext):
    
    #RSA Decryption 
    aes_encrypted_output = RSA_PRIVATE_CIPHER.decrypt(ciphertext)
    
    #AES Decryption
    cipher_aes = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    des_encrypted_output_padded = cipher_aes.decrypt(aes_encrypted_output)
    des_encrypted_output = unpad(des_encrypted_output_padded, AES.block_size)
    
    #DES Decryption
    cipher_des = DES.new(DES_KEY, DES.MODE_ECB)
    hash_output_padded = cipher_des.decrypt(des_encrypted_output)
    original_hash_bytes = unpad(hash_output_padded, DES.block_size)
    
    return original_hash_bytes

# Set theme for a professional, low-light aesthetic
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue") 


def check_password_strength(password, label):
    if not password:
        label.configure(text="* Password must be at least 8 characters long", text_color="#FF5555")
        return

    strength = 0
    
    if len(password) >= 8: strength += 1
    if any(char.isdigit() for char in password): strength += 1
    if any(not char.isalnum() for char in password): strength += 1
    if any(char.isupper() for char in password) and any(char.islower() for char in password): strength += 1

    if len(password) < 8:
        label.configure(text="❌ Too Short (Min 8 chars)", text_color="#FF5555")
    elif strength <= 1:
        label.configure(text="⚠️ Weak - Add numbers or symbols", text_color="#FFA500")
    elif strength == 2 or strength == 3:
        label.configure(text="OK - Good Password", text_color="#FFFF00")
    elif strength >= 4:
        label.configure(text="✅ Strong Password", text_color="#00FF00")
        
def handle_user_registration(username, password):
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Username and Password cannot be empty!")
        return False
    
    if len(password) < 8:
            messagebox.showerror("Security Error", "Password must be at least 8 characters long!")
            return False 

    try:
    
        final_ciphertext = encrypt_pipeline(password)
        record = f"{username}:{final_ciphertext.hex()}\n"
        
        with open(VAULT_FILE, 'a') as f:
            f.write(record)

        messagebox.showinfo("Registration", f"Registration successful for '{username}'.") 
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed for '{username}'. Error: {e}") 
        return False
    
def handle_user_login(username, password):
   
    if not username or not password:
        messagebox.showwarning("Input Error", "Please enter credentials.")
        return False
    
    hashed_pass_login = hashlib.sha512(password.encode('utf-8')).digest()

    try:
        with open(VAULT_FILE, "r") as f:
            lines = f.readlines()
       
        user_found = False
        for line in lines:
            stored_username, stored_cipher_hex = line.strip().split(':')

            if stored_username == username:
                user_found = True
                stored_ciphertext_bytes = bytes.fromhex(stored_cipher_hex)
                stored_hash = decrypt_pipeline(stored_ciphertext_bytes)

                if stored_hash == hashed_pass_login:
                    messagebox.showinfo("Login Successfully!", f"Welcome back, {username}!")
                    return True
                else:
                    messagebox.showerror("Access Denied", "Incorrect Password")
                    return False
        if not user_found:
           messagebox.showwarning("Not Found", "User is not registered")
           return False
        
    except Exception as e:
        messagebox.showerror("Login Failed", f"Try Again. Error: {e}")
        return False

def toggle_password_visibility(entry, show):
    entry.configure(show="" if show else "*")


def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()


def switch_to_login(root):
    clear_frame(right_frame)
    create_login_view(right_frame, root)



def switch_to_register(root):
    clear_frame(right_frame)
    create_register_view(right_frame, root)



# --- Login View (Updated with Aqua accent) ---
def create_login_view(parent_frame, root):
    
    # Header
    ctk.CTkLabel(parent_frame, text="SECURE PORTAL LOGIN", font=("Arial", 32, "bold"), text_color="#FFFFFF").pack(pady=(50, 20))
    ctk.CTkLabel(parent_frame, text="Enter Your Credentials", font=("Arial", 16), text_color="#AAAAAA").pack(pady=(0, 30))
    
    # Username Entry
    global login_username_entry
    login_username_entry = ctk.CTkEntry(
        parent_frame, 
        placeholder_text="Username", 
        width=350, 
        height=50, 
        font=("Arial", 16),
        fg_color="#1F1F1F",
        border_color="#00FFFF",   # NEW: Aqua Border
        border_width=1,
        corner_radius=10
    )
    
    login_username_entry.pack(pady=(15, 15))
    
    # Password Entry
    global login_password_entry
    login_password_entry = ctk.CTkEntry(
        parent_frame, 
        placeholder_text="Password", 
        show="*", 
        width=350, 
        height=50, 
        font=("Arial", 16),
        fg_color="#1F1F1F",
        border_color="#00FFFF",   # NEW: Aqua Border
        border_width=1,
        corner_radius=10
    )
    
    login_password_entry.pack(pady=(15, 40))
    
    show_pass_login = ctk.BooleanVar(value=False)
    ctk.CTkCheckBox(
        parent_frame, 
        text="Show Password", 
        variable=show_pass_login,
        command=lambda: toggle_password_visibility(login_password_entry, show_pass_login.get()),
        font=("Arial", 12),
        text_color="#AAAAAA",
        fg_color="#00FFFF", 
        hover_color="#00CCCC",
        checkbox_width=18,
        checkbox_height=18
    ).pack(pady=(0, 20), padx=(0, 220)) 
    
    # Primary Button (LOGIN) - Vibrant Aqua Fill
    login_button = ctk.CTkButton(
        parent_frame, 
        text="LOGIN", 
        command=lambda: handle_user_login(login_username_entry.get(), login_password_entry.get()), 
        width=350, 
        height=55, 
        font=("Arial", 18, "bold"),
        fg_color="#00FFFF",             # NEW: Vibrant Aqua Fill
        hover_color="#00CCCC",
        text_color="#101010",           
        corner_radius=10
    )
    login_button.pack(pady=(10, 30))
    
    # Switch to Register Prompt Frame
    prompt_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
    prompt_frame.pack(pady=(10, 0))
    
    ctk.CTkLabel(prompt_frame, text="Don't have an account?", font=("Arial", 14), text_color="#AAAAAA").pack(side=tk.LEFT, padx=10)
    
    # Secondary Button (REGISTER) - Aqua Link
    switch_button = ctk.CTkButton(
        prompt_frame, 
        text="Register Now", 
        command=lambda: switch_to_register(root), 
        width=150, 
        fg_color="transparent",
        hover_color="#1F1F1F",
        text_color="#00FFFF",           # NEW: Vibrant Aqua Text Link
        font=("Arial", 14, "underline")
    )
    switch_button.pack(side=tk.LEFT, padx=10)

# --- Register View (Updated with Aqua accent) ---
def create_register_view(parent_frame, root):
    
    # Header
    ctk.CTkLabel(parent_frame, text="SECURE PORTAL LOGIN", font=("Arial", 32, "bold"), text_color="#FFFFFF").pack(pady=(50, 20))
    ctk.CTkLabel(parent_frame, text="Create a New Account ", font=("Arial", 16), text_color="#AAAAAA").pack(pady=(0, 30))

    # Username Entry
    global reg_username_entry
    reg_username_entry = ctk.CTkEntry(
        parent_frame, 
        placeholder_text="Choose Username", 
        width=350, 
        height=50, 
        font=("Arial", 16),
        fg_color="#1F1F1F",
        border_color="#00FFFF",
        border_width=1,
        corner_radius=10
    )
    reg_username_entry.pack(pady=(15, 15))
    
    # Password Entry
    global reg_password_entry
    reg_password_entry = ctk.CTkEntry(
        parent_frame, 
        placeholder_text="Choose Password", 
        show="*", 
        width=350, 
        height=50, 
        font=("Arial", 16),
        fg_color="#1F1F1F",
        border_color="#00FFFF",
        border_width=1,
        corner_radius=10
    )
    reg_password_entry.pack(pady=(15, 5)) 

    strength_label = ctk.CTkLabel(
        parent_frame, 
        text="* Password must be at least 8 characters long", 
        font=("Arial", 11), 
        text_color="#FF5555" 
    )
    strength_label.pack(pady=(0, 15))

    reg_password_entry.bind("<KeyRelease>", lambda event: check_password_strength(reg_password_entry.get(), strength_label))
    
    # Show Password Checkbox
    show_pass_reg = ctk.BooleanVar(value=False)
    ctk.CTkCheckBox(
        parent_frame, 
        text="Show Password", 
        variable=show_pass_reg,
        command=lambda: toggle_password_visibility(reg_password_entry, show_pass_reg.get()),
        font=("Arial", 12),
        text_color="#AAAAAA",
        fg_color="#00FFFF",
        hover_color="#00CCCC",
        checkbox_width=18,
        checkbox_height=18
    ).pack(pady=(0, 20), padx=(0, 220))
    
    # Primary Button (REGISTER)
    register_button = ctk.CTkButton(
        parent_frame, 
        text="CREATE ACCOUNT", 
        command=lambda: handle_user_registration(reg_username_entry.get(), reg_password_entry.get()),
        width=350, 
        height=55, 
        font=("Arial", 18, "bold"),
        fg_color="#00FFFF",
        hover_color="#00CCCC",
        text_color="#101010",
        corner_radius=10
    )
    register_button.pack(pady=(10, 30))
    
    # Switch to Login Prompt Frame
    prompt_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
    prompt_frame.pack(pady=(10, 0))

    ctk.CTkLabel(prompt_frame, text="Already have an account?", font=("Arial", 14), text_color="#AAAAAA").pack(side=tk.LEFT, padx=10)

    # Secondary Button (LOGIN)
    switch_button = ctk.CTkButton(
        prompt_frame, 
        text="Login", 
        command=lambda: switch_to_login(root), 
        width=150, 
        fg_color="transparent",
        hover_color="#1F1F1F",
        text_color="#00FFFF",
        font=("Arial", 14, "underline")
    )
    switch_button.pack(side=tk.LEFT, padx=10)

# --- Main Application Setup (Updated Left Panel Colors and Icon) ---
#Main

if __name__ == "__main__":
    if not load_keys():
        print("Failed to load Keys. \nTry Again.")
        exit()
    else:
        print("\nWelcome to the User System")

        root = ctk.CTk()
        root.title("Secure Authentication Interface")
        root.geometry("850x620")
        root.resizable(False, False)

        # Main container for the two panels
        main_container = ctk.CTkFrame(root, fg_color="#151515") 
        main_container.pack(expand=True, fill='both', padx=0, pady=0)

        # --- Left Graphical Panel (Deep Teal/Midnight Blue) ---
        left_frame = ctk.CTkFrame(
            main_container, 
            width=50,
            corner_radius=10, 
            fg_color="#00FFFF"            # NEW: Deep Teal/Midnight Blue
        )
        left_frame.pack(side="left", fill="y", padx=0, pady=0)

        # Graphics/Text for the left panel 
        ctk.CTkLabel(left_frame, text="🌐", font=("Arial", 100), text_color="#1E4949").pack(pady=(70, 10)) # NEW: Lock Icon with Aqua color
        ctk.CTkLabel(left_frame, text="  SECURE CONNECTION  ", font=("Arial", 22, "bold"), text_color="#093F5E").pack(pady=5)
        ctk.CTkLabel(left_frame, text="Network Access Protocol", font=("Arial", 20), text_color="#113352").pack(pady=5)
        ctk.CTkLabel(left_frame, text="Status: Online\nSystem Ready.", font=("Arial", 14), text_color="#18A5B8").pack(pady=(20, 10))


        # --- Right Form Panel ---
        global right_frame
        right_frame = ctk.CTkFrame(
            main_container, 
            corner_radius=0, 
            fg_color="#151515"              
        )
        right_frame.pack(side="right", fill="both", expand=True, padx=0)

        # Start with the Login view directly (no animation for initial load)
        global view_frame
        view_frame = ctk.CTkFrame(right_frame, fg_color="#151515")
        view_frame.place(x=0, y=0, relwidth=1, relheight=1)
        create_login_view(view_frame, root)

        # Run the application
        root.mainloop()