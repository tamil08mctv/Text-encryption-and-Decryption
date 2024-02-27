import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
import os
import shutil

def generate_key(password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    ciphered_pw = cipher_suite.encrypt(password.encode())
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return cipher_suite, ciphered_pw

def load_key():
    return open("key.key", "rb").read()
1484848555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555

48555555555555555555

def encrypt_folder(folder_path, cipher_suite):
    temp_folder = 'temp'
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)
    os.makedirs(temp_folder)
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            with open(file_path, "rb") as f:
                data = f.read()

            encrypted_data = cipher_suite.encrypt(data)

            relative_path = os.path.relpath(file_path, folder_path)
            encrypted_file_path = os.path.join(temp_folder, relative_path + ".enc")
            os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_data)

    shutil.make_archive(folder_path, 'zip', temp_folder)
    shutil.rmtree(temp_folder)

def decrypt_folder(folder_path, cipher_suite, password):
    temp_folder = 'temp'
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)
    os.makedirs(temp_folder)
    shutil.unpack_archive(folder_path, temp_folder, 'zip')
    for dirpath, dirnames, filenames in os.walk(temp_folder):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = cipher_suite.decrypt(encrypted_data)

            relative_path = os.path.relpath(file_path[:-4], temp_folder)
            decrypted_file_path = os.path.join(folder_path, relative_path)
            os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)
            with open(decrypted_file_path, "wb") as f:
                f.write(decrypted_data)

    shutil.rmtree(temp_folder)

def initiate_folder_with_password():
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    if password != confirm_password:
        result_label.config(text="Passwords do not match. Please try again.")
        return
    generate_key(password)
    result_label.config(text="Folder initiation successful.")

def browse_folder():
    folder_path = filedialog.askdirectory()
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, folder_path)

def encrypt_selected_folder():
    folder_path = file_path_entry.get()
    password = password_entry.get()
    cipher_suite = Fernet(load_key())
    encrypt_folder(folder_path, cipher_suite)
    result_label.config(text="Folder encrypted successfully.")

def decrypt_selected_folder():
    folder_path = file_path_entry.get()
    password = password_entry.get()
    cipher_suite = Fernet(load_key())
    try:
        decrypt_folder(folder_path, cipher_suite, password)
        result_label.config(text="Folder decrypted successfully.")
    except Exception as e:
        result_label.config(text="Error: Incorrect password or invalid encrypted folder.")

# Create Tkinter window
window = tk.Tk()
window.title("Folder Encryption/Decryption")
window.geometry("400x200")

# Folder path label and entry
file_path_label = tk.Label(window, text="Folder Path:")
file_path_label.grid(row=0, column=0, sticky="w")

file_path_entry = tk.Entry(window, width=30)
file_path_entry.grid(row=0, column=1, padx=5, pady=5)

browse_button = tk.Button(window, text="Browse", command=browse_folder)
browse_button.grid(row=0, column=2, padx=5, pady=5)

# Password label and entry
password_label = tk.Label(window, text="Password:")
password_label.grid(row=1, column=0, sticky="w")

password_entry = tk.Entry(window, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

confirm_password_label = tk.Label(window, text="Confirm Password:")
confirm_password_label.grid(row=2, column=0, sticky="w")

confirm_password_entry = tk.Entry(window, show="*")
confirm_password_entry.grid(row=2, column=1, padx=5, pady=5)

# Buttons for operations
initiate_button = tk.Button(window, text="Initiate Folder", command=initiate_folder_with_password)
initiate_button.grid(row=3, column=0, padx=5, pady=5)

encrypt_button = tk.Button(window, text="Encrypt Folder", command=encrypt_selected_folder)
encrypt_button.grid(row=3, column=1, padx=5, pady=5)

decrypt_button = tk.Button(window, text="Decrypt Folder", command=decrypt_selected_folder)
decrypt_button.grid(row=3, column=2, padx=5, pady=5)

# Result label
result_label = tk.Label(window, text="")
result_label.grid(row=4, column=0, columnspan=3, pady=5)

window.mainloop()
