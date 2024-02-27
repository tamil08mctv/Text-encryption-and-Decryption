import tkinter as tk
from tkinter import messagebox
import tkinter.font as font
import pyperclip

last_encrypted_text = ""
last_key = None

def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():  # Check if the character is an alphabet
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

def encrypt_message():
    global last_encrypted_text, last_key
    plaintext = entry_message.get()
    try:
        key = int(entry_key.get())
        if 1 <= key <= 19:
            if plaintext and key != last_key:
                encrypted_text = caesar_encrypt(plaintext, key)
                entry_encrypted_text.delete(0, tk.END)
                entry_encrypted_text.insert(tk.END, encrypted_text)
                last_encrypted_text = encrypted_text
                last_key = key
                messagebox.showinfo("Encryption Successful", "Message encrypted successfully.")
            elif not plaintext:
                messagebox.showwarning("Empty Message", "Please enter a message to encrypt.")
        else:
            messagebox.showwarning("Invalid Key", "Please enter a key between 1 and 19.")
    except ValueError:
        messagebox.showerror("Invalid Key", "Please enter a valid integer key.")

def decrypt_message():
    global entry_message_decrypt, entry_key_decrypt, entry_decrypted_text
    encrypted_text = entry_message_decrypt.get()
    try:
        key = int(entry_key_decrypt.get())
        if 1 <= key <= 19:
            if last_key is not None and last_key == key:
                decrypted_text = caesar_decrypt(encrypted_text, key)
                if encrypted_text == caesar_encrypt(decrypted_text, key):
                    entry_decrypted_text.delete(0, tk.END)
                    entry_decrypted_text.insert(tk.END, decrypted_text)
                else:
                    messagebox.showerror("Invalid Key", "Invalid Key! Decryption failed.")
            else:
                messagebox.showerror("Invalid Key", "Invalid Key! Please enter the correct key used for encryption.")
        else:
            messagebox.showwarning("Invalid Key", "Please enter a key between 1 and 19.")
    except ValueError:
        messagebox.showerror("Invalid Key", "Please enter a valid integer key.")
def copy_encrypted_text():
    global entry_encrypted_text
    try:
        encrypted_text = entry_encrypted_text.get()
        pyperclip.copy(encrypted_text)
        messagebox.showinfo("Copied", "Encrypted text copied to clipboard.")
    except AttributeError:
        messagebox.showerror("Error", "No encrypted text available.")

def copy_decrypted_text():
    global entry_decrypted_text
    try:
        decrypted_text = entry_decrypted_text.get()
        pyperclip.copy(decrypted_text)
        messagebox.showinfo("Copied", "Decrypted text copied to clipboard.")
    except AttributeError:
        messagebox.showerror("Error", "No decrypted text available.")

def open_encrypt_window():
    encrypt_window = tk.Toplevel(root)
    encrypt_window.title("Encryption")

    # Font
    myFont = font.Font(family='Helvetica', size=12)

    global entry_message, entry_key, entry_encrypted_text

    label_message = tk.Label(encrypt_window, text="Enter Message:", font=myFont)
    label_message.grid(row=0, column=0, padx=10, pady=5, sticky="w")
    entry_message = tk.Entry(encrypt_window, width=30, font=myFont)
    entry_message.grid(row=0, column=1, padx=10, pady=5)

    label_key = tk.Label(encrypt_window, text="Enter Key (1-19):", font=myFont)
    label_key.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    entry_key = tk.Entry(encrypt_window, width=30, font=myFont)
    entry_key.grid(row=1, column=1, padx=10, pady=5)

    encrypt_button = tk.Button(encrypt_window, text="Encrypt", command=encrypt_message, font=myFont)
    encrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

    label_encrypted_text = tk.Label(encrypt_window, text="Encrypted Text:", font=myFont)
    label_encrypted_text.grid(row=3, column=0, padx=10, pady=5, sticky="w")
    entry_encrypted_text = tk.Entry(encrypt_window, width=30, font=myFont)
    entry_encrypted_text.grid(row=3, column=1, padx=10, pady=5)

    copy_button_encrypt = tk.Button(encrypt_window, text="Copy", command=copy_encrypted_text, font=myFont)
    copy_button_encrypt.grid(row=4, column=0, columnspan=2, pady=5)


def open_decrypt_window():
    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("Decryption")

    # Font
    myFont = font.Font(family='Helvetica', size=12)

    global entry_message_decrypt, entry_key_decrypt, entry_decrypted_text

    label_message_decrypt = tk.Label(decrypt_window, text="Enter Encrypted Message:", font=myFont)
    label_message_decrypt.grid(row=0, column=0, padx=10, pady=5, sticky="w")
    entry_message_decrypt = tk.Entry(decrypt_window, width=30, font=myFont)
    entry_message_decrypt.grid(row=0, column=1, padx=10, pady=5)

    label_key_decrypt = tk.Label(decrypt_window, text="Enter Key (1-19):", font=myFont)
    label_key_decrypt.grid(row=1, column=0, padx=10, pady=5, sticky="w")
    entry_key_decrypt = tk.Entry(decrypt_window, width=30, font=myFont)
    entry_key_decrypt.grid(row=1, column=1, padx=10, pady=5)

    decrypt_button = tk.Button(decrypt_window, text="Decrypt", command=decrypt_message, font=myFont)
    decrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

    label_decrypted_text = tk.Label(decrypt_window, text="Decrypted Text:", font=myFont)
    label_decrypted_text.grid(row=3, column=0, padx=10, pady=5, sticky="w")
    entry_decrypted_text = tk.Entry(decrypt_window, width=30, font=myFont)
    entry_decrypted_text.grid(row=3, column=1, padx=10, pady=5)

    copy_button_decrypt = tk.Button(decrypt_window, text="Copy", command=copy_decrypted_text, font=myFont)
    copy_button_decrypt.grid(row=4, column=0, columnspan=2, pady=5)


# Main window
root = tk.Tk()
root.title("Caesar Cipher Encryption/Decryption")

encrypt_button = tk.Button(root, text="Encrypt", command=open_encrypt_window)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=open_decrypt_window)
decrypt_button.pack(pady=10)

root.mainloop()
