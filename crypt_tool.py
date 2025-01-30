import os
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Function to pad data
def pad_data(data, algorithm):
    if algorithm == 'AES':
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
    else:
        padder = padding.PKCS7(64).padder()  # 64-bit block for Blowfish and 3DES
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Function to unpad data
def unpad_data(padded_data, algorithm):
    if algorithm == 'AES':
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    else:
        unpadder = padding.PKCS7(64).unpadder()  # 64-bit block for Blowfish and 3DES
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Function to select AES encryption
def encrypt_aes(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    data = pad_data(data, 'AES')

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as enc_file:
        enc_file.write(iv + ciphertext)

    return encrypted_file

# Function to select Blowfish encryption
def encrypt_blowfish(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    data = pad_data(data, 'Blowfish')

    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as enc_file:
        enc_file.write(iv + ciphertext)

    return encrypted_file

# Function to select Triple DES encryption
def encrypt_3des(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    data = pad_data(data, '3DES')

    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as enc_file:
        enc_file.write(iv + ciphertext)

    return encrypted_file

# Function to handle encryption based on selected algorithm
def handle_encrypt(algorithm):
    file_path = file_path_entry.get()
    password = password_entry.get()

    if len(password) != 16:
        messagebox.showerror("Error", "Password must be exactly 16 characters long.")
        return
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found. Please check the path.")
        return

    key = password.encode()

    if algorithm == 'AES':
        encrypted_file = encrypt_aes(file_path, key)
    elif algorithm == 'Blowfish':
        encrypted_file = encrypt_blowfish(file_path, key)
    elif algorithm == '3DES':
        encrypted_file = encrypt_3des(file_path, key)
    
    messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file}")

# Function to handle decryption (same logic for all algorithms)
def decrypt_file(file_path, key, algorithm):
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        iv = encrypted_data[:16] if algorithm == 'AES' else encrypted_data[:8]  # AES uses 16, others use 8 bytes IV
        ciphertext = encrypted_data[len(iv):]
        
        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        elif algorithm == 'Blowfish':
            cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv))
        elif algorithm == '3DES':
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv))

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        data = unpad_data(padded_data, algorithm)

        decrypted_file = file_path.replace('.enc', '_decrypted')
        with open(decrypted_file, 'wb') as dec_file:
            dec_file.write(data)

        messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to handle the decrypt button click
def handle_decrypt():
    file_path = file_path_entry.get()
    password = password_entry.get()

    if len(password) != 16:
        messagebox.showerror("Error", "Password must be exactly 16 characters long.")
        return
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found. Please check the path.")
        return

    key = password.encode()

    # User selects algorithm in the GUI, so we call decrypt for the chosen algorithm
    decrypt_file(file_path, key, selected_algorithm[0])

# Function to set the encryption algorithm based on user selection
def set_algorithm(algorithm):
    selected_algorithm[0] = algorithm

# Create the GUI
root = Tk()
root.title("Encrypted File Transfer")
root.geometry("500x350")

# Labels and entry fields
Label(root, text="Enter the file path:").pack(pady=5)
file_path_entry = Entry(root, width=40)
file_path_entry.pack(pady=5)

Label(root, text="Enter a password (16 characters):").pack(pady=5)
password_entry = Entry(root, width=40, show="*")
password_entry.pack(pady=5)

# Buttons for selecting algorithms
selected_algorithm = ['AES']  # Default to AES
Button(root, text="Algorithm 1: AES", command=lambda: set_algorithm('AES')).pack(pady=5)
Button(root, text="Algorithm 2: Blowfish", command=lambda: set_algorithm('Blowfish')).pack(pady=5)
Button(root, text="Algorithm 3: 3DES", command=lambda: set_algorithm('3DES')).pack(pady=5)

# Buttons for encryption and decryption
Button(root, text="Encrypt", command=lambda: handle_encrypt(selected_algorithm[0])).pack(pady=10)
Button(root, text="Decrypt", command=handle_decrypt).pack(pady=10)

# Run the GUI
root.mainloop()
