import os
import hashlib  # Used for hashing the key
import tkinter as tk  # Used for GUI
from tkinter import filedialog, messagebox
from AES import AES  # This assumes that the AES class is in the AES.py file in the same directory.

# Hashes the input key using SHA-256 and returns a 16-byte key.
def hash_key(key):
    """
    Hashes the key using SHA-256 and returns a 16-byte (128-bit) key.
    """
    hashed_key = hashlib.sha256(key.encode()).digest()
    return hashed_key[:16]  # Return the first 16 bytes


def xor_cipher(input_bytes, key):
    output_bytes = bytearray()
    if not isinstance(key, bytearray):
        key = bytearray(key)
    for i, byte in enumerate(input_bytes):
        output_bytes.append(byte ^ key[i % len(key)])
    return output_bytes


def caesar_cipher(input_bytes, key, encrypt=True):
    output_bytes = bytearray()
    if not isinstance(key, bytearray):
        key = bytearray(key)
    for i, byte in enumerate(input_bytes):
        shift_value = key[i % len(key)]
        if not encrypt:  # invert the shift_value for decryption
            shift_value = 256 - shift_value
        output_bytes.append((byte + shift_value) % 256)
    return output_bytes


def custom_encrypt_decrypt(input_bytes, key, encrypt=True):
    if encrypt:
        # XOR followed by Caesar
        xor_result = xor_cipher(input_bytes, key)
        output_bytes = caesar_cipher(xor_result, key, encrypt=encrypt)
    else:
        # Reverse order for decryption: Caesar followed by XOR
        caesar_result = caesar_cipher(input_bytes, key, encrypt=encrypt)
        output_bytes = xor_cipher(caesar_result, key)
    return bytes(output_bytes)


# Initialize the main Tkinter window.
root = tk.Tk()
root.title("File Encryptor & Decryptor")
root.geometry("900x400")
root.configure(bg="#2e2e2e")

# Define the variables that will hold the state of radio buttons.
algorithm_var = tk.BooleanVar()
operation_var = tk.StringVar(value="encrypt")

# Define the color of label text.
label_fg = "white"

# Define the label, entry, and button widgets.
file_label = tk.Label(root, text="File Path:", fg=label_fg, bg="#2e2e2e", font=("Arial", 16))
file_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")

file_entry = tk.Entry(root, width=40, bg="#404040", fg=label_fg, font=("Arial", 16))
file_entry.grid(row=0, column=1, padx=20, pady=20)

password_label = tk.Label(root, text="Password:", fg=label_fg, bg="#2e2e2e", font=("Arial", 16))
password_label.grid(row=1, column=0, padx=20, pady=20, sticky="w")

password_entry = tk.Entry(root, width=40, show="*", bg="#404040", fg=label_fg, font=("Arial", 16))
password_entry.grid(row=1, column=1, padx=20)


def encrypt_file(filepath, password, use_aes=False):
    with open(filepath, 'rb') as file:
        file_data = file.read()

    hashed_password = hash_key(password)

    # Check if AES encryption is used.
    if use_aes:
        aes = AES(hashed_password)
        encrypted_data = aes.encrypt(file_data)
    else:  # If AES is not used, use the custom encryption.
        encrypted_data = custom_encrypt_decrypt(file_data, hashed_password, encrypt=True)

    # Write the encrypted data to a new file and remove the original file.
    with open(filepath + '.enc', 'wb') as file:
        file.write(encrypted_data)

    os.remove(filepath)


# Function to decrypt the file.
def decrypt_file(filepath, password, use_aes=False):
    with open(filepath, 'rb') as file:
        file_data = file.read()

    hashed_password = hash_key(password)

    # Check if AES decryption is used.
    if use_aes:

        aes = AES(hashed_password)
        decrypted_data = aes.decrypt(file_data)
    else:  # If AES is not used, use the custom decryption.
        decrypted_data = custom_encrypt_decrypt(file_data, hashed_password, encrypt=False)

    # Write the decrypted data to a new file and remove the encrypted file.
    original_filepath = filepath.rstrip('.enc')
    with open(original_filepath, 'wb') as file:
        file.write(decrypted_data)

    os.remove(filepath)


# Function to get the file path.
def browse_file():
    filepath = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filepath)


# Function to process the file, either encryption or decryption.
def process_file():
    filepath = file_entry.get()
    password = password_entry.get()
    use_aes = algorithm_var.get()

    if not filepath or not password:
        messagebox.showerror("Error", "Please provide file path and password.")
        return

    if operation_var.get() == "encrypt":
        encrypt_file(filepath, password, use_aes)
        messagebox.showinfo("Success", "File encrypted successfully.")
    else:
        decrypt_file(filepath, password, use_aes)
        messagebox.showinfo("Success", "File decrypted successfully.")


# Browse button for selecting the file.
browse_button = tk.Button(root, text="Browse", command=browse_file, bg="#404040", fg=label_fg, font=("Arial", 16))
browse_button.grid(row=0, column=2, padx=20, pady=20)

# Radio buttons for selecting the operation: encryption or decryption.
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=operation_var, value="encrypt", fg=label_fg,
                               bg="#2e2e2e", selectcolor="#595959", font=("Arial", 16))
encrypt_radio.grid(row=2, column=0, padx=20, pady=20, sticky="w")

decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=operation_var, value="decrypt", fg=label_fg,
                               bg="#2e2e2e", selectcolor="#595959", font=("Arial", 16))
decrypt_radio.grid(row=2, column=1, padx=20, pady=20, sticky="w")

# Radio buttons for selecting the algorithm: custom or AES.
custom_radio = tk.Radiobutton(root, text="Custom", variable=algorithm_var, value=False, fg=label_fg, bg="#2e2e2e",
                              selectcolor="#595959", font=("Arial", 16))
custom_radio.grid(row=3, column=1, padx=20, pady=20, sticky="w")

aes_radio = tk.Radiobutton(root, text="AES", variable=algorithm_var, value=True, fg=label_fg, bg="#2e2e2e",
                           selectcolor="#595959", font=("Arial", 16))
aes_radio.grid(row=3, column=0, padx=20, pady=20, sticky="w")

# Process button to start the encryption or decryption process.
process_button = tk.Button(root, text="Process", command=process_file, width=15, bg="#404040", fg=label_fg,
                           font=("Arial", 16))
process_button.grid(row=4, column=1, pady=40)

# Start the Tkinter event loop.
root.mainloop()

