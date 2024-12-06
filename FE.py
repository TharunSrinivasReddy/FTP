from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from tkinter import Tk, Label, Entry, Button
import io
import PIL.Image
import os


def text_encryption_and_decryption():
    """Handles text encryption and decryption."""
    def generate_key():
        """Generate and save a key."""
        key = Fernet.generate_key()
        with open("key.file", "wb") as key_file:
            key_file.write(key)

    def load_key():
        """Load the encryption key."""
        if not os.path.exists("key.file"):
            print("Key not found! Generating a new key.")
            generate_key()
        return open("key.file", "rb").read()

    # Generate or load the key
    generate_key()
    key = load_key()

    # Encryption and Decryption
    text = input("Enter text to encrypt: ")
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text.encode())
    decrypted_text = fernet.decrypt(encrypted_text).decode()

    print(f"Encrypted Text: {encrypted_text.decode()}")
    print(f"Decrypted Text: {decrypted_text}")


def image_encryption_and_decryption():
    """Handles image encryption and decryption."""
    key = b'1234567890987654'  # 16-byte key
    iv = b'9876543210876543'  # 16-byte IV (Initialization Vector)

    def encrypt_images(path):
        """Encrypt a single image or all images in a directory."""
        files = []

        # Check if the provided path is a file or directory
        if os.path.isfile(path) and path.lower().endswith(('.jpg', '.jpeg')):
            files.append(path)  # Single file
        elif os.path.isdir(path):
            # Directory: Find all matching images
            for root, _, filenames in os.walk(path):
                for file in filenames:
                    if file.lower().endswith(('.jpg', '.jpeg')) and not file.endswith('.enc'):
                        files.append(os.path.join(root, file))
        else:
            print("Invalid path or no valid files found.")
            return

        # Encrypt the files
        for file in files:
            with open(file, "rb") as img_file:
                data = img_file.read()
            cipher = AES.new(key, AES.MODE_CFB, iv)
            encrypted_data = cipher.encrypt(data)

            with open(file + ".enc", "wb") as enc_file:
                enc_file.write(encrypted_data)

        print("Encryption completed successfully!")

    def decrypt_images(path):
        """Decrypt a single encrypted image or all encrypted images in a directory."""
        files = []

        # Check if the provided path is a file or directory
        if os.path.isfile(path) and path.endswith('.enc'):
            files.append(path)  # Single encrypted file
        elif os.path.isdir(path):
            # Directory: Find all matching encrypted files
            for root, _, filenames in os.walk(path):
                for file in filenames:
                    if file.endswith('.enc'):
                        files.append(os.path.join(root, file))
        else:
            print("Invalid path or no valid files found.")
            return

        # Decrypt the files
        for file in files:
            with open(file, "rb") as enc_file:
                encrypted_data = enc_file.read()
            cipher = AES.new(key, AES.MODE_CFB, iv)
            decrypted_data = cipher.decrypt(encrypted_data)

            # Create a `.dec` file for the decrypted data
            output_path = file.replace('.enc', '.dec')  # Add `.dec` extension
            with open(output_path, "wb") as dec_file:
                dec_file.write(decrypted_data)

        print("Decryption completed successfully! Files saved with '.dec' extension.")

    # Tkinter GUI
    def start_gui():
        """Starts the GUI for image encryption/decryption."""
        def on_encrypt():
            encrypt_images(folder.get())
            label.config(text="Encryption completed!")

        def on_decrypt():
            decrypt_images(folder.get())
            label.config(text="Decryption completed!")

        gui = Tk()
        gui.title("Image Encryption and Decryption")
        gui.geometry("400x300")

        Label(gui, text="Enter Directory Path").pack()
        folder = Entry(gui, width=50)
        folder.pack()
        folder.insert(0, os.getcwd())  # Default to current directory

        Button(gui, text="Encrypt Images", command=on_encrypt).pack(pady=10)
        Button(gui, text="Decrypt Images", command=on_decrypt).pack(pady=10)

        label = Label(gui, text="", font=("Arial", 12))
        label.pack()

        gui.mainloop()

    start_gui()


def main():
    """Main function to choose between text or image operations."""
    while True:
        print("1. Text Encryption and Decryption")
        print("2. Image Encryption and Decryption")
        print("3. Exit")

        try:
            choice = int(input("Enter your choice: "))
            if choice == 1:
                text_encryption_and_decryption()
            elif choice == 2:
                image_encryption_and_decryption()
            elif choice == 3:
                print("Exiting the program. Goodbye!")
                break
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")


if __name__ == "__main__":
    main()
