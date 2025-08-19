from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# Function to generate and save RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated and saved as 'private_key.pem' and 'public_key.pem'.")

# Function to load keys from files
def load_keys():
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Keys not found! Generate keys first.")
        return None, None

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key

# Function to encrypt a message
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Function to decrypt a message
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Main interactive menu
def main():
    while True:
        print("Asymmetric Encryption Demonstration Using RSA:")
        print("Enter 1 to Generate Public and Private Keys")
        print("Enter 2 to Encrypt a Message")
        print("Enter 3 to Decrypt a Message")
        print("Enter 4 to Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            generate_keys()

        elif choice == "2":
            _, public_key = load_keys()
            if public_key is None:
                continue
            message = input("Enter the message to encrypt: ")
            encrypted = encrypt_message(public_key, message)
            print("Encrypted message:", encrypted)
            with open("encrypted_message.bin", "wb") as f:
                f.write(encrypted)
            print("Encrypted message saved to 'encrypted_message.bin'.")

        elif choice == "3":
            private_key, _ = load_keys()
            if private_key is None:
                continue
            if not os.path.exists("encrypted_message.bin"):
                print("No encrypted message found! Encrypt a message first.")
                continue
            with open("encrypted_message.bin", "rb") as f:
                encrypted_message = f.read()
            decrypted = decrypt_message(private_key, encrypted_message)
            print("Decrypted message:", decrypted)

        elif choice == "4":
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
