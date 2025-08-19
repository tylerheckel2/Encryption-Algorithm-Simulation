from cryptography.fernet import Fernet

# AES Functions
def generate_key():
    return Fernet.generate_key()

def encrypt_aes(message, key):
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted

def decrypt_aes(encrypted_message, key):
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message).decode()
    return decrypted

# Main program
def main():
    print("Symmetric Encryption Demonstration Using AES:")
    print("Enter 1 to Encrypt a Message")
    print("Enter 2 to Decrypt a Message")
    print("Enter 3 to Exit")

    key = None
    while True:
        choice = input("\nEnter your choice: ")
        if choice == "1":
            if not key:
                key = generate_key()
                print(f"Generated AES Key: {key.decode()}")
            message = input("Enter the message to encrypt (AES): ")
            encrypted_message = encrypt_aes(message, key)
            print("Encrypted Message:", encrypted_message.decode())
        elif choice == "2":
            if not key:
                print("No key available. Please encrypt a message first.")
            else:
                encrypted_message = input("Enter the encrypted message (AES): ").encode()
                try:
                    decrypted_message = decrypt_aes(encrypted_message, key)
                    print("Decrypted Message:", decrypted_message)
                except Exception as e:
                    print("Decryption failed:", str(e))
        elif choice == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()