from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# AES Encryption/Decryption
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def aes_encrypt(text, key):
    key = key.ljust(16)[:16].encode()  
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted_text).decode()

def aes_decrypt(enc_text, key):
    key = key.ljust(16)[:16].encode()  
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(enc_text)).decode())
    return decrypted_text

# DES Encryption/Decryption
def des_encrypt(text, key):
    key = key.ljust(8)[:8].encode()  
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted_text).decode()

def des_decrypt(enc_text, key):
    key = key.ljust(8)[:8].encode()  
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(enc_text)).decode())
    return decrypted_text

# RSA Key Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode(), public_key.decode()

# RSA Encryption/Decryption
def rsa_encrypt(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_text = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted_text).decode()

def rsa_decrypt(enc_text, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_text = cipher.decrypt(base64.b64decode(enc_text)).decode()
    return decrypted_text

# User Interactive Menu
def main():
    print("\n🔐 TEXT ENCRYPTION & DECRYPTION TOOL 🔐\n")
    print("1. Encrypt Text")
    print("2. Decrypt Text")
    choice = input("Select (1/2): ")

    print("\nSelect Encryption Method:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")
    method_choice = input("Select (1/2/3): ")

    if choice == "1":  
        text = input("\nEnter text to encrypt: ")

        if method_choice == "1":  
            key = input("Enter AES key (16 chars recommended): ")
            encrypted_text = aes_encrypt(text, key)
            print("\n🔐 Encrypted Text:", encrypted_text)

        elif method_choice == "2":  
            key = input("Enter DES key (8 chars recommended): ")
            encrypted_text = des_encrypt(text, key)
            print("\n🔐 Encrypted Text:", encrypted_text)

        elif method_choice == "3":  
            private_key, public_key = generate_rsa_keys()
            encrypted_text = rsa_encrypt(text, public_key)
            print("\n🔐 Encrypted Text:", encrypted_text)
            print("\n🔑 Save these keys for decryption:")
            print("Private Key:\n", private_key)
            print("Public Key:\n", public_key)

        else:
            print("\n❌ Invalid choice!")

    elif choice == "2":  
        enc_text = input("\nEnter encrypted text: ")

        if method_choice == "1":  
            key = input("Enter AES key: ")
            decrypted_text = aes_decrypt(enc_text, key)
            print("\n🔓 Decrypted Text:", decrypted_text)

        elif method_choice == "2":  
            key = input("Enter DES key: ")
            decrypted_text = des_decrypt(enc_text, key)
            print("\n🔓 Decrypted Text:", decrypted_text)

        elif method_choice == "3":  
            private_key = input("Enter your RSA Private Key:\n")
            decrypted_text = rsa_decrypt(enc_text, private_key)
            print("\n🔓 Decrypted Text:", decrypted_text)

        else:
            print("\n❌ Invalid choice!")

    else:
        print("\n❌ Invalid choice!")

if __name__ == "__main__":
    main()
