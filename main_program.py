# -*- coding: utf-8 -*-
"""
Main program for EECE2140, Final Noah-Issac
Created by <Noah>,<Issac>
Created on 24-3-27, Wednesday:
"""
from Crypto.Util.Padding import pad
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# needed for alphabet encoder/decoder
alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z']


def read_file(file_to_open):
    # all file can be seen as txt
    with open(file_to_open, 'r', encoding='utf-8') as opened_file:
        return opened_file.read()  # Returns the contents of the file as a single string


def write_file(filename, data, is_binary=False):
    mode = 'wb' if is_binary else 'w'
    with open(filename, mode) as file:
        if is_binary:
            file.write(data)
        else:
            file.write(data + "\n")


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return iv + encrypted_data

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:AES.block_size]
        encrypted_content = encrypted_data[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        original_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)
        return original_data.decode('utf-8')

'''
def read_binary_file(file_path):
    with open(file_path, 'rb') as file:
        binary_data = file.read()
    return binary_data
def decrypt_file(file_path, aes_key):
    encrypted_data = read_binary_file(file_path)
    aes_cipher = AESCipher(aes_key)
    decrypted_data = aes_cipher.decrypt(encrypted_data)
    return decrypted_data
'''

def alpha_encode(user_inp):
    encoded_msg = ""
    for i in range(len(user_inp)):
        # only proceeds if the element is in the alphabet
        if user_inp[i] in alphabet:
            # let z and turns to a
            if user_inp[i] == 'z':
                encoded_msg = encoded_msg + 'a'
            else:
                # finds the index of the specific element, adds one and then pulls that number from the alphabet list
                encoded_msg = encoded_msg + (alphabet[1 + alphabet.index(user_inp[i])])
        # if not in alphabet then just passes it through
        else:
            encoded_msg = encoded_msg + user_inp[i]
    return encoded_msg


def alpha_decode(inp):
    decoded_msg = ""
    for i in range(len(inp)):
        # only proceeds if the element is in the alphabet
        if inp[i] in alphabet:
            # turns a to z
            if inp[i] == 'a':
                decoded_msg = decoded_msg + 'z'
            else:
                # finds the index of the specific element, subtracts one then pulls that number from the alphabet list
                decoded_msg = decoded_msg + (alphabet[alphabet.index(inp[i]) - 1])
                # if not in alphabet then just passes it through
        else:
            decoded_msg = decoded_msg + inp[i]
    return decoded_msg


def generate_md5_hash(file):
        hash_md5 = hashlib.md5()
        hash_md5.update(file.encode('utf-8'))
        return hash_md5.hexdigest()


def user_interface():
    aes_key = get_random_bytes(16)
    print('\nWelcome to Encryption or Decryption Program.')
    mode = input("Encryption press 1 and Decryption press 2")
    if mode == '1':
        filename = input("Please enter the name of the text file you want to encrypt: ")
        file_content = read_file(filename)
        print("\nChoose the encryption method:")
        print("1. MD5 Hash (Note: This is not reversible, not suitable for encryption)")
        print("2. AES Encryption")
        print("3. Simple Alphabet Shift Encode")
        print("4. asdasdasdasdasd")
        choice = input("Your choice (1/2/3/4): ")

        if choice == "1":
            hash_result = generate_md5_hash(file_content)
            print("MD5 Hash of the file content:", hash_result)
            write_file("Hashed_" + filename, hash_result)
        elif choice == '2':
            aes_cipher = AESCipher(aes_key)
            encrypted_data = aes_cipher.encrypt(file_content)
            with open("AES_encrypted_" + filename, 'wb') as file:
                file.write(encrypted_data)
            print("File has been encrypted.")
        elif choice == '3':
            encoded_message = alpha_encode(file_content)
            write_file("alpha_encoded_" + filename, encoded_message)
            print("File content has been encoded.")
        elif choice == "4":
            pass
        else:
            print("Invalid choice. Please run the program again.")

    elif mode == "2":
        filename = input("Please enter the name of the file you want to decrypt: ")
        file_content = read_file(filename)
        print("\nChoose the decryption method:")
        print("1. AES Decryption")
        print("2. Simple Alphabet Shift Encode")
        print("3. Hash Decryption")
        choice = input("Your choice (1/2/3/4): ")
        if choice == '1':
            aes_cipher = AESCipher(aes_key)
            try:
                decrypted_data = aes_cipher.decrypt(file_content)
                new_filename = "AES_decrypted_" + filename.replace("encrypted_", "")
                write_file(new_filename, decrypted_data, is_binary=False)
                print("File has been decrypted.")
            except Exception as e:
                print(f"Decryption failed: {e}")
        elif choice == '2':
            encoded_message = alpha_decode(file_content)
            write_file("alpha_decoded_" + filename, encoded_message)
            print("File content has been encoded.")
        elif choice == "3":
            file_hash = generate_md5_hash(file_content)
            user_hash = input("Please enter the MD5 hash values to be compared: ")
            if user_hash == file_hash:
                print("Hash matches, file not modified。")
            else:
                print("Hash value does not match, file may have been modified。")
        elif choice == "4":
            pass
        else:
            print("Invalid choice. Please run the program again.")

    else:
        print("Invalid choice. Please run the program again.")


if __name__ == "__main__":
    user_interface()
