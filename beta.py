# -*- coding: utf-8 -*-
"""
Main program for EECE2140, Final Noah-Issac
Created by <Noah>,<Issac>
Created on 24-3-27, Wednesday:
"""
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import DES
from pypdf import PdfReader


def read_file(filename):
    if filename.endswith('.txt'):
        clean_lines = []
        opened_file = open(filename, 'r')
        lines = opened_file.readlines()
        # gets ride of \n and appends to clean_lines list
        for i in range(len(lines)):
            clean_lines.append(lines[i].strip())
        opened_file.close()
        return clean_lines
    elif filename.endswith('.pdf'):
        pages = []
        opened_pdf = PdfReader(filename)
        for page in opened_pdf.pages:
            page_text = page.extract_text()
            if page_text:
                pages.append(page_text.replace("\n", " "))
        return ' '.join(pages)
    else:
        raise ValueError("Unsupported file type.")


def write_file(filename, data):
    # data to be added should be formatted in a list. linebreaks will be inserted between indices
    # works best with .txt files, will work with .pdf files but formatting will be poor
    opened_file = open(filename, 'w')
    opened_file.write(str(data))
    opened_file.write("\n")


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        # init iv
        iv = get_random_bytes(AES.block_size)
        # create cipher
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # encode
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        #  Add the IV in front of the encrypted data for use in decryption
        return iv + encrypted_data

    def decrypt(self, encrypted_data):
        #  Extracting IVs from encrypted data
        iv = encrypted_data[:AES.block_size]
        # create decode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # decode
        original_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return original_data.decode()


class DESCipher:
    def __init__(self, key):
        self.key = key
        
    def encrypt(self, msg):
        #creates DES object in Cipher Block Chain mode named cipher
        cipher = DES.new(self.key, DES.MODE_CBC)
        #makes the initialazation vector, its like the key. Could have one set permenatly but using a random one is more secure
        iv = cipher.iv
        #encripts the data after padding it out to ensure the data is a multiple of 64 bits
        ciphertext = cipher.encrypt(pad(msg.encode('ascii'), DES.block_size))
        print("You will need this for decoding. your i.v is: ", iv.hex())
        return ciphertext
    
    def decrypt(self, iv, ciphertext):
        #creates DES object in CBC mode named cipher
        cipher = DES.new(self.key, DES.MODE_CBC, iv=iv)
        #unpads the cipher text and then decodes it
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return plaintext.decode('ascii')


class AlphaCipher:
    # Class attribute for the alphabet
    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                'v', 'w', 'x', 'y', 'z']

    def encode(self, user_inp):
        encoded_msg = ""
        for char in user_inp:
            # Only proceeds if the element is in the alphabet
            if char in self.alphabet:
                # Catches 'z' and turns to 'a'
                if char == 'z':
                    encoded_msg += 'a'
                else:
                    # Finds the index of the specific element, adds one and then pull
                    encoded_msg += self.alphabet[1 + self.alphabet.index(char)]
            # If not in alphabet then just passes it through
            else:
                encoded_msg += char
        return encoded_msg

    def decode(self, inp):
        decoded_msg = ""
        for char in inp:
            # Only proceeds if the element is in the alphabet
            if char in self.alphabet:
                # Turns 'a' to 'z'
                if char == 'a':
                    decoded_msg += 'z'
                else:
                    # Finds the index of the specific element, subtracts one and then pull
                    decoded_msg += self.alphabet[self.alphabet.index(char) - 1]
                    # If not in alphabet then just passes it through
            else:
                decoded_msg += char
        return decoded_msg


def generate_md5_hash(file):
        hash = hashlib.md5()
        hash.update(file.encode('utf-8'))
        return hash.hexdigest()


def user_interface():
    aes_key = get_random_bytes(16)
    des_key = b'testerma'
    print(des_key)
    print('\nWelcome to Encryption or Decryption Program.')
    mode = input("Encryption press 1 and Decryption press 2: ")
    if mode == '1':
        filename = input("Please enter the name of the text file you want to encrypt: ")
        file_content = read_file(filename)
        content_string = ' '.join(file_content)
        print("\nChoose the encryption method:")
        print("1. MD5 Hash (Note: This is not reversible, not suitable for encryption)")
        print("2. AES Encryption")
        print("3. Simple Alphabet Shift Encode")
        print("4. DES Encryption")
        choice = input("Your choice (1/2/3/4): ")

        if choice == "1":
            hash_result = generate_md5_hash(content_string)
            print("MD5 Hash of the file content:", hash_result)
            write_file("Hashed_" + filename, hash_result)
        elif choice == '2':
            cipher = AESCipher(aes_key)
            encrypted = cipher.encrypt(content_string)
            write_file("AES Encryption" + filename, encrypted)
            print("File content has been encoded.")
        elif choice == '3':
            cipher = AlphaCipher()
            encoded_message = cipher.encode(content_string)
            write_file("Alpha_encoded_" + filename, encoded_message)
            print("File content has been encoded.")
        elif choice == "4":
            cipher = DESCipher(des_key)
            ciphertext = cipher.encrypt(content_string)
            write_file("DES Encryption" + filename, ciphertext)
            
        else:
            print("Invalid choice. Please run the program again.")

    elif mode == "2":
        filename = input("Please enter the name of the file you want to decrypt: ")
        file_content = read_file(filename)
        content_string = ' '.join(file_content)
        print("\nChoose the decryption method:")
        print("1. AES Decryption")
        print("2. Simple Alphabet Shift Encode")
        print("3. Hash Decryption")
        print("4. DES Decryption")
        choice = input("Your choice (1/2/3/4): ")

        if choice == '1':
            cipher = AESCipher(aes_key)
            content_bytes = bytes(content_string[2:-1], "utf-8").decode("unicode_escape").encode("raw_unicode_escape")
            decrypted = cipher.decrypt(content_bytes)
            write_file("AES Encryption" + filename, decrypted)
            print("File content has been encoded.")
        elif choice == '2':
            cipher = AlphaCipher()
            encoded_message = cipher.decode(content_string)
            write_file("alpha_decoded_" + filename, encoded_message)
            print("File content has been encoded.")
        elif choice == "3":
            file_hash = generate_md5_hash(content_string)
            user_hash = input("Please enter the MD5 hash values to be compared: ")
            if user_hash == file_hash:
                print("Hash matches, file not modified。")
            else:
                print("Hash value does not match, file may have been modified。")
        elif choice == "4":
            cipher = DESCipher(des_key)
            content_bytes = bytes(content_string[2:-1], "utf-8").decode("unicode_escape").encode("raw_unicode_escape")
            nonce_input = input("Enter iv in hexadecimal format: ")
            nonce = bytes.fromhex(nonce_input)
            decrypted = cipher.decrypt(nonce, content_bytes)
            print(decrypted)
            write_file("DES Encryption" + filename, decrypted)
        else:
            print("Invalid choice. Please run the program again.")

    else:
        print("Invalid choice. Please run the program again.")


if __name__ == "__main__":
    user_interface()    
