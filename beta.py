# -*- coding: utf-8 -*-
"""
Main program for EECE2140, Final Noah-Issac
Created by <Noah>,<Issac>
Created on 24-3-27, Wednesday:
"""
import hashlib
from Crypto.Cipher import AES
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES
from pypdf import PdfReader


def read_file(filename):
    if filename.endswith('.txt'):
        clean_lines = []
        opened_file = open(filename, 'r')
        lines = opened_file.readlines()
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


class MData:
    def __init__(self, data=b"", character_set='utf-8'):
        # data is bytes
        self.data = data
        self.characterSet = character_set

    def from_string(self, data):
        self.data = data.encode(self.characterSet)
        return self.data

    def from_base64(self, data):
        self.data = base64.b64decode(data.encode(self.characterSet))
        return self.data

    def to_string(self):
        return self.data.decode(self.characterSet)

    def to_base64(self):
        return base64.b64encode(self.data).decode()

    def __str__(self):
        try:
            return self.to_string()
        except Exception:
            return self.to_base64()


class AESCipher:
    def __init__(self, key, mode, iv='', padding_mode="NoPadding", character_set="utf-8"):
        self.key = key
        self.mode = mode
        self.iv = iv
        self.characterSet = character_set
        self.paddingMode = padding_mode
        self.data = ""

    def __ZeroPadding(self, data):
        data += b'\x00'
        while len(data) % 16 != 0:
            data += b'\x00'
        return data

    def __StripZeroPadding(self, data):
        data = data[:-1]
        while len(data) % 16 != 0:
            data = data.rstrip(b'\x00')
            if data[-1] != b"\x00":
                break
        return data

    def __PKCS5_7Padding(self, data):
        need_size = 16 - len(data) % 16
        if need_size == 0:
            need_size = 16
        return data + need_size.to_bytes(1, 'little') * need_size

    def __StripPKCS5_7Padding(self, data):
        padding_size = data[-1]
        return data.rstrip(padding_size.to_bytes(1, 'little'))

    def __paddingData(self, data):
        if self.paddingMode == "NoPadding":
            if len(data) % 16 == 0:
                return data
            else:
                return self.__ZeroPadding(data)
        elif self.paddingMode == "ZeroPadding":
            return self.__ZeroPadding(data)
        elif self.paddingMode == "PKCS5Padding" or self.paddingMode == "PKCS7Padding":
            return self.__PKCS5_7Padding(data)
        else:
            print("No Padding")

    def __stripPaddingData(self, data):
        if self.paddingMode == "NoPadding":
            return self.__StripZeroPadding(data)
        elif self.paddingMode == "ZeroPadding":
            return self.__StripZeroPadding(data)

        elif self.paddingMode == "PKCS5Padding" or self.paddingMode == "PKCS7Padding":
            return self.__StripPKCS5_7Padding(data)
        else:
            print("No Padding")

    def decrypt_from_base64(self, entext):
        mdata = MData(character_set=self.characterSet)
        self.data = mdata.from_base64(entext)
        return self.__decrypt()

    def encrypt_from_string(self, data):
        self.data = data.encode(self.characterSet)
        return self.__encrypt()

    def __encrypt(self):
        if self.mode == AES.MODE_CBC:
            aes = AES.new(self.key, self.mode, self.iv)
        elif self.mode == AES.MODE_ECB:
            aes = AES.new(self.key, self.mode)
        else:
            print("No support")
            return

        data = self.__paddingData(self.data)
        data_a = aes.encrypt(data)
        return MData(data_a)

    def __decrypt(self):
        if self.mode == AES.MODE_CBC:
            aes = AES.new(self.key, self.mode, self.iv)
        elif self.mode == AES.MODE_ECB:
            aes = AES.new(self.key, self.mode)
        else:
            print("No support")
            return
        data = aes.decrypt(self.data)
        mdata = MData(self.__stripPaddingData(data), character_set=self.characterSet)
        return mdata


class DESCipher:
    def __init__(self, key):
        self.key = key
        
    def encrypt(self, msg):
        # creates DES object in Cipher Block Chain mode named cipher
        cipher = DES.new(self.key, DES.MODE_CBC)
        # makes the initialization vector, it's like the key.
        # Could have one set permanently but using a random one is more secure
        iv = cipher.iv
        # encrypts the data after padding it out to ensure the data is a multiple of 64 bits
        ciphertext = cipher.encrypt(pad(msg.encode('ascii'), DES.block_size))
        print("You will need this for decoding. your i.v is: ", iv.hex())
        return ciphertext
    
    def decrypt(self, iv, ciphertext):
        # creates DES object in CBC mode named cipher
        cipher = DES.new(self.key, DES.MODE_CBC, iv=iv)
        # unfilled the cipher text and then decodes it
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
    key = b"1234567812345678"
    iv = b"0000000000000000"
    aes = AESCipher(key, AES.MODE_CBC, iv, padding_mode="ZeroPadding", character_set='utf-8')
    des_key = b'testerma'
    print('\nWelcome to Encryption or Decryption Program.')
    mode = input("Encryption press 1 and Decryption press 2: ")
    if mode == '1':
        filename = input("Please enter the name of the text file you want to encrypt: ")
        file_content = read_file(filename)
        content_string = ' '.join(file_content)
        print("\nChoose the encryption method:")
        print("1. MD5 Hash (Note: This is used to verify that your files have not been changed)")
        print("2. AES Encryption")
        print("3. Simple Alphabet Shift Encode")
        print("4. DES Encryption")
        choice = input("Your choice (1/2/3/4): ")

        if choice == "1":
            hash_result = generate_md5_hash(content_string)
            print("MD5 Hash of the file content:", hash_result)
            write_file("Hashed_" + filename, hash_result)
        elif choice == '2':
            data = content_string
            rdata = aes.encrypt_from_string(data)
            write_file("Encode_" + filename, rdata.to_base64())
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
            data = content_string
            rdata = aes.decrypt_from_base64(data)
            write_file("decode_" + filename, rdata)
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
