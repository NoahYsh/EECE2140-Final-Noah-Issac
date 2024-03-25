from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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
        # 将IV添加到加密数据前面，以便解密时使用
        return iv + encrypted_data

    def decrypt(self, encrypted_data):
        #  Extracting IVs from encrypted data
        iv = encrypted_data[:AES.block_size]
        # create decode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # decode
        original_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return original_data.decode()

# Examples
key = get_random_bytes(16)  # AES-128
cipher = AESCipher(key)

encrypted = cipher.encrypt("Hello, AES!")
print("Encrypted:", encrypted)

decrypted = cipher.decrypt(encrypted)
print("Decrypted:", decrypted)
