from base64 import b64encode, b64decode
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

with open('./userPasswordEncryptionAES256-DO-NOT-REMOVE-THIS.key')as f:
    key = f.read()

def aes_encrypt(data, key=key):
    # 使用SHA256对密钥进行哈希以生成一个32字节（256位）的密钥
    key = hashlib.sha256(key.encode()).digest()

    # 生成一个随机的16字节（128位）的初始向量
    iv = get_random_bytes(16)

    # 使用AES256加密算法和CBC模式进行加密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data.encode())

    # 将初始向量和加密后的数据拼接在一起，以便稍后解密
    encrypted_data = b64encode(iv + encrypted_data).decode('utf-8')

    return encrypted_data

def aes_decrypt(encrypted_data, key=key):
    # 将加密后的数据从Base64解码
    encrypted_data = b64decode(encrypted_data.encode('utf-8'))

    # 获取初始向量
    iv = encrypted_data[:16]

    # 使用AES256加密算法和CBC模式进行解密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data[16:])

    return decrypted_data.decode('utf-8')

import hashlib

def sha512_encrypt(data):
    sha512 = hashlib.sha512()
    sha512.update(data.encode('utf-8'))
    return sha512.hexdigest()

