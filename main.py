from cryptography.hazmat.primitives import hashes  # 确保导入正确的模块
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # 导入PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from os import urandom
import base64

# 加密函数
def encrypt_message(message, password):
    salt = urandom(16)  # 生成盐值
    iv = urandom(16)    # 随机初始化向量
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # 使用正确的哈希模块
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    ).derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 填充消息
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + encrypted_data).decode()

# 解密函数
def decrypt_message(encrypted_message, password):
    decoded_data = base64.b64decode(encrypted_message)
    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    encrypted_data = decoded_data[32:]

    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # 使用正确的哈希模块
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    ).derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# 测试
if __name__ == "__main__":
    original_message = "这是一个测试消息"
    password = "your_password"

    encrypted = encrypt_message(original_message, password)
    print(f"加密后的消息：{encrypted}")

    decrypted = decrypt_message(encrypted, password)
    print(f"解密后的消息：{decrypted}")
