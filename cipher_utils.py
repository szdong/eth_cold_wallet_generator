from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binary_file
import hashlib


# Create key
def make_key(key_path: str):
    key_data = get_random_bytes(32)  # os.urandom(32)  32 * 8 = 256bit https://docs.python.org/3/library/os.html
    binary_file.write(key_path, key_data)


# Encrypt specific files.
def encrypt_file(key_path: str, input_path: str, output_path: str):
    key_data = binary_file.read(key_path)  # Load Key
    input_data = binary_file.read(input_path)  # Load File
    encrypted_data = encrypt(key_data, input_data)  # Encrypt
    binary_file.write(output_path, encrypted_data)


def password_encrypt_file(raw_password: str, input_path: str, output_path: str):
    input_data = binary_file.read(input_path)
    encrypted_data = password_encrypt(raw_password, input_data)
    binary_file.write(output_path, encrypted_data)


def password_encrypt_data(raw_password: str, input_data: str, output_path: str):
    encrypted_data = password_encrypt(raw_password, input_data.encode("utf-8"))
    binary_file.write(output_path, encrypted_data)


def encrypt(key_data: hex, input_data: bytes):
    cipher = AES.new(key_data, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(input_data, AES.block_size))  # Padding : pkcs7
    return cipher.iv + encrypted_data


def password_encrypt(raw_password: str, input_data: hex):
    secret_key = hashlib.sha256(raw_password.encode("utf8")).digest()
    iv = hashlib.md5("default iv".encode("utf8")).digest()  # 16 bytes
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(input_data, AES.block_size))  # Padding : pkcs7
    return cipher.iv + encrypted_data


# Output decrypted file
def decrypt_file(key_path: str, input_path: str, output_path: str):
    key_data = binary_file.read(key_path)  # Load Key
    input_data = binary_file.read(input_path)  # Load File
    original_data = decrypt(key_data, input_data)  # Encrypt
    binary_file.write(output_path, original_data)


def password_decrypt_file(raw_password: str, input_path: str, output_path: str):
    input_data = binary_file.read(input_path)
    original_data = password_decrypt(raw_password, input_data)
    binary_file.write(output_path, original_data)


def password_decrypt_data(raw_password: str, input_path: str):
    input_data = binary_file.read(input_path)
    return password_decrypt(raw_password, input_data).decode("utf-8")


def decrypt(key_data: hex, input_data: hex):
    iv = input_data[0:16]
    encrypted_data = input_data[16:]
    cipher = AES.new(key_data, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)


def password_decrypt(raw_password: str, input_data: hex):
    secret_key = hashlib.sha256(raw_password.encode("utf8")).digest()
    iv = input_data[0:16]
    encrypted_data = input_data[16:]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)
