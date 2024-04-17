from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import base64
import chardet


def detect_encoding(text):
    encodings = ["utf-8", "utf-16", "utf-32", "ascii", "iso-8859-1", "utf-7", "iso-2022", "cp500"]
    result = chardet.detect(text)
    detected_encoding = result['encoding']
    confidence = result['confidence']
    if detected_encoding:
        return detected_encoding, confidence
    else:
        for enc in encodings:
            try:
                text.decode(enc)
                return enc, 1.0
            except UnicodeDecodeError:
                pass
    return None, None


def check_base32(text):
    try:
        base64.b32decode(text.replace(" ", ""))
        return True
    except base64.binascii.Error:
        return False


def check_base64(text):
    text = text.replace(" ", "").replace("\n", "")
    if len(text) % 4 != 0:
        return False
    try:
        decoded_text = base64.b64decode(text)
        print("Decoded text (Base64):", decoded_text.decode())
        return True
    except base64.binascii.Error:
        return False


def check_hash(text):
    algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    for alg in algorithms:
        if len(text) == hashlib.new(alg).digest_size * 2:
            try:
                bytes.fromhex(text)
                return alg
            except ValueError:
                pass
    return None


def decrypt_caesar_cipher(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            code = ord(char)
            code -= shift
            if char.isupper():
                if code < ord('A'):
                    code += 26
            elif char.islower():
                if code < ord('a'):
                    code += 26
            plaintext += chr(code)
        else:
            plaintext += char
    return plaintext


def encrypt_RSA(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def decrypt_RSA(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def calculate_sha256(message):
    hash_object = hashlib.sha256()
    hash_object.update(message)
    return hash_object.digest()


def encrypt_AES(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ciphertext, cipher.nonce


def decrypt_AES(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


text = input("Enter the text you want to identify the encryption or check if it's a hash: ")

encryption = None
caesar_shift = None

if check_base32(text):
    encryption = "Base32"
elif check_base64(text):
    encryption = "Base64"
elif check_hash(text.lower()):
    encryption = "Hash"
else:
    caesar_shift = int(input("Enter the shift for Caesar cipher (0 to 25): "))
    if 0 <= caesar_shift <= 25:
        encryption = "Caesar Cipher"

if encryption:
    print("Type of encryption:", encryption)
    if encryption == "Caesar Cipher":
        decrypted_message = decrypt_caesar_cipher(text, caesar_shift)
        print("Decrypted message:", decrypted_message)
    elif encryption == "Hash":
        hash_algorithm = check_hash(text.lower())
        print(f"The text appears to be a hash of the {hash_algorithm.upper()} algorithm.")
    else:
        decrypt = input("Do you want to decrypt the message? (yes/no): ").lower()
        if decrypt == "yes":
            if encryption == "Base64":
                decoded_text = base64.b64decode(text)
                print("Decoded text:", decoded_text.decode())
            elif encryption == "Base32":
                decoded_text = base64.b32decode(text.replace(" ", ""))
                print("Decoded text:", decoded_text.decode())
            elif encryption == "AES":
                key = bytes.fromhex(input("Enter the AES key in hexadecimal format: "))
                nonce = bytes.fromhex(input("Enter the nonce in hexadecimal format: "))
                ciphertext = bytes.fromhex(text)
                decrypted_message = decrypt_AES(ciphertext, key, nonce)
                print("Decrypted message:", decrypted_message.decode())
            elif encryption == "RSA":
                private_key = RSA.import_key(open("private_key.pem").read())
                ciphertext = bytes.fromhex(text)
                decrypted_message = decrypt_RSA(ciphertext, private_key)
                print("Decrypted message:", decrypted_message.decode())
else:
    print("Type of encryption not identified.")
