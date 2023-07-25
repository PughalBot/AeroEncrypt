from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

##################### Encryption #####################

# Generate private and public RSA keys
# print("Generating RSA private and public keys....")
RSAkey = RSA.generate(2048)
RSAprivate_key = RSAkey.export_key()
RSApublic_key = RSAkey.publickey().export_key()
# print("Done")
# print()

# Generate symmetric AES key
# print("Generating AES symmetric key....")
AESkey = get_random_bytes(16)
# print("Done")
print()

# AES encryption of the data
password = input("Enter plaintext: ")
AEScipherenc = AES.new(AESkey, AES.MODE_GCM)
# print("Encrypting plain text....")
ciphertext, tag = AEScipherenc.encrypt_and_digest(password.encode('utf-8'))
nonce = AEScipherenc.nonce
# print("Done")
print()
print(f"Cipher text: {ciphertext}")
print()

# Encryption of AES symmetric key using RSA public key
# print("Encrypting AES symmetric key....")
key = RSA.import_key(RSApublic_key)
RSAcipherenc = PKCS1_OAEP.new(key)
enc_session_key = RSAcipherenc.encrypt(AESkey)
# print("Done")
print()