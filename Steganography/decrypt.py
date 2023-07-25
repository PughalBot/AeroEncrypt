from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

app = input("Enter the app name to retrieve the password: ")

##################### File Handling #####################

key = RSA.import_key(open("private_key.pem").read())

file_in = open("encrypted_data.bin", "rb")
enc_session_key, AESnonce, tag, ctext = \
    [ file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

##################### Decryption #####################

# Decryption of AES symmetric key using RSA private key
print("Decrypting AES symmetric key....")
RSAcipherdec = PKCS1_OAEP.new(key)
dec_session_key = RSAcipherdec.decrypt(enc_session_key)
print("Done")
print()

# AES decryption of data
print("Decrypting data....")
AEScipherdec = AES.new(dec_session_key, AES.MODE_GCM, AESnonce)
data = AEScipherdec.decrypt_and_verify(ctext, tag)
print("Done")
print()
print("Decrypted data:")
print(data.decode("utf-8"))