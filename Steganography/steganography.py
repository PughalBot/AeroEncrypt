#import functions
import sys
import numpy as np
from PIL import Image

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

np.set_printoptions(threshold=sys.maxsize)

#encoding function
def Encode(src, message, dest):

    img = Image.open(src, 'r')
    width, height = img.size
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    total_pixels = array.size//n

    message += "$Aer0"
    enc_message = encrypt(message)
    b_message = ''.join([format(ord(i), "08b") for i in message])
    req_pixels = len(b_message)

    if req_pixels > total_pixels:
        print("ERROR: Need larger file size")

    else:
        index=0
        for p in range(total_pixels):
            for q in range(0, 3):
                if index < req_pixels:
                    array[p][q] = int(bin(array[p][q])[2:9] + b_message[index], 2)
                    index += 1

        array=array.reshape(height, width, n)
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        enc_img.save(dest)
        print("Image Encoded Successfully")


#decoding function
def Decode(src):

    img = Image.open(src, 'r')
    array = np.array(list(img.getdata()))

    if img.mode == 'RGB':
        n = 3
    elif img.mode == 'RGBA':
        n = 4

    total_pixels = array.size//n

    hidden_bits = ""
    for p in range(total_pixels):
        for q in range(0, 3):
            hidden_bits += (bin(array[p][q])[2:][-1])

    hidden_bits = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]

    message = ""
    for i in range(len(hidden_bits)):
        if message[-5:] == "$Aer0":
            break
        else:
            message += chr(int(hidden_bits[i], 2))
    if "$Aer0" in message:
        print("Hidden Message:", message[:-5])
    else:
        print("No Hidden Message Found")

# message encryption function
def encrypt(message):
    print("Generating RSA private and public keys....")
    RSAkey = RSA.generate(2048)
    RSAprivate_key = RSAkey.export_key()
    RSApublic_key = RSAkey.publickey().export_key()

    print("Generating AES symmetric key....")
    AESkey = get_random_bytes(16)
    print()

    AEScipherenc = AES.new(AESkey, AES.MODE_GCM)
    print("Encrypting plain text....")
    ciphertext, tag = AEScipherenc.encrypt_and_digest(message.encode('utf-8'))
    nonce = AEScipherenc.nonce
    print()
    print(f"Cipher text: {ciphertext}")
    print()

    print("Encrypting AES symmetric key....")
    key = RSA.import_key(RSApublic_key)
    RSAcipherenc = PKCS1_OAEP.new(key)
    enc_session_key = RSAcipherenc.encrypt(AESkey)
    print()
    return ciphertext

# message decrypt function
def decrypt():
    key = RSA.import_key(open("private_key.pem").read())

    file_in = open("encrypted_data.bin", "rb")
    enc_session_key, AESnonce, tag, ctext = \
        [ file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

    print("Decrypting AES symmetric key....")
    RSAcipherdec = PKCS1_OAEP.new(key)
    dec_session_key = RSAcipherdec.decrypt(enc_session_key)
    print("Done")
    print()

    print("Decrypting data....")
    AEScipherdec = AES.new(dec_session_key, AES.MODE_GCM, AESnonce)
    data = AEScipherdec.decrypt_and_verify(ctext, tag)
    print("Done")
    print()
    print("Decrypted data:")
    print(data.decode("utf-8"))

#main function
def Stego():
    print("1: Encode")
    print("2: Decode")
    print("Enter your choice: ", end="")

    func = input()

    if func == '1':
        print("Enter Source Image Path: ", end="")
        src = input()
        print("Enter Message to Hide: ", end="")
        message = input()
        print("Enter Destination Image Path: ", end="")
        dest = input()
        print("Encoding...")
        Encode(src, message, dest)

    elif func == '2':
        print("Enter Source Image Path: ", end="")
        src = input()
        print("Decoding...")
        Decode(src)

    else:
        print("ERROR: Invalid option chosen")

Stego()