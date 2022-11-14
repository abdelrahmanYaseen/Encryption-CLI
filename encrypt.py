from Crypto.Cipher import AES
import typer
import binascii
from getpass import getpass

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)
def unpad(ct):
    return ct[:-ord(ct[-1])]

app = typer.Typer()

@app.command()
def encrypt(msg):
    key = getpass("Key: ")
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    msg_en = cipher.encrypt(pad(msg).encode())
    to_save = binascii.hexlify(msg_en).decode()
    print("Result:", to_save)
    return to_save

@app.command()
def decrypt(msg):
    key = getpass("Key: ")
    decipher = AES.new(key.encode(), AES.MODE_ECB)
    msg_dec = unpad(decipher.decrypt(binascii.unhexlify(msg)).decode())
    print("Result:", msg_dec)
    return msg_dec


if __name__ == '__main__':
    app()

