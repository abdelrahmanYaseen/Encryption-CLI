from Crypto.Cipher import AES
import typer
import binascii
from getpass import getpass

def pad(txt):
    return (16 * (1+ len(txt)//16) - len(txt)) * '`' + txt

def unpad(txt):
    i = 0
    for c in txt:
        if c == '`':
            i+=1
        else:
            break
    return txt[i:]

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

