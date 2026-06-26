from Crypto.Cipher import AES
import typer
import binascii
import hashlib
from getpass import getpass
from pathlib import Path
from typing import Optional
from mnemonic import Mnemonic

_mnemo = Mnemonic("english")

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)
def unpad(ct):
    return ct[:-ord(ct[-1])]

def _read_phrase(phrase_file: Optional[str]) -> str:
    if phrase_file:
        p = Path(phrase_file)
        if not p.exists():
            typer.echo(f"Error: phrase file not found: {phrase_file}", err=True)
            raise typer.Exit(1)
        words = [w.strip() for w in p.read_text().splitlines() if w.strip()]
        return " ".join(words)
    return getpass("12-word seed phrase: ")

def _derive_key(phrase: str, strict: bool = True) -> bytes:
    words = phrase.strip().split()
    if len(words) != 12:
        typer.echo(f"Error: seed phrase must be exactly 12 words (got {len(words)})", err=True)
        raise typer.Exit(1)

    wordlist = set(_mnemo.wordlist)
    invalid = [w for w in words if w not in wordlist]
    if invalid:
        typer.echo(f"Error: not in BIP39 wordlist: {', '.join(invalid)}", err=True)
        raise typer.Exit(1)

    if strict and not _mnemo.check(phrase.strip()):
        typer.echo("Error: invalid BIP39 checksum (phrase fails strict validation). Use --no-strict to bypass.", err=True)
        raise typer.Exit(1)

    return hashlib.pbkdf2_hmac("sha256", phrase.strip().encode(), b"encryption-cli-v1", 100_000)

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

@app.command("encrypt-file")
def encrypt_file(
    filepath: str,
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path (default: <file>.enc)"),
    no_strict: bool = typer.Option(False, "--no-strict", help="Accept any BIP39 words without checksum validation"),
    phrase_file: Optional[str] = typer.Option(None, "--phrase-file", "-f", help="Path to txt file with one word per line"),
):
    """Encrypt a file using a 12-word BIP39 seed phrase (AES-256-GCM)."""
    src = Path(filepath)
    if not src.exists():
        typer.echo(f"Error: file not found: {filepath}", err=True)
        raise typer.Exit(1)

    phrase = _read_phrase(phrase_file)
    key = _derive_key(phrase, strict=not no_strict)

    data = src.read_bytes()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    dest = Path(output) if output else src.with_suffix(src.suffix + ".enc")
    dest.write_bytes(cipher.nonce + tag + ciphertext)
    typer.echo(f"Encrypted: {dest}")

@app.command("decrypt-file")
def decrypt_file(
    filepath: str,
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path (default: strips .enc or appends .dec)"),
    no_strict: bool = typer.Option(False, "--no-strict", help="Accept any BIP39 words without checksum validation"),
    phrase_file: Optional[str] = typer.Option(None, "--phrase-file", "-f", help="Path to txt file with one word per line"),
):
    """Decrypt a file using a 12-word BIP39 seed phrase (AES-256-GCM)."""
    src = Path(filepath)
    if not src.exists():
        typer.echo(f"Error: file not found: {filepath}", err=True)
        raise typer.Exit(1)

    phrase = _read_phrase(phrase_file)
    key = _derive_key(phrase, strict=not no_strict)

    raw = src.read_bytes()
    if len(raw) < 32:
        typer.echo("Error: file too small to be a valid encrypted file", err=True)
        raise typer.Exit(1)

    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        typer.echo("Error: decryption failed — wrong seed phrase or corrupted file", err=True)
        raise typer.Exit(1)

    if output:
        dest = Path(output)
    elif src.suffix == ".enc":
        dest = src.with_suffix("")
    else:
        dest = src.with_suffix(src.suffix + ".dec")

    dest.write_bytes(plaintext)
    typer.echo(f"Decrypted: {dest}")


if __name__ == '__main__':
    app()

