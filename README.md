# Encryption CLI

A command-line tool for encrypting and decrypting text and files using AES encryption.

---

## Features

| Command | Input | Cipher |
|---|---|---|
| `encrypt` | text string | AES-128-ECB |
| `decrypt` | text string | AES-128-ECB |
| `encrypt-file` | any file | AES-256-GCM + BIP39 seed phrase |
| `decrypt-file` | `.enc` file | AES-256-GCM + BIP39 seed phrase |

---

## Requirements

- Python 3.8+
- Dependencies in `requirements.txt`

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Encrypt / Decrypt Text

```bash
python encrypt.py encrypt "your message here"
# prompts for a key (must be 16, 24, or 32 bytes)

python encrypt.py decrypt "<hex ciphertext>"
# prompts for the same key
```

---

### Encrypt a File

```bash
python encrypt.py encrypt-file path/to/file.pdf
```

- Prompts for a **12-word BIP39 seed phrase**
- Validates every word against the BIP39 English wordlist (2048 words)
- Validates BIP39 checksum by default (**strict mode**)
- Output: `path/to/file.pdf.enc`

```bash
# Custom output path
python encrypt.py encrypt-file path/to/file.pdf -o path/to/output.enc

# Skip checksum validation (wordlist-only)
python encrypt.py encrypt-file path/to/file.pdf --no-strict
```

---

### Decrypt a File

```bash
python encrypt.py decrypt-file path/to/file.pdf.enc
```

- Prompts for the same 12-word seed phrase used during encryption
- Verifies AES-GCM authentication tag — detects wrong phrase or corrupted file before writing output
- Output: `path/to/file.pdf` (strips `.enc`) or `path/to/file.dec` for other extensions

```bash
# Custom output path
python encrypt.py decrypt-file path/to/file.enc -o path/to/restored.pdf

# Skip checksum validation (must match flag used during encryption)
python encrypt.py decrypt-file path/to/file.enc --no-strict
```

---

## Seed Phrase Validation

By default (**strict mode**), the seed phrase must:

1. Be exactly **12 words**
2. Every word must be in the **BIP39 English wordlist** (2048 words)
3. Pass the **BIP39 checksum** — the 12th word encodes a checksum of the first 11

This means only valid BIP39 mnemonics work — the same phrases used by crypto wallets (MetaMask, Ledger, Trezor, etc.).

With `--no-strict`, only rules 1 and 2 are enforced. Any 12 valid BIP39 words work regardless of checksum.

> Use the same `--no-strict` flag for both encryption and decryption. The key derivation is identical either way, but the validation gate must match.

---

## How File Encryption Works

```
seed phrase
    |
    v
PBKDF2-SHA256(phrase, salt="encryption-cli-v1", iterations=100,000)
    |
    v
32-byte AES-256 key
    |
    v
AES-256-GCM encrypt(file bytes)
    |
    v
.enc file = [16-byte nonce] + [16-byte GCM tag] + [ciphertext]
```

- **AES-256-GCM**: authenticated encryption — wrong key or any file modification is detected before output is written
- **PBKDF2** (100,000 iterations): makes brute-force attacks expensive
- **Random nonce** per encryption: same file + same phrase produces different ciphertext each time

---

## Example Seed Phrases

Valid BIP39 (strict mode):
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Valid words, no checksum (`--no-strict`):
```
apple banana cherry dog elephant fox grape horse island jungle kite lemon
```

> Never use example phrases for real data. Generate a secure phrase with a BIP39-compatible wallet or tool.

---

## Security Notes

- The `encrypt`/`decrypt` text commands use **AES-ECB** — deterministic and not semantically secure. Avoid for sensitive data; use the file commands instead.
- File commands use **AES-GCM** which provides both confidentiality and integrity.
- Your seed phrase is the only key to your data. **There is no recovery mechanism.**
- Do not store your seed phrase in the same location as the encrypted file.
