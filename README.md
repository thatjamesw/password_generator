# 🔑 Secure Password Generator (Python & Bash)

This repository contains two implementations of a **secure, configurable password generator**:

- **`password_generator.py`** – Python CLI version  
- **`password_generator.sh`** – Bash CLI version  

Both provide **cryptographically secure** password generation with flexible options for length, character classes, exclusions, and presets.

---

## ✨ Features

- Cryptographically secure randomness  
  - Python: `secrets` module  
  - Bash: `/dev/urandom` with rejection sampling (avoids modulo bias)

- Configurable **character classes**:
  - `--uppercase` → `A–Z`
  - `--lowercase` → `a–z`
  - `--numbers`   → `0–9`
  - `--symbols`   → punctuation (`!@#$%^&*...`)

- **Secure preset (`--secure`)**
  - Enforces **minimum length of 32**
  - Enables **all classes** (unless you explicitly choose otherwise)

- **Exclude similar (`--exclude-similar`)**
  - Removes easily confused characters:
    ```
    I l 1 O 0 B 8 G 6 S 5 Z 2
    ```
  - Also strips ambiguous symbols when `--symbols` is used:
    ```
    { } [ ] ( ) / \ ' " ` ~ , ; : . <>
    ```

- **Class coverage guarantee**  
  Always includes at least one character from each selected class.

- **Custom charset (`--only "CHARS"`)**  
  Use exactly the characters you provide, bypassing class flags.

- **Multiple passwords (`-n, --count`)**  
  Generate more than one password at a time.

---

## ⚙️ Defaults

- **Default run (no arguments):**  
  Generates a **32-character password** using **all classes**.  

- **Secure preset (`--secure`):**  
  Ensures **length ≥ 32** and all classes enabled (unless `--only` is used).

---

## 🚀 Usage

### Python version
```bash
# Default (32 chars, all classes)
python password_generator.py

# Secure preset (≥32 chars, all classes)
python password_generator.py --secure

# Custom length and classes
python password_generator.py -l 24 --uppercase --lowercase --numbers

# Multiple passwords
python password_generator.py -n 5 -l 20 --symbols --exclude-similar

# Custom charset only (hex)
python password_generator.py -l 40 --only "0123456789abcdef"
```

### Bash Version
```bash
# Default (32 chars, all classes)
bash password_generator.sh

# Secure preset (≥32 chars, all classes)
bash password_generator.sh --secure

# Custom length and classes
bash password_generator.sh -l 24 --uppercase --lowercase --numbers

# Multiple passwords
bash password_generator.sh -n 5

# Custom charset only (hex)
bash password_generator.sh -l 40 --only "0123456789abcdef"
```
---
## 🔒 Notes on Security

- Password entropy grows with length and charset size.

- As a rule of thumb:
    - ≥16 chars with all classes → strong
    - ≥32 chars → highly secure and suitable as a default

Both versions are safe to use for generating credentials, tokens, or other secrets.