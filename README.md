# 🔑 Secure Password Generator (Python & Bash)

This repository contains two implementations of a **secure, configurable password generator**:

- **`password_generator.py`** – Python CLI version, recommended as the default implementation
- **`password_generator.sh`** – Bash CLI version for portability and shell-only environments

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
  Duplicate characters are removed by default to avoid accidental weighting.

- **Optional weighted charset (`--weighted-only`)**
  - Preserves duplicate characters in `--only`
  - Useful when you intentionally want repeated characters to change selection weighting

- **Multiple passwords (`-n, --count`)**  
  Generate more than one password at a time.

- **Optional entropy estimate (`--entropy`)**
  - Appends an approximate entropy value in bits to each generated password
  - Useful for quickly understanding relative password strength

- **Clipboard output (`--copy`)**
  - Copies the generated password to the system clipboard instead of printing it directly
  - Requires `--count 1`

---

## ⚙️ Defaults

- **Default run (no arguments):**  
  Generates a **32-character password** using **all classes**.  

- **Secure preset (`--secure`):**  
  Ensures **length ≥ 32** and all classes enabled (unless `--only` is used).

---

## 🚀 Usage

### Python version
Recommended for most use cases.
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

# Custom charset with intentional weighting
python password_generator.py -l 40 --only "aaaabc123" --weighted-only

# Show estimated entropy
python password_generator.py --entropy

# Copy to clipboard instead of printing
python password_generator.py --copy
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

# Custom charset with intentional weighting
bash password_generator.sh -l 40 --only "aaaabc123" --weighted-only

# Show estimated entropy
bash password_generator.sh --entropy

# Copy to clipboard instead of printing
bash password_generator.sh --copy
```
---
## 🔒 Notes on Security

- Password entropy grows with length and charset size.
- When `--entropy` is used, the displayed value is an **estimate** based on password length and the effective character pool size.
- By default, repeated characters in `--only` are deduplicated. When `--weighted-only` is used, repeated characters are treated as weighting and the estimate reflects that weighted pool.
- Because both generators also guarantee class coverage, the estimate should be treated as a practical guide rather than an exact mathematical value.
- `--copy` helps keep generated passwords out of terminal output, but clipboard managers or OS history tools may still retain copied values.

- As a rule of thumb:
    - ≥16 chars with all classes → strong
    - ≥32 chars → highly secure and suitable as a default

Both versions use cryptographically secure randomness for generating credentials, tokens, or other secrets, with the Python implementation recommended for most users.

---
## ⚡ Simpler Commands

The most common commands now have shorter forms:

- `python password_generator.py 20` → 20-character password
- `python password_generator.py 20 -C` → copy a 20-character password to the clipboard
- `python password_generator.py 20 -E` → show estimated entropy
- `python password_generator.py 20 -o "abcdef012345"` → use a custom charset
- `python password_generator.py 20 -o "aaaabc123" -W` → use a weighted custom charset

The Bash version supports the same shortcuts:

- `bash password_generator.sh 20`
- `bash password_generator.sh 20 -C`
- `bash password_generator.sh 20 -E`
