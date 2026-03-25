# Secure Password Generator

This repository contains two command-line password generators:

- `password_generator.py`: the recommended implementation for most users
- `password_generator.sh`: a Bash version for shell-only or portability-focused workflows

Both versions use cryptographically secure randomness and support configurable length, character classes, custom character sets, clipboard copy, and estimated entropy output.

## Why Two Versions

Use the Python version if you can. It is simpler to maintain, easier to extend, and the safest default choice for day-to-day use.

Use the Bash version when you specifically want a shell script with minimal runtime requirements beyond standard Unix tools.

## Quick Start

Recommended:

```bash
python3 password_generator.py
```

This generates a 32-character password using uppercase letters, lowercase letters, numbers, and symbols.

Common shortcuts:

```bash
python3 password_generator.py 20
python3 password_generator.py 20 -C
python3 password_generator.py 20 -E
python3 password_generator.py 20 -x
python3 password_generator.py 20 -o "abcdef012345"
python3 password_generator.py 20 -o "aaaabc123" -W
```

Equivalent Bash commands:

```bash
bash password_generator.sh 20
bash password_generator.sh 20 -C
bash password_generator.sh 20 -E
```

## Features

- Cryptographically secure randomness
- Default length of 32 characters
- Automatic inclusion of all character classes when none are specified
- Guaranteed class coverage for selected classes
- Optional exclusion of similar or ambiguous characters
- Custom character sets with safe deduplication by default
- Optional weighted custom character sets
- Clipboard copy mode
- Estimated entropy output
- Multi-password generation

## Safer Defaults

The tools aim to make the common path safe:

- Default output is a 32-character password
- If no class flags are set, all character classes are included
- `--only` deduplicates repeated characters by default so accidental weighting does not weaken output
- `--copy` avoids printing the password directly to the terminal

If you intentionally want repeated characters in `--only` to change selection probability, use `--weighted-only`.

## Python Usage

```bash
# Default 32-character password
python3 password_generator.py

# 24-character password
python3 password_generator.py 24

# Secure preset
python3 password_generator.py --secure

# Copy to clipboard instead of printing
python3 password_generator.py -C

# Show estimated entropy
python3 password_generator.py -E

# Exclude similar characters
python3 password_generator.py 24 -x

# Generate multiple passwords
python3 password_generator.py -n 5 20

# Select specific classes
python3 password_generator.py 24 --uppercase --lowercase --numbers

# Custom character set
python3 password_generator.py 40 -o "0123456789abcdef"

# Weighted custom character set
python3 password_generator.py 40 -o "aaaabc123" -W
```

## Bash Usage

```bash
# Default 32-character password
bash password_generator.sh

# 24-character password
bash password_generator.sh 24

# Secure preset
bash password_generator.sh --secure

# Copy to clipboard instead of printing
bash password_generator.sh -C

# Show estimated entropy
bash password_generator.sh -E

# Exclude similar characters
bash password_generator.sh 24 -x

# Generate multiple passwords
bash password_generator.sh -n 5 20

# Select specific classes
bash password_generator.sh 24 --uppercase --lowercase --numbers

# Custom character set
bash password_generator.sh 40 -o "0123456789abcdef"

# Weighted custom character set
bash password_generator.sh 40 -o "aaaabc123" -W
```

## Options

Both tools support the same core behavior.

- `-l, --length N`: password length
- `-n, --count N`: number of passwords to generate
- `--secure`: enforce a minimum length of 32 and enable all classes if none are selected
- `--uppercase`: include `A-Z`
- `--lowercase`: include `a-z`
- `--numbers`: include `0-9`
- `--symbols`: include punctuation
- `-x, --exclude-similar`: exclude characters such as `O`, `0`, `l`, and `1`, along with ambiguous symbols
- `-o, --only "CHARS"`: use only the supplied characters, with duplicates removed by default
- `-W, --weighted-only`: preserve duplicate characters in `--only`
- `-E, --entropy`: append an estimated entropy value in bits
- `-C, --copy`: copy the generated password to the clipboard instead of printing it; requires `--count 1`

## Security Notes

- Password strength increases with both length and character pool size.
- The entropy shown by `--entropy` is an estimate, not an exact model of the full password-generation process.
- When class coverage is enforced, the estimate should be treated as a practical guide rather than a formal guarantee.
- `--copy` reduces exposure in terminal output, but copied passwords may still be retained by clipboard managers or operating system history.
- The Python version is the recommended implementation for most users.

Practical rule of thumb:

- 16 or more characters with all classes is strong for many uses
- 32 characters is an excellent default for high-entropy passwords and secrets

## Notes

- `--copy` requires `--count 1`
- `--weighted-only` requires `--only`
- If filtering removes every available character, the tools exit with an error
