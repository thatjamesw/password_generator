#!/usr/bin/env python3
"""
Secure Password Generator (CLI)

Examples:
  # Default: 32-char password with all classes
  python password_generator.py

  # Secure preset (>=32 chars, all classes)
  python password_generator.py --secure

  # Multiple passwords, exclude confusing characters like O/0/1/l
  python password_generator.py -n 5 -l 24 --uppercase --lowercase --numbers --symbols --exclude-similar

  # 40 chars, custom charset only (hex)
  python password_generator.py -l 40 --only "0123456789abcdef"
"""

from __future__ import annotations

import argparse
from collections import Counter
import math
import secrets
import string
import subprocess
import sys
from typing import List

# Characters often considered "confusing" or ambiguous in certain fonts/contexts
SIMILAR_CHARS = set("Il1O0B8G6S5Z2")
AMBIGUOUS_SYMBOLS = set("{}[]()/\\'\"`~,;:.<>")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate cryptographically secure passwords with configurable character classes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Core options
    p.add_argument(
        "-l", "--length",
        type=int,
        default=32,  # Default changed to 32
        help="Password length."
    )
    p.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="How many passwords to generate."
    )
    p.add_argument(
        "positional_length",
        nargs="?",
        type=int,
        help="Optional positional password length shortcut."
    )
    p.add_argument(
        "--secure",
        action="store_true",
        help="Secure preset: length>=32 and all classes enabled. You may still override --length."
    )

    # Character classes (opt-in flags; if none specified, default to ALL)
    p.add_argument("--uppercase", action="store_true", help="Include uppercase letters A–Z.")
    p.add_argument("--lowercase", action="store_true", help="Include lowercase letters a–z.")
    p.add_argument("--numbers",   action="store_true", help="Include digits 0–9.")
    p.add_argument("--symbols",   action="store_true", help="Include punctuation symbols.")

    # Refinements
    p.add_argument(
        "-x", "--exclude-similar",
        action="store_true",
        help="Exclude easily confused characters (e.g., O/0, l/1, S/5) and certain ambiguous symbols."
    )
    p.add_argument(
        "-o", "--only",
        type=str,
        default="",
        help="Optional explicit character set override. Duplicates are removed unless --weighted-only is used."
    )
    p.add_argument(
        "-W", "--weighted-only",
        action="store_true",
        help="Preserve duplicate characters in --only so repeated chars act as weighting."
    )
    p.add_argument(
        "-E", "--entropy",
        action="store_true",
        help="Append an estimated entropy value in bits to each generated password."
    )
    p.add_argument(
        "-C", "--copy",
        action="store_true",
        help="Copy the generated password to the clipboard instead of printing it. Requires --count 1."
    )

    return p

def filtered_charset(chars: str, exclude_similar: bool, preserve_duplicates: bool = False) -> List[str]:
    filtered: List[str] = []
    seen = set()
    for char in chars:
        if exclude_similar and (char in SIMILAR_CHARS or char in AMBIGUOUS_SYMBOLS):
            continue
        if not preserve_duplicates and char in seen:
            continue
        filtered.append(char)
        seen.add(char)
    return filtered

def get_class_pools(args: argparse.Namespace) -> List[List[str]]:
    # If --only is provided, we skip class logic entirely
    if args.only:
        custom = filtered_charset(args.only, args.exclude_similar, preserve_duplicates=args.weighted_only)
        if not custom:
            raise ValueError("The provided --only charset is empty after filtering.")
        return [custom]

    # Determine which classes are "chosen"
    class_flags_provided = any([args.uppercase, args.lowercase, args.numbers, args.symbols])

    uppercase = args.uppercase or not class_flags_provided
    lowercase = args.lowercase or not class_flags_provided
    numbers   = args.numbers   or not class_flags_provided
    symbols   = args.symbols   or not class_flags_provided

    pools: List[List[str]] = []

    if uppercase:
        pools.append(filtered_charset(string.ascii_uppercase, args.exclude_similar))
    if lowercase:
        pools.append(filtered_charset(string.ascii_lowercase, args.exclude_similar))
    if numbers:
        pools.append(filtered_charset(string.digits, args.exclude_similar))

    if symbols:
        # Start with string.punctuation; remove ambiguous symbols if requested
        sym = set(string.punctuation)
        if args.exclude_similar:
            sym -= AMBIGUOUS_SYMBOLS
        pools.append(list(sorted(sym)))

    # Safety check that none of the pools are empty
    pools = [pool for pool in pools if len(pool) > 0]

    if not pools:
        raise ValueError("No characters available to build a password. Adjust flags or --only.")
    return pools

def generate_password(length: int, pools: List[List[str]]) -> str:
    """
    Guarantees at least one character from each provided pool, then fills the remainder
    from the combined pool. Uses 'secrets' for cryptographic randomness.
    """
    if length < len(pools):
        raise ValueError(
            f"Length {length} is too short for the number of required classes ({len(pools)})."
        )

    rand = secrets.SystemRandom()

    # Pick at least one from each pool
    required = [secrets.choice(pool) for pool in pools]

    # Fill remaining from union of all pools
    all_chars: List[str] = [c for pool in pools for c in pool]
    remaining = [secrets.choice(all_chars) for _ in range(length - len(required))]

    # Shuffle to avoid predictable placement of required characters
    pwd_chars = required + remaining
    rand.shuffle(pwd_chars)
    return "".join(pwd_chars)

def estimate_entropy_bits(length: int, pools: List[List[str]]) -> float:
    """
    Return an approximate entropy estimate in bits.

    This uses the weighted combined character pool and does not try to exactly
    model the class-coverage constraint.
    """
    all_chars = [c for pool in pools for c in pool]
    if length <= 0 or not all_chars:
        return 0.0

    counts = Counter(all_chars)
    total = len(all_chars)
    bits_per_char = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return length * bits_per_char

def copy_to_clipboard(text: str) -> None:
    clipboard_commands = [
        ["pbcopy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip"],
    ]

    for command in clipboard_commands:
        try:
            subprocess.run(command, input=text, text=True, check=True, capture_output=True)
            return
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else "clipboard command failed"
            raise SystemExit(f"Error: unable to copy password to clipboard: {stderr}") from exc

    raise SystemExit(
        "Error: no supported clipboard command found. Install pbcopy, xclip, xsel, or clip."
    )

def enforce_secure_preset(args: argparse.Namespace) -> None:
    # Secure preset => ensure robust defaults
    if args.secure:
        if args.length < 32:     # Enforce minimum 32 when --secure
            args.length = 32
        # If user didn’t explicitly choose classes or --only, enable all
        if not any([args.uppercase, args.lowercase, args.numbers, args.symbols, bool(args.only)]):
            args.uppercase = args.lowercase = args.numbers = args.symbols = True

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.positional_length is not None:
        args.length = args.positional_length

    # Apply secure preset (may still be overridden by explicit flags)
    enforce_secure_preset(args)

    pools = get_class_pools(args)

    # Practical sanity checks
    if args.length <= 0:
        raise SystemExit("Error: --length must be a positive integer.")
    if args.count <= 0:
        raise SystemExit("Error: --count must be a positive integer.")
    if args.weighted_only and not args.only:
        raise SystemExit("Error: --weighted-only requires --only.")
    if args.copy and args.count != 1:
        raise SystemExit("Error: --copy requires --count 1.")

    try:
        entropy_bits = estimate_entropy_bits(args.length, pools) if args.entropy else None
        for _ in range(args.count):
            password = generate_password(args.length, pools)
            if args.copy:
                copy_to_clipboard(password)
                if entropy_bits is None:
                    print("Password copied to clipboard.")
                else:
                    print(f"Password copied to clipboard.\t(est. entropy: {entropy_bits:.2f} bits)")
            elif entropy_bits is None:
                print(password)
            else:
                print(f"{password}\t(est. entropy: {entropy_bits:.2f} bits)")
    except ValueError as e:
        raise SystemExit(f"Error: {e}")

if __name__ == "__main__":
    main()
