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
import secrets
import string
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
        "--exclude-similar",
        action="store_true",
        help="Exclude easily confused characters (e.g., O/0, l/1, S/5) and certain ambiguous symbols."
    )
    p.add_argument(
        "--only",
        type=str,
        default="",
        help="Optional explicit character set override (uses only these chars). Bypasses class flags."
    )

    return p

def filtered_charset(chars: str, exclude_similar: bool) -> List[str]:
    s = set(chars)
    if exclude_similar:
        s -= SIMILAR_CHARS
        # Also remove ambiguous symbols if they happen to appear here
        s -= AMBIGUOUS_SYMBOLS
    return list(sorted(s))

def get_class_pools(args: argparse.Namespace) -> List[List[str]]:
    # If --only is provided, we skip class logic entirely
    if args.only:
        custom = filtered_charset(args.only, args.exclude_similar)
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

    # Apply secure preset (may still be overridden by explicit flags)
    enforce_secure_preset(args)

    pools = get_class_pools(args)

    # Practical sanity checks
    if args.length <= 0:
        raise SystemExit("Error: --length must be a positive integer.")
    if args.count <= 0:
        raise SystemExit("Error: --count must be a positive integer.")

    try:
        for _ in range(args.count):
            print(generate_password(args.length, pools))
    except ValueError as e:
        raise SystemExit(f"Error: {e}")

if __name__ == "__main__":
    main()
