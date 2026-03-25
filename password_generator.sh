#!/usr/bin/env bash
# Secure Password Generator (Bash)
# - Cryptographically secure: /dev/urandom + rejection sampling (no modulo bias)
# - Class coverage: at least one from each selected class
# - Defaults: 32 chars, all classes
# - Secure preset: --secure enforces length >= 32 and all classes (unless --only is used)

set -euo pipefail

# -------- Character classes --------
UPPER="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER="abcdefghijklmnopqrstuvwxyz"
DIGITS="0123456789"
# Mind the quoting for symbols (kept explicit and comprehensive)
SYMBOLS='!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~'

# Characters often considered "confusing" or ambiguous
SIMILAR="Il1O0B8G6S5Z2"
AMBIGUOUS_SYMBOLS='{}[]()/\'"'"'`~,;:.<>'

# -------- Defaults --------
LENGTH=32
LENGTH_SET=false
COUNT=1
USE_UPPER=
USE_LOWER=
USE_DIGITS=
USE_SYMBOLS=
SHOW_ENTROPY=false
WEIGHTED_ONLY=false
COPY_TO_CLIPBOARD=false
SECURE=false
EXCLUDE_SIMILAR=false
ONLY_SET=""

# -------- Helpers --------

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [options]

Options:
  [LENGTH]                 Optional positional password length shortcut
  -l, --length N           Password length (default: 32)
  -n, --count N            How many passwords to generate (default: 1)
      --secure             Secure preset: min length 32 and all classes enabled (unless --only is used)
      --uppercase          Include uppercase letters A–Z
      --lowercase          Include lowercase letters a–z
      --numbers            Include digits 0–9
      --symbols            Include punctuation symbols
  -x, --exclude-similar    Exclude confusing/ambiguous characters (O/0, l/1, S/5, { } [ ] ( ) etc.)
  -o, --only "CHARS"       Use these characters only; duplicates are removed unless --weighted-only is set
  -W, --weighted-only      Preserve duplicate characters in --only so repeated chars act as weighting
  -E, --entropy            Append an estimated entropy value in bits to each password
  -C, --copy               Copy the generated password to the clipboard instead of printing it (requires --count 1)
  -h, --help               Show this help

Notes:
- If no class flags are provided (and --only is not used), ALL classes are included by default.
- Class coverage is guaranteed: at least one char from each selected class appears in the password.
EOF
}

# Read a 32-bit unsigned int from /dev/urandom
rand_u32() {
  od -An -N4 -tu4 /dev/urandom | awk '{$1=$1;print}'
}

# Uniform random integer in [0, N-1] using rejection sampling to avoid bias
rand_index() {
  local n=$1
  if (( n <= 0 )); then
    echo "0"; return
  fi
  local max=4294967296   # 2^32
  local limit=$(( (max / n) * n ))
  local r
  while :; do
    r=$(rand_u32)
    if (( r < limit )); then
      echo $(( r % n ))
      return
    fi
  done
}

# Return 1 if haystack contains single-character needle, else 0
_contains_char() {
  local needle="$1" hay="$2"
  case "$hay" in
    *"$needle"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Filter chars in $1, removing any character present in $2
filter_chars() {
  local chars="$1" remove="$2"
  local out=""
  local c
  local i
  for (( i=0; i<${#chars}; i++ )); do
    c="${chars:i:1}"
    if ! _contains_char "$c" "$remove"; then
      out+="$c"
    fi
  done
  printf '%s' "$out"
}

dedupe_chars() {
  local chars="$1"
  local out=""
  local c
  local i
  for (( i=0; i<${#chars}; i++ )); do
    c="${chars:i:1}"
    if ! _contains_char "$c" "$out"; then
      out+="$c"
    fi
  done
  printf '%s' "$out"
}

# Build per-class pools as an array of strings (each string is a set of characters)
build_pools() {
  POOLS=() # global array
  if [[ -n "$ONLY_SET" ]]; then
    local custom="$ONLY_SET"
    if $EXCLUDE_SIMILAR; then
      custom="$(filter_chars "$custom" "$SIMILAR$AMBIGUOUS_SYMBOLS")"
    fi
    if ! $WEIGHTED_ONLY; then
      custom="$(dedupe_chars "$custom")"
    fi
    [[ -z "$custom" ]] && { echo "Error: --only charset empty after filtering." >&2; exit 1; }
    POOLS+=("$custom")
    return
  fi

  local any_flag=false
  [[ -n "$USE_UPPER" ]]   && any_flag=true
  [[ -n "$USE_LOWER" ]]   && any_flag=true
  [[ -n "$USE_DIGITS" ]]  && any_flag=true
  [[ -n "$USE_SYMBOLS" ]] && any_flag=true

  local upper lower digits symbols
  if $any_flag; then
    upper="$([[ -n "$USE_UPPER" ]] && echo true || echo false)"
    lower="$([[ -n "$USE_LOWER" ]] && echo true || echo false)"
    digits="$([[ -n "$USE_DIGITS" ]] && echo true || echo false)"
    symbols="$([[ -n "$USE_SYMBOLS" ]] && echo true || echo false)"
  else
    # Default to ALL classes
    upper=true; lower=true; digits=true; symbols=true
  fi

  local s
  if $upper; then
    s="$UPPER"
    $EXCLUDE_SIMILAR && s="$(filter_chars "$s" "$SIMILAR")"
    [[ -n "$s" ]] && POOLS+=("$s")
  fi
  if $lower; then
    s="$LOWER"
    $EXCLUDE_SIMILAR && s="$(filter_chars "$s" "$SIMILAR")"
    [[ -n "$s" ]] && POOLS+=("$s")
  fi
  if $digits; then
    s="$DIGITS"
    $EXCLUDE_SIMILAR && s="$(filter_chars "$s" "$SIMILAR")"
    [[ -n "$s" ]] && POOLS+=("$s")
  fi
  if $symbols; then
    s="$SYMBOLS"
    $EXCLUDE_SIMILAR && s="$(filter_chars "$s" "$AMBIGUOUS_SYMBOLS")"
    [[ -n "$s" ]] && POOLS+=("$s")
  fi

  if ((${#POOLS[@]} == 0)); then
    echo "Error: No characters available after filtering." >&2
    exit 1
  fi
}

# Choose one random character from a set (string)
choose_one() {
  local set="$1"
  local idx
  idx=$(rand_index "${#set}")
  printf '%s' "${set:idx:1}"
}

estimate_entropy_bits() {
  local length="$1"; shift
  local -a pools=( "$@" )
  local all=""
  local p

  for p in "${pools[@]}"; do
    all+="$p"
  done

  if (( length <= 0 || ${#all} <= 0 )); then
    printf '0.00'
    return
  fi

  ALL_CHARS="$all" awk -v pass_len="$length" 'BEGIN {
    all = ENVIRON["ALL_CHARS"]
    total = length(all)
    if (total <= 0) {
      printf "0.00"
      exit
    }

    for (i = 1; i <= total; i++) {
      c = substr(all, i, 1)
      counts[c]++
    }

    bits_per_char = 0
    for (c in counts) {
      p = counts[c] / total
      bits_per_char -= p * (log(p) / log(2))
    }

    printf "%.2f", pass_len * bits_per_char
  }'
}

copy_to_clipboard() {
  local text="$1"

  if command -v pbcopy >/dev/null 2>&1; then
    printf '%s' "$text" | pbcopy
    return
  fi
  if command -v xclip >/dev/null 2>&1; then
    printf '%s' "$text" | xclip -selection clipboard
    return
  fi
  if command -v xsel >/dev/null 2>&1; then
    printf '%s' "$text" | xsel --clipboard --input
    return
  fi
  if command -v clip >/dev/null 2>&1; then
    printf '%s' "$text" | clip
    return
  fi

  echo "Error: no supported clipboard command found. Install pbcopy, xclip, xsel, or clip." >&2
  exit 1
}

# Generate a single password
generate_password() {
  local length="$1"; shift
  local -a pools=( "$@" )

  if (( length < ${#pools[@]} )); then
    echo "Error: --length $length too short for ${#pools[@]} required classes." >&2
    return 1
  fi

  local -a chars=()
  local p

  # One from each pool
  for p in "${pools[@]}"; do
    chars+=( "$(choose_one "$p")" )
  done

  # Build combined set
  local all=""
  for p in "${pools[@]}"; do
    all+="$p"
  done

  # Fill remaining
  local remaining=$(( length - ${#chars[@]} ))
  local i
  for (( i=0; i<remaining; i++ )); do
    chars+=( "$(choose_one "$all")" )
  done

  # Fisher–Yates shuffle
  local j tmp
  for (( i=${#chars[@]}-1; i>0; i-- )); do
    j=$(rand_index $(( i + 1 )))
    tmp="${chars[i]}"; chars[i]="${chars[j]}"; chars[j]="$tmp"
  done

  local out=""
  for i in "${!chars[@]}"; do
    out+="${chars[i]}"
  done
  printf '%s' "$out"
}

# -------- Arg parsing (manual, POSIX-friendly) --------

if [[ $# -eq 0 ]]; then
  : # use defaults (32 chars, all classes)
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--length)        LENGTH="${2:-}"; LENGTH_SET=true; shift 2 ;;
    -n|--count)         COUNT="${2:-}"; shift 2 ;;
    --secure)           SECURE=true; shift ;;
    --uppercase)        USE_UPPER=1; shift ;;
    --lowercase)        USE_LOWER=1; shift ;;
    --numbers)          USE_DIGITS=1; shift ;;
    --symbols)          USE_SYMBOLS=1; shift ;;
    -x|--exclude-similar) EXCLUDE_SIMILAR=true; shift ;;
    -o|--only)          ONLY_SET="${2:-}"; shift 2 ;;
    -W|--weighted-only) WEIGHTED_ONLY=true; shift ;;
    -E|--entropy)       SHOW_ENTROPY=true; shift ;;
    -C|--copy)          COPY_TO_CLIPBOARD=true; shift ;;
    -h|--help)          usage; exit 0 ;;
    --)                 shift; break ;;
    -*)
      echo "Unknown option: $1" >&2
      usage; exit 1 ;;
    *)
      if [[ "$1" =~ ^[0-9]+$ ]] && ! $LENGTH_SET; then
        LENGTH="$1"
        LENGTH_SET=true
        shift
      else
        echo "Unexpected argument: $1" >&2
        usage; exit 1
      fi ;;
  esac
done

# -------- Secure preset enforcement --------
if $SECURE; then
  # Enforce minimum length 32
  if (( LENGTH < 32 )); then LENGTH=32; fi
  # If user didn't explicitly choose classes or provide --only, enable all
  if [[ -z "$ONLY_SET" && -z "$USE_UPPER$USE_LOWER$USE_DIGITS$USE_SYMBOLS" ]]; then
    USE_UPPER=1; USE_LOWER=1; USE_DIGITS=1; USE_SYMBOLS=1
  fi
fi

# -------- Sanity checks --------
[[ "$LENGTH" =~ ^[0-9]+$ ]] || { echo "Error: --length must be a positive integer." >&2; exit 1; }
[[ "$COUNT"  =~ ^[0-9]+$ ]] || { echo "Error: --count must be a positive integer."  >&2; exit 1; }
(( LENGTH > 0 && COUNT > 0 )) || { echo "Error: --length and --count must be > 0." >&2; exit 1; }
if $WEIGHTED_ONLY && [[ -z "$ONLY_SET" ]]; then
  echo "Error: --weighted-only requires --only." >&2
  exit 1
fi
if $COPY_TO_CLIPBOARD && (( COUNT != 1 )); then
  echo "Error: --copy requires --count 1." >&2
  exit 1
fi

# -------- Build pools & generate --------
build_pools

ENTROPY_BITS=""
if $SHOW_ENTROPY; then
  ENTROPY_BITS="$(estimate_entropy_bits "$LENGTH" "${POOLS[@]}")"
fi

for (( c=0; c<COUNT; c++ )); do
  if ! pw="$(generate_password "$LENGTH" "${POOLS[@]}")"; then
    exit 1
  fi
  if $COPY_TO_CLIPBOARD; then
    copy_to_clipboard "$pw"
    if $SHOW_ENTROPY; then
      printf 'Password copied to clipboard.\t(est. entropy: %s bits)\n' "$ENTROPY_BITS"
    else
      echo "Password copied to clipboard."
    fi
  elif $SHOW_ENTROPY; then
    printf '%s\t(est. entropy: %s bits)\n' "$pw" "$ENTROPY_BITS"
  else
    echo "$pw"
  fi
done
