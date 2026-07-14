#!/usr/bin/env python3
"""GUI tool that turns any file into encrypted text and emits a decryptor script.

The selected file is read as bytes, converted to Base64 text, encrypted with a
configurable stack of classical ciphers, and written into a standalone Python
script. Running that script asks for the same parameters and reconstructs the
original extension and bytes.
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
import secrets
import wave
import string
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

ALPHABET = string.ascii_letters + string.digits + "+/="
DEFAULT_CIPHER_ORDER = [
    "Caesar",
    "Vigenere",
    "Atbash",
    "Quagmire I",
    "Quagmire II",
    "Quagmire III",
    "Quagmire IV",
    "Enigma",
    "Red",
    "Purple",
    "Green",
]
EXTRA_CIPHERS = [
    "ROT47",
    "Affine",
    "Keyed Caesar",
    "Beaufort",
    "Progressive Caesar",
    "Autokey",
    "Gronsfeld",
    "Rail Fence",
    "Columnar Transposition",
    "Bifid",
    "Trifid",
    "Porta",
    "Trithemius",
    "Alberti",
    "Reverse",
    "Binary",
    "Baconian",
    "Hex",
    "Polybius Square",
    "Morse Code",
    "XOR Stream",
    "RC4 Stream",
    "ADFGVX",
    "Octal",
    "Decimal ASCII",
]
MACHINE_CIPHERS = {"Enigma", "Red", "Purple", "Green"}
EXPANDING_CIPHERS = {
    "Binary",
    "Baconian",
    "Hex",
    "Polybius Square",
    "Morse Code",
    "XOR Stream",
    "RC4 Stream",
    "ADFGVX",
    "Octal",
    "Decimal ASCII",
}
KEYWORD_CIPHERS = {
    "Vigenere",
    "Keyed Caesar",
    "Beaufort",
    "Autokey",
    "Columnar Transposition",
    "Porta",
    "Alberti",
    "XOR Stream",
    "RC4 Stream",
}

TEXT_PREVIEW_LIMIT = 8_000
ENCRYPTED_PREVIEW_LIMIT = 20_000


def detect_preview_kind(data: bytes, path: Path | None = None) -> str:
    """Return the best built-in preview type for file bytes."""
    suffix = path.suffix.lower() if path else ""
    if data.startswith((b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"BM")):
        return "image"
    if (data.startswith(b"RIFF") and data[8:12] == b"WAVE") or suffix in {".wav", ".wave"}:
        return "sound"
    if decode_text_preview(data, limit=512)[0]:
        return "text"
    return "binary"


def decode_text_preview(data: bytes, limit: int = TEXT_PREVIEW_LIMIT) -> tuple[str | None, bool]:
    """Decode bytes for a safe text preview and report whether it was truncated."""
    sample = data[:limit]
    truncated = len(data) > limit
    encodings = ["utf-8"]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    for encoding in encodings:
        try:
            text = sample.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(text):
            return text, truncated
    try:
        text = sample.decode("latin-1")
    except UnicodeDecodeError:
        return None, truncated
    return (text, truncated) if _looks_like_text(text) else (None, truncated)


def _looks_like_text(text: str) -> bool:
    if not text:
        return True
    printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
    return printable / len(text) >= 0.85


def sound_preview_summary(data: bytes) -> str:
    """Return metadata for supported audio previews."""
    try:
        with wave.open(io.BytesIO(data), "rb") as audio:
            frames = audio.getnframes()
            rate = audio.getframerate()
            duration = frames / rate if rate else 0
            return (
                "WAV audio preview\n"
                f"Channels: {audio.getnchannels()}\n"
                f"Sample width: {audio.getsampwidth()} bytes\n"
                f"Sample rate: {rate} Hz\n"
                f"Frames: {frames}\n"
                f"Duration: {duration:.2f} seconds\n\n"
                "Playback is not built into this preview, but the file can be restored and opened in an audio player."
            )
    except wave.Error:
        return "Audio-like file detected, but only WAV metadata preview is supported by the built-in viewer."


def hex_preview(data: bytes, limit: int = 512) -> str:
    sample = data[:limit]
    lines = []
    for offset in range(0, len(sample), 16):
        chunk = sample[offset:offset + 16]
        hex_values = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_values = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_values:<47}  {ascii_values}")
    if len(data) > limit:
        lines.append(f"... truncated after {limit} of {len(data)} bytes ...")
    return "\n".join(lines)


CIPHER_RUNTIME = r'''
import base64
import json
from pathlib import Path

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
ALPHABET_INDEX = {char: index for index, char in enumerate(ALPHABET)}
GRID_CACHE: dict[int, tuple[str, dict[str, int]]] = {}
MACHINE_CIPHERS = {"Enigma", "Red", "Purple", "Green"}
EXPANDING_CIPHERS = {
    "Binary",
    "Baconian",
    "Hex",
    "Polybius Square",
    "Morse Code",
    "XOR Stream",
    "RC4 Stream",
    "ADFGVX",
    "Octal",
    "Decimal ASCII",
}
KEYWORD_CIPHERS = {"Vigenere", "Keyed Caesar", "Beaufort", "Autokey", "Columnar Transposition", "Porta", "Alberti", "XOR Stream", "RC4 Stream"}


def normalized_alphabet(seed: str, alphabet: str = ALPHABET) -> str:
    seen = []
    for char in seed + alphabet:
        if char in alphabet and char not in seen:
            seen.append(char)
    if len(seen) != len(alphabet):
        raise ValueError("keyword alphabet did not normalize correctly")
    return "".join(seen)


def alphabet_index_map(alphabet: str = ALPHABET) -> dict[str, int]:
    if alphabet == ALPHABET:
        return ALPHABET_INDEX
    return {char: index for index, char in enumerate(alphabet)}


def key_indexes(key: str, alphabet: str = ALPHABET) -> list[int]:
    index_map = alphabet_index_map(alphabet)
    values = [index_map[char] for char in key if char in index_map]
    if not values:
        raise ValueError(f"key must contain at least one supported character from {alphabet!r}")
    return values


def param_value(params: dict[str, str], name: str, fallback: str = "key") -> str:
    return params.get(name) or params.get(fallback, "")


def translate_alphabet(text: str, source: str, target: str) -> str:
    table = {src: dst for src, dst in zip(source, target)}
    return "".join(table.get(char, char) for char in text)


def is_ascii_letter(char: str) -> bool:
    return "A" <= char <= "Z" or "a" <= char <= "z"


def shift_letter(char: str, shift: int) -> str:
    if "A" <= char <= "Z":
        return chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
    if "a" <= char <= "z":
        return chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
    return char


def letter_key_shifts(key: str) -> list[int]:
    shifts = [ord(char.upper()) - ord("A") for char in key if is_ascii_letter(char)]
    if not shifts:
        raise ValueError("key must contain at least one letter for this cipher")
    return shifts


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    return "".join(shift_letter(char, shift) for char in text)


def vigenere(text: str, key: str, decrypt: bool = False, alphabet: str = ALPHABET) -> str:
    if alphabet != ALPHABET:
        shifts = key_indexes(key, alphabet)
        index_map = alphabet_index_map(alphabet)
        result = []
        key_position = 0
        alphabet_size = len(alphabet)
        for char in text:
            value = index_map.get(char)
            if value is None:
                result.append(char)
                continue
            shift = shifts[key_position % len(shifts)]
            if decrypt:
                shift = -shift
            result.append(alphabet[(value + shift) % alphabet_size])
            key_position += 1
        return "".join(result)

    shifts = letter_key_shifts(key)
    result = []
    key_position = 0
    for char in text:
        if not is_ascii_letter(char):
            result.append(char)
            continue
        shift = shifts[key_position % len(shifts)]
        if decrypt:
            shift = -shift
        result.append(shift_letter(char, shift))
        key_position += 1
    return "".join(result)

def atbash(text: str) -> str:
    out = []
    for char in text:
        if "A" <= char <= "Z":
            out.append(chr(ord("Z") - (ord(char) - ord("A"))))
        elif "a" <= char <= "z":
            out.append(chr(ord("z") - (ord(char) - ord("a"))))
        else:
            out.append(char)
    return "".join(out)


def rot47(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(char)
    return "".join(out)


def affine(text: str, a: int, b: int, decrypt: bool = False) -> str:
    def inverse(value: int, modulus: int) -> int:
        for candidate in range(modulus):
            if (value * candidate) % modulus == 1:
                return candidate
        raise ValueError(f"{value} has no inverse modulo {modulus}")

    size = len(ALPHABET)
    a_inverse = inverse(a, size) if decrypt else None
    out = []
    for char in text:
        value = ALPHABET_INDEX.get(char)
        if value is None:
            out.append(char)
            continue
        mapped = (a_inverse * (value - b)) % size if decrypt else (a * value + b) % size
        out.append(ALPHABET[mapped])
    return "".join(out)


def keyed_caesar(text: str, key: str, shift: int, decrypt: bool = False) -> str:
    keyed = normalized_alphabet(key)
    if decrypt:
        return translate_alphabet(caesar(text, shift, decrypt=True), keyed, ALPHABET)
    return caesar(translate_alphabet(text, ALPHABET, keyed), shift)


def beaufort(text: str, key: str) -> str:
    shifts = key_indexes(key)
    out = []
    key_position = 0
    alphabet_size = len(ALPHABET)
    for char in text:
        value = ALPHABET_INDEX.get(char)
        if value is None:
            out.append(char)
            continue
        shift = shifts[key_position % len(shifts)]
        out.append(ALPHABET[(shift - value) % alphabet_size])
        key_position += 1
    return "".join(out)


def progressive_caesar(text: str, start: int, step: int, decrypt: bool = False) -> str:
    out = []
    position = 0
    alphabet_size = len(ALPHABET)
    for char in text:
        value = ALPHABET_INDEX.get(char)
        if value is None:
            out.append(char)
            continue
        shift = start + position * step
        if decrypt:
            shift = -shift
        out.append(ALPHABET[(value + shift) % alphabet_size])
        position += 1
    return "".join(out)


def autokey(text: str, key: str, decrypt: bool = False) -> str:
    stream = key_indexes(key)
    out = []
    stream_position = 0
    alphabet_size = len(ALPHABET)
    for char in text:
        value = ALPHABET_INDEX.get(char)
        if value is None:
            out.append(char)
            continue
        shift = stream[stream_position]
        if decrypt:
            plain_value = (value - shift) % alphabet_size
            out.append(ALPHABET[plain_value])
            stream.append(plain_value)
        else:
            out.append(ALPHABET[(value + shift) % alphabet_size])
            stream.append(value)
        stream_position += 1
    return "".join(out)


def gronsfeld(text: str, digits: str, decrypt: bool = False) -> str:
    shifts = [int(char) for char in digits if char.isdigit()]
    if not shifts:
        raise ValueError("Gronsfeld digits must contain at least one number.")
    out = []
    position = 0
    alphabet_size = len(ALPHABET)
    for char in text:
        value = ALPHABET_INDEX.get(char)
        if value is None:
            out.append(char)
            continue
        shift = shifts[position % len(shifts)]
        if decrypt:
            shift = -shift
        out.append(ALPHABET[(value + shift) % alphabet_size])
        position += 1
    return "".join(out)


def rail_fence(text: str, rails: int, offset: int = 0, decrypt: bool = False) -> str:
    if rails < 2:
        raise ValueError("Rail Fence rails must be at least 2.")
    pattern = []
    rail = offset % rails
    direction = 1 if rail == 0 else -1
    for _ in text:
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    if not decrypt:
        return "".join(text[index] for current_rail in range(rails) for index, value in enumerate(pattern) if value == current_rail)
    rail_lengths = [pattern.count(current_rail) for current_rail in range(rails)]
    rail_text = []
    start = 0
    for length in rail_lengths:
        rail_text.append(list(text[start:start + length]))
        start += length
    positions = [0] * rails
    out = []
    for current_rail in pattern:
        out.append(rail_text[current_rail][positions[current_rail]])
        positions[current_rail] += 1
    return "".join(out)


def columnar_transposition(text: str, key: str, decrypt: bool = False) -> str:
    key_values = key_indexes(key)
    width = len(key_values)
    order = sorted(range(width), key=lambda index: (key_values[index], index))
    if not decrypt:
        columns = [text[index::width] for index in range(width)]
        return "".join(columns[index] for index in order)
    base, extra = divmod(len(text), width)
    lengths = [base + (1 if index < extra else 0) for index in range(width)]
    columns = [""] * width
    cursor = 0
    for index in order:
        length = lengths[index]
        columns[index] = text[cursor:cursor + length]
        cursor += length
    out = []
    for row in range(max(lengths, default=0)):
        for column in range(width):
            if row < len(columns[column]):
                out.append(columns[column][row])
    return "".join(out)


def _grid_alphabet(size: int) -> str:
    cached = GRID_CACHE.get(size)
    if cached is not None:
        return cached[0]
    padding = "!#$%&()*,-.:;<>?@[]^_`{|}~" + "\u00a1\u00a2\u00a3\u00a4\u00a5\u00a6\u00a7\u00a8\u00a9\u00aa\u00ab\u00ac\u00ae\u00af"
    grid_chars = list(ALPHABET + "".join(char for char in padding if char not in ALPHABET))
    codepoint = 0x0100
    grid_set = set(grid_chars)
    while len(grid_chars) < size:
        char = chr(codepoint)
        if char not in grid_set and char.isprintable():
            grid_chars.append(char)
            grid_set.add(char)
        codepoint += 1
    grid = "".join(grid_chars[:size])
    GRID_CACHE[size] = (grid, {char: index for index, char in enumerate(grid)})
    return grid


def _grid_index_map(grid: str) -> dict[str, int]:
    return GRID_CACHE[len(grid)][1]


def _replace_grid_chars(text: str, transformed: str, grid: str) -> str:
    iterator = iter(transformed)
    return "".join(next(iterator) if char in grid else char for char in text)


def bifid(text: str, decrypt: bool = False) -> str:
    width = 9
    grid = _grid_alphabet(width * width)
    grid_index = _grid_index_map(grid)
    supported = [char for char in text if char in grid_index]
    if not supported:
        return text
    if not decrypt:
        rows = [grid_index[char] // width for char in supported]
        columns = [grid_index[char] % width for char in supported]
        merged = rows + columns
        transformed = "".join(grid[merged[index] * width + merged[index + 1]] for index in range(0, len(merged), 2))
        return _replace_grid_chars(text, transformed, grid)
    coords = []
    for char in supported:
        value = grid_index[char]
        coords.extend([value // width, value % width])
    midpoint = len(coords) // 2
    transformed = "".join(grid[coords[index] * width + coords[midpoint + index]] for index in range(midpoint))
    return _replace_grid_chars(text, transformed, grid)


def trifid(text: str, decrypt: bool = False) -> str:
    width = 5
    grid = _grid_alphabet(width ** 3)
    grid_index = _grid_index_map(grid)
    supported = [char for char in text if char in grid_index]
    if not supported:
        return text
    if not decrypt:
        layers = []
        rows = []
        columns = []
        for char in supported:
            value = grid_index[char]
            layers.append(value // 25)
            rows.append((value // 5) % 5)
            columns.append(value % 5)
        merged = layers + rows + columns
        transformed = "".join(
            grid[merged[index] * 25 + merged[index + 1] * 5 + merged[index + 2]]
            for index in range(0, len(merged), 3)
        )
        return _replace_grid_chars(text, transformed, grid)
    coords = []
    for char in supported:
        value = grid_index[char]
        coords.extend([value // 25, (value // 5) % 5, value % 5])
    third = len(coords) // 3
    transformed = "".join(
        grid[coords[index] * 25 + coords[third + index] * 5 + coords[third * 2 + index]]
        for index in range(third)
    )
    return _replace_grid_chars(text, transformed, grid)


def porta(text: str, key: str) -> str:
    shifts = [(ord(char.upper()) - ord("A")) // 2 for char in key if is_ascii_letter(char)]
    if not shifts:
        raise ValueError("Porta requires at least one letter in the key.")
    out = []
    key_position = 0
    for char in text:
        if not is_ascii_letter(char):
            out.append(char)
            continue
        base = ord("A") if char.isupper() else ord("a")
        value = ord(char) - base
        shift = shifts[key_position % len(shifts)]
        if value < 13:
            mapped = 13 + ((value + shift) % 13)
        else:
            mapped = (value - 13 - shift) % 13
        out.append(chr(base + mapped))
        key_position += 1
    return "".join(out)


def trithemius(text: str, decrypt: bool = False) -> str:
    out = []
    position = 0
    for char in text:
        if not is_ascii_letter(char):
            out.append(char)
            continue
        shift = position if not decrypt else -position
        out.append(shift_letter(char, shift))
        position += 1
    return "".join(out)


def alberti(text: str, key: str, decrypt: bool = False) -> str:
    inner = normalized_alphabet(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    outer = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = []
    position = 0
    for char in text:
        if not is_ascii_letter(char):
            out.append(char)
            continue
        rotate = position % 26
        rotated_inner = inner[rotate:] + inner[:rotate]
        source, target = (rotated_inner, outer) if decrypt else (outer, rotated_inner)
        upper = char.upper()
        mapped = target[source.index(upper)]
        out.append(mapped if char.isupper() else mapped.lower())
        position += 1
    return "".join(out)


def reverse_text(text: str) -> str:
    return text[::-1]


def binary_text(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(format(ord(char), "08b") for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk, 2)) for chunk in chunks)


def baconian(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(format(ord(char), "08b").replace("0", "a").replace("1", "b") for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk.replace("a", "0").replace("b", "1"), 2)) for chunk in chunks)


def hex_text(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(format(ord(char), "02x") for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk, 16)) for chunk in chunks)


def polybius_square(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(f"{ord(char) // 16:02d}{ord(char) % 16:02d}" for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk[:2]) * 16 + int(chunk[2:])) for chunk in chunks)


def morse_code(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " / ".join(format(ord(char), "08b").replace("0", ".").replace("1", "-") for char in text)
    chunks = [chunk for chunk in text.split(" / ") if chunk]
    return "".join(chr(int(chunk.replace(".", "0").replace("-", "1"), 2)) for chunk in chunks)


def xor_stream(text: str, key: str, decrypt: bool = False) -> str:
    key_values = [ord(char) for char in key]
    if not key_values:
        raise ValueError("XOR Stream requires a non-empty key.")
    if not decrypt:
        return " ".join(format(ord(char) ^ key_values[index % len(key_values)], "02x") for index, char in enumerate(text))
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk, 16) ^ key_values[index % len(key_values)]) for index, chunk in enumerate(chunks))


def rc4_stream(text: str, key: str, decrypt: bool = False) -> str:
    key_bytes = [ord(char) for char in key]
    if not key_bytes:
        raise ValueError("RC4 Stream requires a non-empty key.")

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key_bytes[i % len(key_bytes)]) % 256
        state[i], state[j] = state[j], state[i]

    def keystream():
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + state[i]) % 256
            state[i], state[j] = state[j], state[i]
            yield state[(state[i] + state[j]) % 256]

    stream = keystream()
    if not decrypt:
        return " ".join(format(ord(char) ^ next(stream), "02x") for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk, 16) ^ next(stream)) for chunk in chunks)


def adfgvx(text: str, decrypt: bool = False) -> str:
    symbols = "ADFGVX"
    width = 8
    if not decrypt:
        encoded = []
        for char in text:
            value = ord(char)
            digits = []
            for _ in range(width):
                digits.append(symbols[value % 6])
                value //= 6
            encoded.append("".join(reversed(digits)))
        return " ".join(encoded)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    out = []
    for chunk in chunks:
        if len(chunk) != width or any(char not in symbols for char in chunk):
            raise ValueError("ADFGVX chunks must be 8 symbols drawn from ADFGVX.")
        value = 0
        for char in chunk:
            value = value * 6 + symbols.index(char)
        out.append(chr(value))
    return "".join(out)


def octal_text(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(format(ord(char), "03o") for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk, 8)) for chunk in chunks)


def decimal_ascii(text: str, decrypt: bool = False) -> str:
    if not decrypt:
        return " ".join(str(ord(char)).zfill(3) for char in text)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(int(chunk)) for chunk in chunks)


def quagmire(
    text: str,
    variant: int,
    plain_key: str,
    cipher_key: str,
    indicator_key: str,
    decrypt: bool = False,
) -> str:
    plain = normalized_alphabet(plain_key if variant in {1, 3, 4} else "")
    cipher = normalized_alphabet(cipher_key if variant in {2, 3, 4} else "")
    indicator = normalized_alphabet(indicator_key)
    shifts = key_indexes(indicator_key, indicator)
    out = []
    position = 0
    for char in text:
        if char not in ALPHABET:
            out.append(char)
            continue
        shift = shifts[position % len(shifts)]
        shifted_cipher = cipher[shift:] + cipher[:shift]
        if decrypt:
            out.append(plain[shifted_cipher.index(char)])
        else:
            out.append(shifted_cipher[plain.index(char)])
        position += 1
    return "".join(out)


def plugboard_map(text: str, pairs: str) -> str:
    mapping = {}
    for token in pairs.replace(",", " ").split():
        if len(token) != 2 or token[0] not in ALPHABET or token[1] not in ALPHABET:
            raise ValueError("Plugboard pairs must be two supported characters, for example 'AB CD'.")
        left, right = token
        if left in mapping or right in mapping:
            raise ValueError("Plugboard characters cannot be reused across pairs.")
        mapping[left] = right
        mapping[right] = left
    return "".join(mapping.get(char, char) for char in text)


def parse_enigma_plugboard(pairs: str) -> dict[str, str]:
    mapping = {}
    for token in pairs.replace(",", " ").upper().split():
        if len(token) != 2 or not token.isalpha():
            raise ValueError("Enigma plugboard pairs must be two letters, for example 'AB CD'.")
        left, right = token
        if left == right or left in mapping or right in mapping:
            raise ValueError("Enigma plugboard letters cannot be paired with themselves or reused.")
        mapping[left] = right
        mapping[right] = left
    return mapping


def enigma_machine(
    text: str,
    rotor_positions: str,
    plugboard_pairs: str = "",
    rotor_order: str = "I II III",
    ring_settings: str = "AAA",
    reflector_name: str = "B",
) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rotor_wirings = {
        "I": ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
        "II": ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
        "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
        "IV": ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
        "V": ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
        "VI": ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
        "VII": ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
        "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
        "BETA": ("LEYJVCNIXWPBQMDRTAKZGFUHOS", ""),
        "GAMMA": ("FSOKANUERHMBTIYCWLQPZXVGJD", ""),
    }
    reflectors = {
        "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
        "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
        "B THIN": "ENKQAUYWJICOPBLMDXZVFTHRGS",
        "C THIN": "RDOBJNTKVEHMLFCWZAXGYIPSUQ",
    }
    rotor_names = rotor_order.replace(",", " ").upper().split() or ["I", "II", "III"]
    if len(rotor_names) not in {3, 4} or any(name not in rotor_wirings for name in rotor_names):
        raise ValueError("Enigma rotor order must contain three or four rotors from I-VIII plus optional Beta/Gamma.")
    if len(rotor_names) == 4 and rotor_names[0] not in {"BETA", "GAMMA"}:
        raise ValueError("Enigma M4 mode requires Beta or Gamma as the leftmost fourth rotor.")
    reflector_key = reflector_name.upper().replace("-", " ").strip() or ("B THIN" if len(rotor_names) == 4 else "B")
    if reflector_key not in reflectors:
        raise ValueError("Enigma reflector must be B, C, B Thin, or C Thin.")
    reflector = reflectors[reflector_key]
    defaults = "AAAA" if len(rotor_names) == 4 else "AAA"
    positions_text = "".join(char for char in rotor_positions.upper() if char in alphabet) or defaults
    rings_text = "".join(char for char in ring_settings.upper() if char in alphabet) or defaults
    positions = [(alphabet.index((positions_text + defaults)[index])) for index in range(len(rotor_names))]
    rings = [(alphabet.index((rings_text + defaults)[index])) for index in range(len(rotor_names))]
    plugboard = parse_enigma_plugboard(plugboard_pairs)

    def rotor_forward(value: int, rotor_name: str, position: int, ring: int) -> int:
        wiring = rotor_wirings[rotor_name][0]
        shifted = (value + position - ring) % 26
        wired = alphabet.index(wiring[shifted])
        return (wired - position + ring) % 26

    def rotor_backward(value: int, rotor_name: str, position: int, ring: int) -> int:
        wiring = rotor_wirings[rotor_name][0]
        shifted = (value + position - ring) % 26
        wired = wiring.index(alphabet[shifted])
        return (wired - position + ring) % 26

    def step_rotors() -> None:
        moving_offset = len(rotor_names) - 3
        left = moving_offset
        middle = moving_offset + 1
        right = moving_offset + 2
        if alphabet[positions[middle]] in rotor_wirings[rotor_names[middle]][1]:
            positions[left] = (positions[left] + 1) % 26
            positions[middle] = (positions[middle] + 1) % 26
        elif alphabet[positions[right]] in rotor_wirings[rotor_names[right]][1]:
            positions[middle] = (positions[middle] + 1) % 26
        positions[right] = (positions[right] + 1) % 26

    output = []
    for char in text:
        if char.upper() not in alphabet:
            output.append(char)
            continue
        step_rotors()
        upper = char.upper()
        upper = plugboard.get(upper, upper)
        value = alphabet.index(upper)
        for rotor_index in range(len(rotor_names) - 1, -1, -1):
            value = rotor_forward(value, rotor_names[rotor_index], positions[rotor_index], rings[rotor_index])
        value = alphabet.index(reflector[value])
        for rotor_index in range(len(rotor_names)):
            value = rotor_backward(value, rotor_names[rotor_index], positions[rotor_index], rings[rotor_index])
        upper = plugboard.get(alphabet[value], alphabet[value])
        output.append(upper if char.isupper() else upper.lower())
    return "".join(output)


def parse_purple_settings(switches: str, alphabet_setting: str) -> tuple[int, str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plugboard = (alphabet_setting or "AEIOUYBCDFGHJKLMNPQRSTVWXZ").upper()
    if len(plugboard) != 26 or set(plugboard) != set(alphabet):
        raise ValueError("Purple alphabet must be a 26-letter permutation, e.g. AEIOUYBCDFGHJKLMNPQRSTVWXZ.")
    setting = switches or "1-1,1,1-12"
    try:
        sixes, twenties, speed = setting.split("-")
        twenty_positions = [int(value) for value in twenties.split(",")]
        if len(twenty_positions) != 3 or len(speed) != 2:
            raise ValueError
        values = [int(sixes), *twenty_positions, int(speed[0]), int(speed[1])]
    except ValueError as exc:
        raise ValueError("Purple switches must use syntax like 9-1,24,6-23.") from exc
    if not all(1 <= value <= 25 for value in values[:4]) or not all(1 <= value <= 3 for value in values[4:]):
        raise ValueError("Purple switch positions must be 1-25 and motion switches must be 1-3.")
    if values[4] == values[5]:
        raise ValueError("Purple fast and middle switches must be different.")
    return sum(values), plugboard


def purple_style_machine(text: str, switches: str, alphabet_setting: str, decrypt: bool = False) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shift_seed, plugboard = parse_purple_settings(switches, alphabet_setting)
    inverse_plugboard = {char: alphabet[index] for index, char in enumerate(plugboard)}
    out = []
    for index, char in enumerate(text):
        if char.upper() not in alphabet:
            out.append(char)
            continue
        shift = (shift_seed + index) % 26
        if decrypt:
            wired = shift_letter(char.upper(), -shift)
            mapped = inverse_plugboard[wired]
        else:
            mapped = plugboard[alphabet.index(char.upper())]
            mapped = shift_letter(mapped, shift)
        out.append(mapped if char.isupper() else mapped.lower())
    return "".join(out)


def rotor_machine(
    text: str,
    key: str,
    rotor_positions: str,
    machine: str,
    plugboard_pairs: str = "",
    decrypt: bool = False,
    enigma_rotors: str = "I II III",
    enigma_ring_settings: str = "AAA",
    enigma_reflector: str = "B",
    purple_switches: str = "1-1,1,1-12",
    purple_alphabet: str = "AEIOUYBCDFGHJKLMNPQRSTVWXZ",
) -> str:
    if machine == "Enigma":
        return enigma_machine(text, rotor_positions, plugboard_pairs, enigma_rotors, enigma_ring_settings, enigma_reflector)
    if machine == "Purple":
        return purple_style_machine(text, purple_switches, purple_alphabet, decrypt)

    machine_seeds = {
        "Enigma": "EKMFLGDQVZNTOWYHXUSPAIBRCJ0123456789+/=",
        "Red": "REDTYPEXabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=",
        "Purple": "PURPLESIXESTWENTIESabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=",
        "Green": "GREENJADE0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=",
    }
    rotor_alphabet = normalized_alphabet(machine_seeds[machine] + key)
    rotor_key = (rotor_positions or "A") + key + machine
    return vigenere(text, rotor_key, decrypt=decrypt, alphabet=rotor_alphabet)

def apply_cipher(text: str, cipher: str, params: dict[str, str], decrypt: bool = False) -> str:
    if cipher == "Caesar":
        return caesar(text, int(params["shift"]), decrypt)
    if cipher == "Vigenere":
        return vigenere(text, param_value(params, "vigenere_key"), decrypt)
    if cipher == "Atbash":
        return atbash(text)
    if cipher.startswith("Quagmire"):
        return quagmire(
            text,
            {"Quagmire I": 1, "Quagmire II": 2, "Quagmire III": 3, "Quagmire IV": 4}[cipher],
            params.get("quagmire_plain_key", ""),
            params.get("quagmire_cipher_key", ""),
            params["quagmire_indicator_key"],
            decrypt,
        )
    if cipher in MACHINE_CIPHERS:
        return rotor_machine(
            text,
            param_value(params, "rotor_key"),
            params["rotor_positions"],
            cipher,
            params.get("plugboard_pairs", ""),
            decrypt,
            params.get("enigma_rotors", "I II III"),
            params.get("enigma_ring_settings", "AAA"),
            params.get("enigma_reflector", "B"),
            params.get("purple_switches", "1-1,1,1-12"),
            params.get("purple_alphabet", "AEIOUYBCDFGHJKLMNPQRSTVWXZ"),
        )
    if cipher == "ROT47":
        return rot47(text)
    if cipher == "Affine":
        return affine(text, int(params["affine_a"]), int(params["affine_b"]), decrypt)
    if cipher == "Keyed Caesar":
        return keyed_caesar(text, param_value(params, "keyed_caesar_key"), int(params["shift"]), decrypt)
    if cipher == "Beaufort":
        return beaufort(text, param_value(params, "beaufort_key"))
    if cipher == "Progressive Caesar":
        return progressive_caesar(text, int(params["shift"]), int(params["step"]), decrypt)
    if cipher == "Autokey":
        return autokey(text, param_value(params, "autokey_key"), decrypt)
    if cipher == "Gronsfeld":
        return gronsfeld(text, params["gronsfeld_digits"], decrypt)
    if cipher == "Rail Fence":
        return rail_fence(text, int(params["rails"]), int(params.get("rail_offset", "0") or 0), decrypt)
    if cipher == "Columnar Transposition":
        return columnar_transposition(text, param_value(params, "columnar_key"), decrypt)
    if cipher == "Bifid":
        return bifid(text, decrypt)
    if cipher == "Trifid":
        return trifid(text, decrypt)
    if cipher == "Porta":
        return porta(text, param_value(params, "porta_key"))
    if cipher == "Trithemius":
        return trithemius(text, decrypt)
    if cipher == "Alberti":
        return alberti(text, param_value(params, "alberti_key"), decrypt)
    if cipher == "Reverse":
        return reverse_text(text)
    if cipher == "Binary":
        return binary_text(text, decrypt)
    if cipher == "Baconian":
        return baconian(text, decrypt)
    if cipher == "Hex":
        return hex_text(text, decrypt)
    if cipher == "Polybius Square":
        return polybius_square(text, decrypt)
    if cipher == "Morse Code":
        return morse_code(text, decrypt)
    if cipher == "XOR Stream":
        return xor_stream(text, param_value(params, "stream_key"), decrypt)
    if cipher == "RC4 Stream":
        return rc4_stream(text, param_value(params, "stream_key"), decrypt)
    if cipher == "ADFGVX":
        return adfgvx(text, decrypt)
    if cipher == "Octal":
        return octal_text(text, decrypt)
    if cipher == "Decimal ASCII":
        return decimal_ascii(text, decrypt)
    raise ValueError(f"unknown cipher: {cipher}")


def encrypt_with_ciphers(text: str, ciphers: list[str], params: dict[str, str]) -> str:
    for cipher in ciphers:
        text = apply_cipher(text, cipher, params, decrypt=False)
    return text


def decrypt_with_ciphers(text: str, ciphers: list[str], params: dict[str, str]) -> str:
    for cipher in reversed(ciphers):
        text = apply_cipher(text, cipher, params, decrypt=True)
    return text
'''

exec(CIPHER_RUNTIME, globals())


def validate_params(ciphers: list[str], params: dict[str, str]) -> None:
    selected_expanders = [cipher for cipher in ciphers if cipher in EXPANDING_CIPHERS]
    if len(selected_expanders) > 1:
        raise ValueError(
            "Select at most one text-expanding cipher at a time to avoid huge payloads: "
            + ", ".join(selected_expanders)
        )
    quagmire_ciphers = [cipher for cipher in ciphers if cipher.startswith("Quagmire")]
    if quagmire_ciphers:
        if not params.get("quagmire_indicator_key"):
            raise ValueError("Quagmire ciphers require an indicator key.")
        key_indexes(params["quagmire_indicator_key"])
        if any(cipher in {"Quagmire I", "Quagmire III", "Quagmire IV"} for cipher in quagmire_ciphers):
            key_indexes(params.get("quagmire_plain_key", ""))
        if any(cipher in {"Quagmire II", "Quagmire III", "Quagmire IV"} for cipher in quagmire_ciphers):
            key_indexes(params.get("quagmire_cipher_key", ""))
    key_requirements = {
        "Vigenere": "vigenere_key",
        "Keyed Caesar": "keyed_caesar_key",
        "Beaufort": "beaufort_key",
        "Autokey": "autokey_key",
        "Columnar Transposition": "columnar_key",
        "Porta": "porta_key",
        "Alberti": "alberti_key",
        "XOR Stream": "stream_key",
        "RC4 Stream": "stream_key",
        "Red": "rotor_key",
        "Green": "rotor_key",
    }
    for cipher, key_name in key_requirements.items():
        if cipher in ciphers:
            key_indexes(param_value(params, key_name))
    if "Enigma" in ciphers:
        enigma_machine(
            "",
            params.get("rotor_positions", "AAA"),
            params.get("plugboard_pairs", ""),
            params.get("enigma_rotors", "I II III"),
            params.get("enigma_ring_settings", "AAA"),
            params.get("enigma_reflector", "B"),
        )
    if "Purple" in ciphers:
        parse_purple_settings(
            params.get("purple_switches", "1-1,1,1-12"),
            params.get("purple_alphabet", "AEIOUYBCDFGHJKLMNPQRSTVWXZ"),
        )
    if "Gronsfeld" in ciphers and not any(char.isdigit() for char in params.get("gronsfeld_digits", "")):
        raise ValueError("Gronsfeld requires at least one digit.")
    if "Rail Fence" in ciphers:
        if int(params.get("rails", "0")) < 2:
            raise ValueError("Rail Fence rails must be at least 2.")
        int(params.get("rail_offset", "0") or 0)
    if "Affine" in ciphers:
        a = int(params["affine_a"])
        b = int(params["affine_b"])
        sample = "aZ9+="
        if affine(affine(sample, a, b), a, b, decrypt=True) != sample:
            raise ValueError("Affine parameters failed validation.")


def required_parameter_names(ciphers: list[str]) -> list[str]:
    names: list[str] = []
    quagmire_ciphers = [cipher for cipher in ciphers if cipher.startswith("Quagmire")]
    if quagmire_ciphers:
        if any(cipher in {"Quagmire I", "Quagmire III", "Quagmire IV"} for cipher in quagmire_ciphers):
            names.append("quagmire_plain_key")
        if any(cipher in {"Quagmire II", "Quagmire III", "Quagmire IV"} for cipher in quagmire_ciphers):
            names.append("quagmire_cipher_key")
        names.append("quagmire_indicator_key")
    key_requirements = [
        ("Vigenere", "vigenere_key"),
        ("Keyed Caesar", "keyed_caesar_key"),
        ("Beaufort", "beaufort_key"),
        ("Autokey", "autokey_key"),
        ("Columnar Transposition", "columnar_key"),
        ("Porta", "porta_key"),
        ("Alberti", "alberti_key"),
        ("XOR Stream", "stream_key"),
        ("RC4 Stream", "stream_key"),
        ("Red", "rotor_key"),
        ("Green", "rotor_key"),
    ]
    for cipher, key_name in key_requirements:
        if cipher in ciphers and key_name not in names:
            names.append(key_name)
    if any(cipher in {"Caesar", "Keyed Caesar", "Progressive Caesar"} for cipher in ciphers):
        names.append("shift")
    if any(cipher in MACHINE_CIPHERS for cipher in ciphers):
        names.append("rotor_positions")
    if "Enigma" in ciphers:
        names.extend(["plugboard_pairs", "enigma_rotors", "enigma_ring_settings", "enigma_reflector"])
    if "Purple" in ciphers:
        names.extend(["purple_switches", "purple_alphabet"])
    if "Affine" in ciphers:
        names.extend(["affine_a", "affine_b"])
    if "Progressive Caesar" in ciphers:
        names.append("step")
    if "Gronsfeld" in ciphers:
        names.append("gronsfeld_digits")
    if "Rail Fence" in ciphers:
        names.extend(["rails", "rail_offset"])
    return names


def build_decryptor_script(encrypted_text: str, extension: str, ciphers: list[str]) -> str:
    """Return a standalone Python script containing encrypted file text."""
    return f'''#!/usr/bin/env python3
"""Standalone decryptor generated by file_encryptor_gui.py."""

{CIPHER_RUNTIME}

ORIGINAL_EXTENSION = {extension!r}
CIPHERS = {json.dumps(ciphers)!r}
ENCRYPTED_TEXT = {encrypted_text!r}
REQUIRED_PARAMETERS = {json.dumps(required_parameter_names(ciphers))!r}


def main() -> None:
    print("This script contains an encrypted file payload.")
    print("Cipher stack:", " -> ".join(json.loads(CIPHERS)))
    params = {{}}
    prompts = {{
        "vigenere_key": "Vigenere key used by the encrypter: ",
        "keyed_caesar_key": "Keyed Caesar alphabet key used by the encrypter: ",
        "beaufort_key": "Beaufort key used by the encrypter: ",
        "autokey_key": "Autokey seed key used by the encrypter: ",
        "columnar_key": "Columnar Transposition key used by the encrypter: ",
        "porta_key": "Porta key used by the encrypter: ",
        "alberti_key": "Alberti disk key used by the encrypter: ",
        "stream_key": "XOR/RC4 stream key used by the encrypter: ",
        "rotor_key": "Red/Green rotor key used by the encrypter: ",
        "quagmire_plain_key": "Quagmire plaintext alphabet key used by the encrypter: ",
        "quagmire_cipher_key": "Quagmire ciphertext alphabet key used by the encrypter: ",
        "quagmire_indicator_key": "Quagmire indicator key used by the encrypter: ",
        "shift": "Caesar/keyed shift used by the encrypter: ",
        "rotor_positions": "Rotor positions used by the encrypter: ",
        "plugboard_pairs": "Enigma plugboard pairs used by the encrypter (blank if none): ",
        "enigma_rotors": "Enigma rotor order used by the encrypter (for example I II III): ",
        "enigma_ring_settings": "Enigma ring settings used by the encrypter (for example AAA or AAAA): ",
        "enigma_reflector": "Enigma reflector used by the encrypter (B, C, B Thin, or C Thin): ",
        "purple_switches": "Purple switch settings used by the encrypter (e.g. 9-1,24,6-23): ",
        "purple_alphabet": "Purple plugboard alphabet used by the encrypter: ",
        "affine_a": "Affine multiplier a used by the encrypter: ",
        "affine_b": "Affine shift b used by the encrypter: ",
        "step": "Progressive Caesar step used by the encrypter: ",
        "gronsfeld_digits": "Gronsfeld digit key used by the encrypter: ",
        "rails": "Rail Fence rail count used by the encrypter: ",
        "rail_offset": "Rail Fence starting rail offset used by the encrypter: ",
    }}
    for name in json.loads(REQUIRED_PARAMETERS):
        params[name] = input(prompts[name]).strip()
    default_name = "decrypted_file" + ORIGINAL_EXTENSION
    output_name = input(f"Output file [{{default_name}}]: ").strip() or default_name
    text = decrypt_with_ciphers(ENCRYPTED_TEXT, json.loads(CIPHERS), params)
    Path(output_name).write_bytes(base64.b64decode(text.encode("ascii"), validate=True))
    print(f"Decrypted original file to {{Path(output_name).resolve()}}")


if __name__ == "__main__":
    main()
'''


class FileEncryptionApp(tk.Tk):
    """Small Tkinter GUI for creating encrypted standalone decryptor scripts."""

    def __init__(self) -> None:
        super().__init__()
        self.title("File Encryption Script Builder")
        self.geometry("900x720")
        self.minsize(760, 560)
        self.resizable(True, True)

        self.file_path = tk.StringVar()
        self.shift = tk.StringVar(value=str(secrets.randbelow(len(ALPHABET) - 1) + 1))
        self.step = tk.StringVar(value="1")
        self.rails = tk.StringVar(value="3")
        self.rail_offset = tk.StringVar(value="0")
        self.gronsfeld_digits = tk.StringVar(value="314159")
        self.affine_a = tk.StringVar(value="2")
        self.affine_b = tk.StringVar(value="7")
        generated_key = secrets.token_urlsafe(12).replace("-", "A").replace("_", "B")
        self.vigenere_key = tk.StringVar(value=generated_key)
        self.keyed_caesar_key = tk.StringVar(value=generated_key)
        self.beaufort_key = tk.StringVar(value=generated_key)
        self.autokey_key = tk.StringVar(value=generated_key)
        self.columnar_key = tk.StringVar(value=generated_key)
        self.porta_key = tk.StringVar(value=generated_key)
        self.alberti_key = tk.StringVar(value=generated_key)
        self.stream_key = tk.StringVar(value=generated_key)
        self.rotor_key = tk.StringVar(value=generated_key)
        self.quagmire_plain_key = tk.StringVar(value="PLAINTEXT")
        self.quagmire_cipher_key = tk.StringVar(value="CIPHERTEXT")
        self.quagmire_indicator_key = tk.StringVar(value="INDICATOR")
        self.rotor_positions = tk.StringVar(value="ABC")
        self.plugboard_pairs = tk.StringVar(value="")
        self.enigma_rotors = tk.StringVar(value="I II III")
        self.enigma_ring_settings = tk.StringVar(value="AAA")
        self.enigma_reflector = tk.StringVar(value="B")
        self.purple_switches = tk.StringVar(value="1-1,1,1-12")
        self.purple_alphabet = tk.StringVar(value="AEIOUYBCDFGHJKLMNPQRSTVWXZ")
        self.status = tk.StringVar(value="Choose a file to begin.")
        self.cipher_vars = {name: tk.BooleanVar(value=name in DEFAULT_CIPHER_ORDER) for name in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS}

        self._build_widgets()

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        root = ttk.Frame(self, padding=12)
        root.grid(row=0, column=0, sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        file_frame = ttk.LabelFrame(root, text="Source file")
        file_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        file_frame.columnconfigure(0, weight=1)
        ttk.Entry(file_frame, textvariable=self.file_path).grid(row=0, column=0, sticky="ew", padx=(10, 6), pady=10)
        ttk.Button(file_frame, text="Browse...", command=self.choose_file).grid(row=0, column=1, sticky="e", padx=(0, 6), pady=10)
        ttk.Button(file_frame, text="Preview source", command=self.preview_source_file).grid(row=0, column=2, sticky="e", padx=(0, 10), pady=10)

        content = ttk.PanedWindow(root, orient="vertical")
        content.grid(row=1, column=0, sticky="nsew")

        cipher_frame = ttk.LabelFrame(content, text="Cipher stack (applied top-to-bottom, decrypted in reverse)")
        cipher_frame.columnconfigure(0, weight=1)
        cipher_frame.rowconfigure(1, weight=1)
        content.add(cipher_frame, weight=3)

        toolbar = ttk.Frame(cipher_frame)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
        toolbar.columnconfigure(2, weight=1)
        ttk.Button(toolbar, text="Select defaults", command=lambda: self._set_all_ciphers(False, defaults=True)).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(toolbar, text="Select all", command=lambda: self._set_all_ciphers(True)).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(toolbar, text="Clear all", command=lambda: self._set_all_ciphers(False)).grid(row=0, column=2, sticky="w")

        canvas = tk.Canvas(cipher_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(cipher_frame, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)
        scroll_window = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(0, 10))

        def update_scroll_region(_event: tk.Event | None = None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_scroll_frame(event: tk.Event) -> None:
            canvas.itemconfigure(scroll_window, width=event.width)

        scroll_frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_scroll_frame)

        for column in range(4):
            scroll_frame.columnconfigure(column, weight=1, uniform="cipher")
        for index, cipher in enumerate(DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS):
            row, column = divmod(index, 4)
            ttk.Checkbutton(scroll_frame, text=cipher, variable=self.cipher_vars[cipher]).grid(
                row=row, column=column, sticky="w", padx=8, pady=3
            )

        params_frame = ttk.LabelFrame(content, text="Encryption parameters")
        for column in range(4):
            params_frame.columnconfigure(column, weight=1, uniform="params")
        content.add(params_frame, weight=2)

        fields = [
            ("vigenere_key", "Vigenere key", ttk.Entry(params_frame, textvariable=self.vigenere_key)),
            ("keyed_caesar_key", "Keyed Caesar alphabet key", ttk.Entry(params_frame, textvariable=self.keyed_caesar_key)),
            ("beaufort_key", "Beaufort key", ttk.Entry(params_frame, textvariable=self.beaufort_key)),
            ("autokey_key", "Autokey seed key", ttk.Entry(params_frame, textvariable=self.autokey_key)),
            ("columnar_key", "Columnar Transposition key", ttk.Entry(params_frame, textvariable=self.columnar_key)),
            ("porta_key", "Porta key", ttk.Entry(params_frame, textvariable=self.porta_key)),
            ("alberti_key", "Alberti disk key", ttk.Entry(params_frame, textvariable=self.alberti_key)),
            ("stream_key", "XOR/RC4 stream key", ttk.Entry(params_frame, textvariable=self.stream_key)),
            ("rotor_key", "Red/Green rotor key", ttk.Entry(params_frame, textvariable=self.rotor_key)),
            ("quagmire_plain_key", "Quagmire plaintext key (I, III, IV)", ttk.Entry(params_frame, textvariable=self.quagmire_plain_key)),
            ("quagmire_cipher_key", "Quagmire ciphertext key (II, III, IV)", ttk.Entry(params_frame, textvariable=self.quagmire_cipher_key)),
            ("quagmire_indicator_key", "Quagmire indicator key (I-IV)", ttk.Entry(params_frame, textvariable=self.quagmire_indicator_key)),
            ("shift", "Shift (Caesar, Keyed Caesar, Progressive Caesar)", ttk.Spinbox(params_frame, from_=1, to=len(ALPHABET) - 1, textvariable=self.shift, width=10)),
            ("rotor_positions", "Rotor positions (Enigma, Red, Purple, Green)", ttk.Entry(params_frame, textvariable=self.rotor_positions)),
            ("plugboard_pairs", "Plugboard pairs (Enigma only, e.g. AB CD)", ttk.Entry(params_frame, textvariable=self.plugboard_pairs)),
            ("enigma_rotors", "Rotor order (Enigma only, e.g. I II III)", ttk.Entry(params_frame, textvariable=self.enigma_rotors)),
            ("enigma_ring_settings", "Ring settings (Enigma/M4, e.g. AAA or AAAA)", ttk.Entry(params_frame, textvariable=self.enigma_ring_settings)),
            ("enigma_reflector", "Reflector (Enigma/M4: B, C, B Thin, C Thin)", ttk.Entry(params_frame, textvariable=self.enigma_reflector)),
            ("purple_switches", "Switches (Purple only, e.g. 9-1,24,6-23)", ttk.Entry(params_frame, textvariable=self.purple_switches)),
            ("purple_alphabet", "Plugboard alphabet (Purple only)", ttk.Entry(params_frame, textvariable=self.purple_alphabet)),
            ("affine_a", "Affine a (Affine only, coprime with 65)", ttk.Spinbox(params_frame, from_=1, to=64, textvariable=self.affine_a, width=10)),
            ("affine_b", "Affine b (Affine only)", ttk.Spinbox(params_frame, from_=0, to=64, textvariable=self.affine_b, width=10)),
            ("step", "Progressive step (Progressive Caesar only)", ttk.Spinbox(params_frame, from_=1, to=64, textvariable=self.step, width=10)),
            ("gronsfeld_digits", "Gronsfeld digits (Gronsfeld only)", ttk.Entry(params_frame, textvariable=self.gronsfeld_digits)),
            ("rails", "Rail Fence rails (Rail Fence only)", ttk.Spinbox(params_frame, from_=2, to=20, textvariable=self.rails, width=10)),
            ("rail_offset", "Rail Fence offset (Rail Fence only)", ttk.Spinbox(params_frame, from_=0, to=20, textvariable=self.rail_offset, width=10)),
        ]
        self.parameter_controls = []
        for index, (name, label, widget) in enumerate(fields):
            row = (index // 4) * 2
            column = index % 4
            label_widget = ttk.Label(params_frame, text=label)
            label_widget.grid(row=row, column=column, sticky="w", padx=10, pady=(10, 2))
            widget.grid(row=row + 1, column=column, sticky="ew", padx=10, pady=(0, 10))
            self.parameter_controls.append((name, label_widget, widget))

        for variable in self.cipher_vars.values():
            variable.trace_add("write", lambda *_args: self._refresh_parameter_visibility())
        self._refresh_parameter_visibility()

        action_frame = ttk.Frame(root)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.columnconfigure(2, weight=1)
        ttk.Button(action_frame, text="Create encrypted decryptor script", command=self.create_script).grid(row=0, column=0, sticky="w")
        ttk.Button(action_frame, text="Preview encrypted text", command=self.preview_encrypted_text).grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Label(action_frame, textvariable=self.status, wraplength=680).grid(row=0, column=2, sticky="ew", padx=(12, 0))

    def _set_all_ciphers(self, value: bool, defaults: bool = False) -> None:
        if defaults:
            for cipher, variable in self.cipher_vars.items():
                variable.set(cipher in DEFAULT_CIPHER_ORDER)
            self.status.set("Restored the default non-expanding cipher stack.")
            self._refresh_parameter_visibility()
            return

        if value:
            for cipher, variable in self.cipher_vars.items():
                variable.set(cipher not in EXPANDING_CIPHERS)
            self.status.set(
                "Selected all non-expanding ciphers. Add at most one expanding cipher manually to avoid huge decryptor payloads."
            )
            self._refresh_parameter_visibility()
            return

        for variable in self.cipher_vars.values():
            variable.set(False)
        self.status.set("Cleared all ciphers.")
        self._refresh_parameter_visibility()

    def _refresh_parameter_visibility(self) -> None:
        required = set(required_parameter_names(self.selected_ciphers()))
        for name, label_widget, input_widget in getattr(self, "parameter_controls", []):
            if name in required:
                label_widget.grid()
                input_widget.grid()
            else:
                label_widget.grid_remove()
                input_widget.grid_remove()

    def choose_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a file to encrypt")
        if selected:
            self.file_path.set(selected)
            self.status.set(f"Selected {selected}")

    def selected_ciphers(self) -> list[str]:
        return [cipher for cipher in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS if self.cipher_vars[cipher].get()]

    def _collect_encrypt_request(self) -> tuple[Path, list[str], dict[str, str]]:
        source = Path(self.file_path.get()).expanduser()
        if not source.is_file():
            raise FileNotFoundError("Choose an existing file first.")
        ciphers = self.selected_ciphers()
        if not ciphers:
            raise ValueError("Select at least one cipher.")
        params = {
            "key": self.vigenere_key.get().strip(),
            "vigenere_key": self.vigenere_key.get().strip(),
            "keyed_caesar_key": self.keyed_caesar_key.get().strip(),
            "beaufort_key": self.beaufort_key.get().strip(),
            "autokey_key": self.autokey_key.get().strip(),
            "columnar_key": self.columnar_key.get().strip(),
            "porta_key": self.porta_key.get().strip(),
            "alberti_key": self.alberti_key.get().strip(),
            "stream_key": self.stream_key.get().strip(),
            "rotor_key": self.rotor_key.get().strip(),
            "quagmire_plain_key": self.quagmire_plain_key.get().strip(),
            "quagmire_cipher_key": self.quagmire_cipher_key.get().strip(),
            "quagmire_indicator_key": self.quagmire_indicator_key.get().strip(),
            "shift": self.shift.get().strip(),
            "rotor_positions": self.rotor_positions.get().strip(),
            "plugboard_pairs": self.plugboard_pairs.get().strip(),
            "enigma_rotors": self.enigma_rotors.get().strip(),
            "enigma_ring_settings": self.enigma_ring_settings.get().strip(),
            "enigma_reflector": self.enigma_reflector.get().strip(),
            "purple_switches": self.purple_switches.get().strip(),
            "purple_alphabet": self.purple_alphabet.get().strip(),
            "affine_a": self.affine_a.get().strip(),
            "affine_b": self.affine_b.get().strip(),
            "step": self.step.get().strip(),
            "gronsfeld_digits": self.gronsfeld_digits.get().strip(),
            "rails": self.rails.get().strip(),
            "rail_offset": self.rail_offset.get().strip(),
        }
        validate_params(ciphers, params)
        return source, ciphers, params

    def _encrypted_text_for(self, source: Path, ciphers: list[str], params: dict[str, str]) -> str:
        text_file_version = base64.b64encode(source.read_bytes()).decode("ascii")
        return encrypt_with_ciphers(text_file_version, ciphers, params)

    def preview_source_file(self) -> None:
        try:
            source = Path(self.file_path.get()).expanduser()
            if not source.is_file():
                raise FileNotFoundError("Choose an existing file first.")
            self._show_file_preview(f"Source preview: {source.name}", source.read_bytes(), source)
            self.status.set(f"Previewed source file {source}.")
        except Exception as exc:
            messagebox.showerror("Could not preview source", str(exc))
            self.status.set(f"Preview error: {exc}")

    def preview_encrypted_text(self) -> None:
        try:
            source, ciphers, params = self._collect_encrypt_request()
            encrypted_text = self._encrypted_text_for(source, ciphers, params)
            preview = encrypted_text[:ENCRYPTED_PREVIEW_LIMIT]
            if len(encrypted_text) > ENCRYPTED_PREVIEW_LIMIT:
                preview += f"\n\n... truncated after {ENCRYPTED_PREVIEW_LIMIT} of {len(encrypted_text)} characters ..."
            self._show_text_preview(
                "Encrypted text preview",
                f"Cipher stack: {' -> '.join(ciphers)}\nCharacters: {len(encrypted_text)}\n\n{preview}",
            )
            self.status.set(f"Previewed encrypted text for {source.name}.")
        except Exception as exc:
            messagebox.showerror("Could not preview encrypted text", str(exc))
            self.status.set(f"Preview error: {exc}")

    def _show_file_preview(self, title: str, data: bytes, source: Path) -> None:
        kind = detect_preview_kind(data, source)
        if kind == "image" and self._show_image_preview(title, source):
            return
        if kind == "sound":
            self._show_text_preview(title, sound_preview_summary(data))
            return
        if kind == "text":
            text, truncated = decode_text_preview(data)
            suffix = f"\n\n... truncated after {TEXT_PREVIEW_LIMIT} of {len(data)} bytes ..." if truncated else ""
            self._show_text_preview(title, (text or "") + suffix)
            return
        self._show_text_preview(title, "Binary file preview (hex):\n\n" + hex_preview(data))

    def _show_image_preview(self, title: str, source: Path) -> bool:
        try:
            image = tk.PhotoImage(file=str(source))
        except tk.TclError:
            return False
        scale = max(image.width() // 720, image.height() // 480, 1)
        if scale > 1:
            image = image.subsample(scale, scale)
        window = tk.Toplevel(self)
        window.title(title)
        window.geometry("760x560")
        window.minsize(360, 240)
        window.preview_image = image
        ttk.Label(window, text=f"{source.name} ({image.width()}x{image.height()} preview)").pack(anchor="w", padx=10, pady=(10, 4))
        canvas = tk.Canvas(window, highlightthickness=0)
        x_scroll = ttk.Scrollbar(window, orient="horizontal", command=canvas.xview)
        y_scroll = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        canvas.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        y_scroll.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))
        x_scroll.pack(side="bottom", fill="x", padx=10)
        canvas.create_image(0, 0, anchor="nw", image=image)
        canvas.configure(scrollregion=(0, 0, image.width(), image.height()))
        return True

    def _show_text_preview(self, title: str, text: str) -> None:
        window = tk.Toplevel(self)
        window.title(title)
        window.geometry("760x560")
        window.minsize(360, 240)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        text_widget = tk.Text(window, wrap="word")
        y_scroll = ttk.Scrollbar(window, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=y_scroll.set)
        text_widget.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        text_widget.insert("1.0", text)
        text_widget.configure(state="disabled")

    def create_script(self) -> None:
        try:
            source, ciphers, params = self._collect_encrypt_request()
            encrypted_text = self._encrypted_text_for(source, ciphers, params)

            default_name = f"{source.stem}_encrypted_decryptor.py"
            output = filedialog.asksaveasfilename(
                title="Save encrypted Python decryptor",
                initialfile=default_name,
                defaultextension=".py",
                filetypes=[("Python scripts", "*.py"), ("All files", "*.*")],
            )
            if not output:
                self.status.set("Save cancelled.")
                return

            output_path = Path(output)
            output_path.write_text(build_decryptor_script(encrypted_text, source.suffix, ciphers), encoding="utf-8")
            parameter_summary = ", ".join(f"{name}={params[name]!r}" for name in required_parameter_names(ciphers))
            self.status.set(f"Saved {output_path}. Keep these decrypt parameters: {parameter_summary}.")
            messagebox.showinfo("Encrypted script created", self.status.get())
        except Exception as exc:
            messagebox.showerror("Could not create script", str(exc))
            self.status.set(f"Error: {exc}")


def main() -> None:
    app = FileEncryptionApp()
    app.mainloop()


if __name__ == "__main__":
    main()
