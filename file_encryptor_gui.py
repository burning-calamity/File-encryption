#!/usr/bin/env python3
"""GUI tool that turns any file into encrypted text and emits a decryptor script.

The selected file is read as bytes, converted to Base64 text, encrypted with a
configurable stack of classical ciphers, and written into a standalone Python
script. Running that script asks for the same parameters and reconstructs the
original extension and bytes.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
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
KEYWORD_CIPHERS = {
    "Vigenere",
    "Quagmire I",
    "Quagmire II",
    "Quagmire III",
    "Quagmire IV",
    "Keyed Caesar",
    "Beaufort",
    "Autokey",
    "Columnar Transposition",
    "XOR Stream",
    "RC4 Stream",
}


CIPHER_RUNTIME = r'''
import base64
import json
from pathlib import Path

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
MACHINE_CIPHERS = {"Enigma", "Red", "Purple", "Green"}
KEYWORD_CIPHERS = {"Vigenere", "Quagmire I", "Quagmire II", "Quagmire III", "Quagmire IV", "Keyed Caesar", "Beaufort", "Autokey", "Columnar Transposition", "XOR Stream", "RC4 Stream"}


def normalized_alphabet(seed: str, alphabet: str = ALPHABET) -> str:
    seen = []
    for char in seed + alphabet:
        if char in alphabet and char not in seen:
            seen.append(char)
    if len(seen) != len(alphabet):
        raise ValueError("keyword alphabet did not normalize correctly")
    return "".join(seen)


def key_indexes(key: str, alphabet: str = ALPHABET) -> list[int]:
    values = [alphabet.index(char) for char in key if char in alphabet]
    if not values:
        raise ValueError(f"key must contain at least one supported character from {alphabet!r}")
    return values


def translate_alphabet(text: str, source: str, target: str) -> str:
    table = {src: dst for src, dst in zip(source, target)}
    return "".join(table.get(char, char) for char in text)


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    return "".join(ALPHABET[(ALPHABET.index(char) + shift) % len(ALPHABET)] if char in ALPHABET else char for char in text)


def vigenere(text: str, key: str, decrypt: bool = False, alphabet: str = ALPHABET) -> str:
    shifts = key_indexes(key, alphabet)
    result = []
    key_position = 0
    for char in text:
        if char not in alphabet:
            result.append(char)
            continue
        shift = shifts[key_position % len(shifts)]
        if decrypt:
            shift = -shift
        result.append(alphabet[(alphabet.index(char) + shift) % len(alphabet)])
        key_position += 1
    return "".join(result)


def atbash(text: str) -> str:
    return "".join(ALPHABET[-ALPHABET.index(char) - 1] if char in ALPHABET else char for char in text)


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
        if char not in ALPHABET:
            out.append(char)
            continue
        value = ALPHABET.index(char)
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
    for char in text:
        if char not in ALPHABET:
            out.append(char)
            continue
        shift = shifts[key_position % len(shifts)]
        out.append(ALPHABET[(shift - ALPHABET.index(char)) % len(ALPHABET)])
        key_position += 1
    return "".join(out)


def progressive_caesar(text: str, start: int, step: int, decrypt: bool = False) -> str:
    out = []
    position = 0
    for char in text:
        if char not in ALPHABET:
            out.append(char)
            continue
        shift = start + position * step
        if decrypt:
            shift = -shift
        out.append(ALPHABET[(ALPHABET.index(char) + shift) % len(ALPHABET)])
        position += 1
    return "".join(out)


def autokey(text: str, key: str, decrypt: bool = False) -> str:
    stream = key_indexes(key)
    out = []
    stream_position = 0
    for char in text:
        if char not in ALPHABET:
            out.append(char)
            continue
        shift = stream[stream_position]
        value = ALPHABET.index(char)
        if decrypt:
            plain_value = (value - shift) % len(ALPHABET)
            out.append(ALPHABET[plain_value])
            stream.append(plain_value)
        else:
            out.append(ALPHABET[(value + shift) % len(ALPHABET)])
            stream.append(value)
        stream_position += 1
    return "".join(out)


def gronsfeld(text: str, digits: str, decrypt: bool = False) -> str:
    shifts = [int(char) for char in digits if char.isdigit()]
    if not shifts:
        raise ValueError("Gronsfeld digits must contain at least one number.")
    out = []
    position = 0
    for char in text:
        if char not in ALPHABET:
            out.append(char)
            continue
        shift = shifts[position % len(shifts)]
        if decrypt:
            shift = -shift
        out.append(ALPHABET[(ALPHABET.index(char) + shift) % len(ALPHABET)])
        position += 1
    return "".join(out)


def rail_fence(text: str, rails: int, decrypt: bool = False) -> str:
    if rails < 2:
        raise ValueError("Rail Fence rails must be at least 2.")
    pattern = []
    rail = 0
    direction = 1
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
    if not decrypt:
        encoded = []
        for char in text:
            value = ord(char)
            encoded.append(symbols[value // 36] + symbols[(value // 6) % 6] + symbols[value % 6])
        return " ".join(encoded)
    chunks = [chunk for chunk in text.split(" ") if chunk]
    return "".join(chr(symbols.index(chunk[0]) * 36 + symbols.index(chunk[1]) * 6 + symbols.index(chunk[2])) for chunk in chunks)


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


def quagmire(text: str, key: str, variant: int, decrypt: bool = False) -> str:
    plain = normalized_alphabet(key if variant in {1, 3} else "")
    cipher = normalized_alphabet(key[::-1] if variant in {2, 3, 4} else "")
    indicator = normalized_alphabet(key if variant == 4 else key[::-1])
    shifts = key_indexes(key, indicator)
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


def rotor_machine(text: str, key: str, rotor_positions: str, machine: str, decrypt: bool = False) -> str:
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
        return vigenere(text, params["key"], decrypt)
    if cipher == "Atbash":
        return atbash(text)
    if cipher.startswith("Quagmire"):
        return quagmire(text, params["key"], {"Quagmire I": 1, "Quagmire II": 2, "Quagmire III": 3, "Quagmire IV": 4}[cipher], decrypt)
    if cipher in MACHINE_CIPHERS:
        return rotor_machine(text, params["key"], params["rotor_positions"], cipher, decrypt)
    if cipher == "ROT47":
        return rot47(text)
    if cipher == "Affine":
        return affine(text, int(params["affine_a"]), int(params["affine_b"]), decrypt)
    if cipher == "Keyed Caesar":
        return keyed_caesar(text, params["key"], int(params["shift"]), decrypt)
    if cipher == "Beaufort":
        return beaufort(text, params["key"])
    if cipher == "Progressive Caesar":
        return progressive_caesar(text, int(params["shift"]), int(params["step"]), decrypt)
    if cipher == "Autokey":
        return autokey(text, params["key"], decrypt)
    if cipher == "Gronsfeld":
        return gronsfeld(text, params["gronsfeld_digits"], decrypt)
    if cipher == "Rail Fence":
        return rail_fence(text, int(params["rails"]), decrypt)
    if cipher == "Columnar Transposition":
        return columnar_transposition(text, params["key"], decrypt)
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
        return xor_stream(text, params["key"], decrypt)
    if cipher == "RC4 Stream":
        return rc4_stream(text, params["key"], decrypt)
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
    if any(cipher in KEYWORD_CIPHERS or cipher in MACHINE_CIPHERS for cipher in ciphers):
        if not params.get("key"):
            raise ValueError("A shared keyword/key is required for the selected ciphers.")
        key_indexes(params["key"])
    if "Gronsfeld" in ciphers and not any(char.isdigit() for char in params.get("gronsfeld_digits", "")):
        raise ValueError("Gronsfeld requires at least one digit.")
    if "Rail Fence" in ciphers and int(params.get("rails", "0")) < 2:
        raise ValueError("Rail Fence rails must be at least 2.")
    if "Affine" in ciphers:
        a = int(params["affine_a"])
        b = int(params["affine_b"])
        sample = "aZ9+="
        if affine(affine(sample, a, b), a, b, decrypt=True) != sample:
            raise ValueError("Affine parameters failed validation.")


def required_parameter_names(ciphers: list[str]) -> list[str]:
    names: list[str] = []
    if any(cipher in KEYWORD_CIPHERS or cipher in MACHINE_CIPHERS for cipher in ciphers):
        names.append("key")
    if any(cipher in {"Caesar", "Keyed Caesar", "Progressive Caesar"} for cipher in ciphers):
        names.append("shift")
    if any(cipher in MACHINE_CIPHERS for cipher in ciphers):
        names.append("rotor_positions")
    if "Affine" in ciphers:
        names.extend(["affine_a", "affine_b"])
    if "Progressive Caesar" in ciphers:
        names.append("step")
    if "Gronsfeld" in ciphers:
        names.append("gronsfeld_digits")
    if "Rail Fence" in ciphers:
        names.append("rails")
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
        "key": "Shared cipher keyword/key used by the encrypter: ",
        "shift": "Caesar/keyed shift used by the encrypter: ",
        "rotor_positions": "Rotor positions used by the encrypter: ",
        "affine_a": "Affine multiplier a used by the encrypter: ",
        "affine_b": "Affine shift b used by the encrypter: ",
        "step": "Progressive Caesar step used by the encrypter: ",
        "gronsfeld_digits": "Gronsfeld digit key used by the encrypter: ",
        "rails": "Rail Fence rail count used by the encrypter: ",
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
        self.shift = tk.IntVar(value=secrets.randbelow(len(ALPHABET) - 1) + 1)
        self.step = tk.IntVar(value=1)
        self.rails = tk.IntVar(value=3)
        self.gronsfeld_digits = tk.StringVar(value="314159")
        self.affine_a = tk.IntVar(value=2)
        self.affine_b = tk.IntVar(value=7)
        self.cipher_key = tk.StringVar(value=secrets.token_urlsafe(12).replace("-", "A").replace("_", "B"))
        self.rotor_positions = tk.StringVar(value="ABC")
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
        ttk.Button(file_frame, text="Browse...", command=self.choose_file).grid(row=0, column=1, sticky="e", padx=(0, 10), pady=10)

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
            ("Shared keyword/key", ttk.Entry(params_frame, textvariable=self.cipher_key)),
            ("Shift", ttk.Spinbox(params_frame, from_=1, to=len(ALPHABET) - 1, textvariable=self.shift, width=10)),
            ("Rotor positions", ttk.Entry(params_frame, textvariable=self.rotor_positions)),
            ("Affine a (coprime with 65)", ttk.Spinbox(params_frame, from_=1, to=64, textvariable=self.affine_a, width=10)),
            ("Affine b", ttk.Spinbox(params_frame, from_=0, to=64, textvariable=self.affine_b, width=10)),
            ("Progressive step", ttk.Spinbox(params_frame, from_=1, to=64, textvariable=self.step, width=10)),
            ("Gronsfeld digits", ttk.Entry(params_frame, textvariable=self.gronsfeld_digits)),
            ("Rail Fence rails", ttk.Spinbox(params_frame, from_=2, to=20, textvariable=self.rails, width=10)),
        ]
        for index, (label, widget) in enumerate(fields):
            row = (index // 4) * 2
            column = index % 4
            ttk.Label(params_frame, text=label).grid(row=row, column=column, sticky="w", padx=10, pady=(10, 2))
            widget.grid(row=row + 1, column=column, sticky="ew", padx=10, pady=(0, 10))

        action_frame = ttk.Frame(root)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.columnconfigure(1, weight=1)
        ttk.Button(action_frame, text="Create encrypted decryptor script", command=self.create_script).grid(row=0, column=0, sticky="w")
        ttk.Label(action_frame, textvariable=self.status, wraplength=680).grid(row=0, column=1, sticky="ew", padx=(12, 0))

    def _set_all_ciphers(self, value: bool, defaults: bool = False) -> None:
        for cipher, variable in self.cipher_vars.items():
            variable.set(cipher in DEFAULT_CIPHER_ORDER if defaults else value)

    def choose_file(self) -> None:
        selected = filedialog.askopenfilename(title="Choose a file to encrypt")
        if selected:
            self.file_path.set(selected)
            self.status.set(f"Selected {selected}")

    def selected_ciphers(self) -> list[str]:
        return [cipher for cipher in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS if self.cipher_vars[cipher].get()]

    def create_script(self) -> None:
        try:
            source = Path(self.file_path.get()).expanduser()
            if not source.is_file():
                raise FileNotFoundError("Choose an existing file first.")
            ciphers = self.selected_ciphers()
            if not ciphers:
                raise ValueError("Select at least one cipher.")
            params = {
                "key": self.cipher_key.get().strip(),
                "shift": str(int(self.shift.get())),
                "rotor_positions": self.rotor_positions.get().strip(),
                "affine_a": str(int(self.affine_a.get())),
                "affine_b": str(int(self.affine_b.get())),
                "step": str(int(self.step.get())),
                "gronsfeld_digits": self.gronsfeld_digits.get().strip(),
                "rails": str(int(self.rails.get())),
            }
            validate_params(ciphers, params)
            text_file_version = base64.b64encode(source.read_bytes()).decode("ascii")
            encrypted_text = encrypt_with_ciphers(text_file_version, ciphers, params)

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
