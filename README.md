# File-encryption

A small Python/Tkinter utility for converting any selected file into Base64 text,
encrypting that text with a stack of classical ciphers, and writing a standalone
Python script that can decrypt the payload back to its original file extension.

The cipher list is inspired by the
[`op-message-encryptor-and-decryptor`](https://github.com/burning-calamity/op-message-encryptor-and-decryptor/tree/main)
project and includes Caesar, Vigenere, Atbash, Quagmire I-IV, Enigma-style,
Red/Purple/Green rotor-machine-style ciphers, ROT47, Affine, Keyed Caesar,
Beaufort, Progressive Caesar, Autokey, Gronsfeld, Rail Fence, Columnar
Transposition, Reverse, Binary, Baconian, Hex, Polybius Square, Morse Code,
XOR Stream, RC4 Stream, ADFGVX, Octal, and Decimal ASCII.

## Usage

```bash
python file_encryptor_gui.py
```

1. Choose the file to encrypt.
2. Select the cipher stack to apply.
3. Pick or keep the generated keyword, shift, rotor positions, Affine values,
   Progressive Caesar step, Gronsfeld digits, and Rail Fence rail count.
4. Save the generated `*_encrypted_decryptor.py` script.
5. Keep the chosen parameters somewhere safe. The generated script asks for the
   parameters needed by the selected ciphers before restoring the original file.

The generated decryptor embeds the encrypted text payload and the original file
extension, then asks where to write the decrypted output.


## Testing

```bash
python -m unittest -v
```

The included tests verify every cipher can round-trip text, the generated
decryptor can restore a payload with a representative layered cipher stack, and invalid Affine
parameters are rejected before a decryptor is created.
