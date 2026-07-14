import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from file_encryptor_gui import (
    DEFAULT_CIPHER_ORDER,
    EXTRA_CIPHERS,
    apply_cipher,
    build_decryptor_script,
    encrypt_with_ciphers,
    validate_params,
)


PARAMS = {
    "key": "SecretKey9",
    "shift": "7",
    "rotor_positions": "ABC",
    "affine_a": "2",
    "affine_b": "7",
    "step": "3",
    "gronsfeld_digits": "314159",
    "rails": "3",
}


class FileEncryptorTests(unittest.TestCase):
    def test_each_cipher_round_trips(self):
        text = "abcdEFGH123+/="
        for cipher in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS:
            with self.subTest(cipher=cipher):
                encrypted = apply_cipher(text, cipher, PARAMS, decrypt=False)
                decrypted = apply_cipher(encrypted, cipher, PARAMS, decrypt=True)
                self.assertEqual(decrypted, text)

    def test_generated_decryptor_round_trips_full_stack(self):
        payload = b"abc\x00xyz test payload"
        ciphers = DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS
        plain = base64.b64encode(payload).decode("ascii")
        encrypted = encrypt_with_ciphers(plain, ciphers, PARAMS)
        script = build_decryptor_script(encrypted, ".bin", ciphers)

        with tempfile.TemporaryDirectory() as directory:
            script_path = Path(directory) / "decryptor.py"
            script_path.write_text(script, encoding="utf-8")
            user_input = "SecretKey9\n7\nABC\n2\n7\n3\n314159\n3\nout.bin\n"
            result = subprocess.run(
                [sys.executable, str(script_path)],
                input=user_input,
                text=True,
                cwd=directory,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(directory) / "out.bin").read_bytes(), payload)

    def test_validation_rejects_bad_affine_multiplier(self):
        bad_params = PARAMS | {"affine_a": "5"}
        with self.assertRaises(ValueError):
            validate_params(["Affine"], bad_params)


if __name__ == "__main__":
    unittest.main()
