import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from file_encryptor_gui import (
    DEFAULT_CIPHER_ORDER,
    EXPANDING_CIPHERS,
    EXTRA_CIPHERS,
    apply_cipher,
    build_decryptor_script,
    decode_text_preview,
    detect_preview_kind,
    encrypt_with_ciphers,
    hex_preview,
    sound_preview_summary,
    validate_params,
    required_parameter_names,
)


PARAMS = {
    "key": "SecretKey9",
    "vigenere_key": "SecretKey9",
    "keyed_caesar_key": "SecretKey9",
    "beaufort_key": "SecretKey9",
    "autokey_key": "SecretKey9",
    "columnar_key": "SecretKey9",
    "porta_key": "SecretKey9",
    "alberti_key": "SecretKey9",
    "stream_key": "SecretKey9",
    "rotor_key": "SecretKey9",
    "quagmire_plain_key": "PlainKey",
    "quagmire_cipher_key": "CipherKey",
    "quagmire_indicator_key": "Indicator",
    "shift": "7",
    "rotor_positions": "ABC",
    "plugboard_pairs": "AZ BY",
    "enigma_rotors": "I II III",
    "enigma_ring_settings": "AAA",
    "enigma_reflector": "B",
    "purple_switches": "9-1,24,6-23",
    "purple_alphabet": "NOKTYUXEQLHBRMPDICJASVWGZF",
    "affine_a": "2",
    "affine_b": "7",
    "step": "3",
    "gronsfeld_digits": "314159",
    "rails": "3",
    "rail_offset": "1",
}


class FileEncryptorTests(unittest.TestCase):
    def test_each_cipher_round_trips(self):
        text = "abcdEFGH123+/="
        for cipher in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS:
            with self.subTest(cipher=cipher):
                encrypted = apply_cipher(text, cipher, PARAMS, decrypt=False)
                decrypted = apply_cipher(encrypted, cipher, PARAMS, decrypt=True)
                self.assertEqual(decrypted, text)

    def test_known_accuracy_vectors(self):
        self.assertEqual(apply_cipher("ABC xyz", "Caesar", PARAMS | {"shift": "3"}, decrypt=False), "DEF abc")
        self.assertEqual(apply_cipher("ATTACKATDAWN", "Vigenere", PARAMS | {"vigenere_key": "LEMON"}, decrypt=False), "LXFOPVEFRNHR")
        self.assertEqual(apply_cipher("ABC xyz", "Atbash", PARAMS, decrypt=False), "ZYX cba")
        self.assertEqual(apply_cipher("WEAREDISCOVEREDFLEEATONCE", "Rail Fence", PARAMS | {"rails": "3", "rail_offset": "0"}, decrypt=False), "WECRLTEERDSOEEFEAOCAIVDEN")
        self.assertEqual(apply_cipher("AAAAA", "Enigma", PARAMS | {"plugboard_pairs": "", "rotor_positions": "AAA", "enigma_rotors": "I II III", "enigma_ring_settings": "AAA", "enigma_reflector": "B"}, decrypt=False), "BDZGO")

    def test_generated_decryptor_round_trips_representative_stack(self):
        payload = b"abc\x00xyz test payload"
        ciphers = DEFAULT_CIPHER_ORDER + ["Affine", "Rail Fence", "XOR Stream"]
        plain = base64.b64encode(payload).decode("ascii")
        encrypted = encrypt_with_ciphers(plain, ciphers, PARAMS)
        script = build_decryptor_script(encrypted, ".bin", ciphers)

        with tempfile.TemporaryDirectory() as directory:
            script_path = Path(directory) / "decryptor.py"
            script_path.write_text(script, encoding="utf-8")
            user_input = "\n".join(PARAMS[name] for name in required_parameter_names(ciphers)) + "\nout.bin\n"
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

    def test_preview_helpers_detect_text_binary_and_wav(self):
        text, truncated = decode_text_preview(b"hello\nworld")
        self.assertEqual(text, "hello\nworld")
        self.assertFalse(truncated)
        self.assertEqual(detect_preview_kind(b"hello\nworld"), "text")
        self.assertEqual(detect_preview_kind(b"\x00\x01\x02\x03"), "binary")
        self.assertIn("00000000", hex_preview(b"\x00ABC"))

        wav_data = (
            b"RIFF"
            + (36).to_bytes(4, "little")
            + b"WAVEfmt "
            + (16).to_bytes(4, "little")
            + (1).to_bytes(2, "little")
            + (1).to_bytes(2, "little")
            + (8000).to_bytes(4, "little")
            + (8000).to_bytes(4, "little")
            + (1).to_bytes(2, "little")
            + (8).to_bytes(2, "little")
            + b"data"
            + (0).to_bytes(4, "little")
        )
        self.assertEqual(detect_preview_kind(wav_data), "sound")
        self.assertIn("WAV audio preview", sound_preview_summary(wav_data))

    def test_validation_rejects_multiple_expanding_ciphers(self):
        with self.assertRaises(ValueError):
            validate_params(["Binary", "Hex"], PARAMS)

    def test_select_all_safe_stack_has_at_most_one_expander(self):
        safe_stack = [cipher for cipher in DEFAULT_CIPHER_ORDER + EXTRA_CIPHERS if cipher not in EXPANDING_CIPHERS]
        self.assertFalse([cipher for cipher in safe_stack if cipher in EXPANDING_CIPHERS])

    def test_hidden_numeric_fields_do_not_block_unrelated_validation(self):
        bad_hidden_params = PARAMS | {"affine_a": "not-a-number", "rails": "also-bad"}
        validate_params(["Caesar"], bad_hidden_params)

    def test_bifid_trifid_and_rail_offset_round_trip(self):
        text = "abcdEFGH123+/="
        for cipher in ["Bifid", "Trifid", "Rail Fence"]:
            with self.subTest(cipher=cipher):
                encrypted = apply_cipher(text, cipher, PARAMS, decrypt=False)
                self.assertEqual(apply_cipher(encrypted, cipher, PARAMS, decrypt=True), text)

    def test_trifid_handles_base64_payload_regression(self):
        text = "AAU="
        encrypted = apply_cipher(text, "Trifid", PARAMS, decrypt=False)
        self.assertEqual(apply_cipher(encrypted, "Trifid", PARAMS, decrypt=True), text)

    def test_adfgvx_handles_unicode_from_trifid(self):
        text = "AAU="
        trifid_text = apply_cipher(text, "Trifid", PARAMS, decrypt=False)
        encrypted = apply_cipher(trifid_text, "ADFGVX", PARAMS, decrypt=False)
        decoded = apply_cipher(encrypted, "ADFGVX", PARAMS, decrypt=True)
        self.assertEqual(decoded, trifid_text)
        self.assertEqual(apply_cipher(decoded, "Trifid", PARAMS, decrypt=True), text)

    def test_alberti_skips_unicode_letters_from_trifid(self):
        text = "AAU="
        trifid_text = apply_cipher(text, "Trifid", PARAMS, decrypt=False)
        encrypted = apply_cipher(trifid_text, "Alberti", PARAMS, decrypt=False)
        decoded = apply_cipher(encrypted, "Alberti", PARAMS, decrypt=True)
        self.assertEqual(decoded, trifid_text)
        self.assertEqual(apply_cipher(decoded, "Trifid", PARAMS, decrypt=True), text)

    def test_enigma_plugboard_affects_encryption_and_round_trips(self):
        text = "abcdEFGH123+/="
        no_plugboard = PARAMS | {"plugboard_pairs": ""}
        encrypted_without = apply_cipher(text, "Enigma", no_plugboard, decrypt=False)
        encrypted_with = apply_cipher(text, "Enigma", PARAMS, decrypt=False)
        self.assertNotEqual(encrypted_with, encrypted_without)
        self.assertEqual(apply_cipher(encrypted_with, "Enigma", PARAMS, decrypt=True), text)

    def test_enigma_rotor_and_ring_settings_affect_encryption(self):
        text = "AttackAtDawn"
        baseline = apply_cipher(text, "Enigma", PARAMS, decrypt=False)
        changed_rotors = PARAMS | {"enigma_rotors": "III II I"}
        changed_rings = PARAMS | {"enigma_ring_settings": "BCD"}
        self.assertNotEqual(apply_cipher(text, "Enigma", changed_rotors, decrypt=False), baseline)
        self.assertNotEqual(apply_cipher(text, "Enigma", changed_rings, decrypt=False), baseline)
        self.assertEqual(apply_cipher(baseline, "Enigma", PARAMS, decrypt=True), text)

    def test_enigma_m4_mode_round_trips(self):
        text = "AttackAtDawn"
        params = PARAMS | {
            "enigma_rotors": "BETA I II III",
            "enigma_ring_settings": "AAAA",
            "rotor_positions": "AAAA",
            "enigma_reflector": "B Thin",
        }
        encrypted = apply_cipher(text, "Enigma", params, decrypt=False)
        self.assertNotEqual(encrypted, text)
        self.assertEqual(apply_cipher(encrypted, "Enigma", params, decrypt=True), text)

    def test_purple_settings_affect_output_and_validate(self):
        text = "PURPLEMACHINE"
        encrypted = apply_cipher(text, "Purple", PARAMS, decrypt=False)
        changed = PARAMS | {"purple_switches": "1-1,1,1-12"}
        self.assertNotEqual(apply_cipher(text, "Purple", changed, decrypt=False), encrypted)
        self.assertEqual(apply_cipher(encrypted, "Purple", PARAMS, decrypt=True), text)
        with self.assertRaises(ValueError):
            validate_params(["Purple"], PARAMS | {"purple_alphabet": "ABC"})

    def test_quagmire_iv_uses_separate_settings(self):
        text = "abcdEFGH123+/="
        encrypted = apply_cipher(text, "Quagmire IV", PARAMS, decrypt=False)
        changed_params = PARAMS | {"quagmire_cipher_key": "Different"}
        self.assertNotEqual(apply_cipher(text, "Quagmire IV", changed_params, decrypt=False), encrypted)
        self.assertEqual(apply_cipher(encrypted, "Quagmire IV", PARAMS, decrypt=True), text)

    def test_validation_rejects_bad_affine_multiplier(self):
        bad_params = PARAMS | {"affine_a": "5"}
        with self.assertRaises(ValueError):
            validate_params(["Affine"], bad_params)


if __name__ == "__main__":
    unittest.main()
