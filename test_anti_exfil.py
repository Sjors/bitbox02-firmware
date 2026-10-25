#!/usr/bin/env python3
"""Run the BIP-EXFIL shared vectors using BitBox02's actual libsecp dependency.

Uses a native compiler; ESP-IDF and a device are not needed. Integration tests
must additionally exercise transaction signing on the firmware emulator.
"""
import ctypes
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
SECP = ROOT / "src/rust/bitbox-secp256k1/depend/secp256k1-zkp"


class TestAntiExfil(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        library = Path(cls.tmp.name) / "anti_exfil.so"
        wrapper = Path(cls.tmp.name) / "wrapper.c"
        wrapper.write_text(
            '#include "' + str(ROOT / "src/anti_exfil.c") + '"\n'
            "void test_reduce(unsigned char scalar[32]) { ae_reduce(scalar); }\n"
        )
        subprocess.run(
            [
                "cc",
                "-shared",
                "-fPIC",
                "-O2",
                "-DENABLE_MODULE_EXTRAKEYS=1",
                "-DENABLE_MODULE_SCHNORRSIG=1",
                "-DECMULT_WINDOW_SIZE=2",
                "-DCOMB_BLOCKS=2",
                "-DCOMB_TEETH=5",
                "-I" + str(SECP / "include"),
                str(wrapper),
                *(
                    str(SECP / "src" / name)
                    for name in ("secp256k1.c", "precomputed_ecmult.c", "precomputed_ecmult_gen.c")
                ),
                "-o",
                str(library),
            ],
            check=True,
        )
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
        cls.lib.secp256k1_context_create.restype = ctypes.c_void_p
        cls.lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
        cls.lib.bitbox_anti_exfil_commit.argtypes = [ctypes.c_void_p] + [ctypes.c_char_p] * 4
        cls.lib.bitbox_anti_exfil_sign.argtypes = [ctypes.c_void_p] + [ctypes.c_char_p] * 6
        cls.ctx = cls.lib.secp256k1_context_create(1)
        cls.vectors = json.loads((ROOT / "test_data/anti_exfil_vectors.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.lib.secp256k1_context_destroy(cls.ctx)
        cls.tmp.cleanup()

    def test_scalar_reduction_boundaries(self):
        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.lib.test_reduce.argtypes = [ctypes.c_char_p]
        for value in (0, 1, order - 1, order, order + 1, 2**256 - 1):
            scalar = ctypes.create_string_buffer(value.to_bytes(32, "big"), 32)
            self.lib.test_reduce(scalar)
            self.assertEqual(int.from_bytes(scalar.raw, "big"), value % order)

    def test_vectors_and_transcript_rejection(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["index"]):
                key, msg, commitment, entropy, expected_nonce, expected_sig = (
                    bytes.fromhex(vector[name])
                    for name in (
                        "secret_key",
                        "message",
                        "host_commitment",
                        "host_nonce",
                        "signer_nonce",
                        "signature",
                    )
                )
                nonce = ctypes.create_string_buffer(33)
                sig = ctypes.create_string_buffer(64)
                self.assertEqual(
                    self.lib.bitbox_anti_exfil_commit(self.ctx, nonce, key, msg, commitment), 1
                )
                self.assertEqual(nonce.raw, expected_nonce)
                args = [key, msg, commitment, expected_nonce, entropy]
                self.assertEqual(self.lib.bitbox_anti_exfil_sign(self.ctx, sig, *args), 1)
                self.assertEqual(sig.raw, expected_sig)
                # A replacement of any part of a committed session must fail.
                for index in range(len(args)):
                    bad = args.copy()
                    bad[index] = bytes([bad[index][0] ^ 1]) + bad[index][1:]
                    self.assertEqual(self.lib.bitbox_anti_exfil_sign(self.ctx, sig, *bad), 0)
                    self.assertEqual(sig.raw, bytes(64))
                for invalid in (
                    bytes(32),
                    bytes.fromhex("ff" * 32),
                    bytes.fromhex(
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
                    ),
                ):
                    self.assertEqual(
                        self.lib.bitbox_anti_exfil_sign(
                            self.ctx, sig, key, msg, commitment, expected_nonce, invalid
                        ),
                        0,
                    )
                    self.assertEqual(sig.raw, bytes(64))


if __name__ == "__main__":
    unittest.main()
