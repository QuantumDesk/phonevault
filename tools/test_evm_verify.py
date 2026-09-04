#!/usr/bin/env python3
"""Vectors for the pure-Python Keccak / RLP / secp256k1 recovery used by the host verifier."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evm_verify  # noqa: E402

# Well-known constants (independently checkable against any Ethereum library).
KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
KECCAK_ABC = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
ADDRESS_OF_KEY_1 = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
ADDRESS_OF_KEY_2 = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"


class KeccakTest(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(evm_verify.keccak256(b"").hex(), KECCAK_EMPTY)
        self.assertEqual(evm_verify.keccak256(b"abc").hex(), KECCAK_ABC)

    def test_multi_block_input_differs_from_sha3(self):
        # 200 bytes spans two rate blocks; just prove it is deterministic and 32 bytes.
        digest = evm_verify.keccak256(bytes(range(200)))
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, evm_verify.keccak256(bytes(range(200))))
        # Keccak-256 != SHA3-256 (padding differs); guard against an accidental hashlib swap.
        import hashlib
        self.assertNotEqual(digest.hex(), hashlib.sha3_256(bytes(range(200))).hexdigest())


class RlpTest(unittest.TestCase):
    def test_canonical_examples(self):
        self.assertEqual(evm_verify.rlp_encode(0), b"\x80")
        self.assertEqual(evm_verify.rlp_encode(15), b"\x0f")
        self.assertEqual(evm_verify.rlp_encode(1024), b"\x82\x04\x00")
        self.assertEqual(evm_verify.rlp_encode(b""), b"\x80")
        self.assertEqual(evm_verify.rlp_encode(b"dog"), b"\x83dog")
        self.assertEqual(evm_verify.rlp_encode([]), b"\xc0")
        self.assertEqual(evm_verify.rlp_encode([b"cat", b"dog"]), b"\xc8\x83cat\x83dog")
        long_string = b"a" * 56
        self.assertEqual(evm_verify.rlp_encode(long_string), b"\xb8\x38" + long_string)

    def test_round_trip_with_client_decoder(self):
        import aoa_client
        payload = [1, 7, 10 ** 9, 30 * 10 ** 9, 21000, bytes(20), 10 ** 18, b"", []]
        encoded = evm_verify.rlp_encode(payload)
        decoded, end = aoa_client._decode_rlp(encoded)
        self.assertEqual(end, len(encoded))
        self.assertEqual(aoa_client._rlp_integer(decoded[0], "chainId"), 1)
        self.assertEqual(aoa_client._rlp_integer(decoded[4], "gasLimit"), 21000)
        self.assertEqual(decoded[5], bytes(20))
        self.assertEqual(decoded[8], [])


class RecoveryTest(unittest.TestCase):
    def test_private_key_to_address_matches_known_constants(self):
        self.assertEqual(evm_verify.private_key_to_address(1), ADDRESS_OF_KEY_1)
        self.assertEqual(evm_verify.private_key_to_address(2), ADDRESS_OF_KEY_2)

    def test_sign_then_recover_yields_the_known_address(self):
        message = evm_verify.keccak256(b"phone vault test message")
        for key, expected in ((1, ADDRESS_OF_KEY_1), (2, ADDRESS_OF_KEY_2)):
            for k in (3, 0xDEADBEEF, evm_verify.CURVE_ORDER // 3):
                r, s, parity = evm_verify.sign_for_test(message, key, k)
                self.assertLessEqual(s, evm_verify.CURVE_ORDER // 2, "test signer must be low-s")
                self.assertEqual(evm_verify.recover_address(message, r, s, parity), expected)
                # Flipping parity recovers a DIFFERENT key — the parity bit is load-bearing.
                self.assertNotEqual(evm_verify.recover_address(message, r, s, parity ^ 1), expected)

    def test_recovery_rejects_out_of_range_components(self):
        message = evm_verify.keccak256(b"x")
        with self.assertRaises(ValueError):
            evm_verify.recover_address(message, 0, 1, 0)
        with self.assertRaises(ValueError):
            evm_verify.recover_address(message, 1, evm_verify.CURVE_ORDER, 0)
        with self.assertRaises(ValueError):
            evm_verify.recover_address(message, 1, 1, 2)


class Eip1559Test(unittest.TestCase):
    FIELDS = {
        "chainId": 1, "nonce": 9, "maxPriorityFeePerGas": 10 ** 9, "maxFeePerGas": 40 * 10 ** 9,
        "gasLimit": 21000, "to": bytes.fromhex("3535353535353535353535353535353535353535"),
        "value": 10 ** 18, "data": b"",
    }

    def test_signing_hash_is_typed_and_deterministic(self):
        digest = evm_verify.eip1559_signing_hash(self.FIELDS)
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, evm_verify.eip1559_signing_hash(dict(self.FIELDS)))
        changed = dict(self.FIELDS, value=self.FIELDS["value"] + 1)
        self.assertNotEqual(digest, evm_verify.eip1559_signing_hash(changed))

    def test_full_signed_transaction_round_trip(self):
        """Build a signed tx with key 1, then prove the host recomputes hash + signer."""
        import aoa_client
        signing_hash = evm_verify.eip1559_signing_hash(self.FIELDS)
        r, s, parity = evm_verify.sign_for_test(signing_hash, 1, 12345)
        f = self.FIELDS
        raw = b"\x02" + evm_verify.rlp_encode([
            f["chainId"], f["nonce"], f["maxPriorityFeePerGas"], f["maxFeePerGas"], f["gasLimit"],
            f["to"], f["value"], f["data"], [], parity, r, s,
        ])
        decoded = aoa_client.decode_signed_eip1559("0x" + raw.hex())
        self.assertEqual(decoded["r"], r)
        self.assertEqual(decoded["yParity"], parity)
        recovered = evm_verify.recover_address(signing_hash, decoded["r"], decoded["s"], decoded["yParity"])
        self.assertEqual(recovered, ADDRESS_OF_KEY_1)
        self.assertEqual(evm_verify.eip1559_transaction_hash(raw), evm_verify.keccak256(raw))
        with self.assertRaises(ValueError):
            evm_verify.eip1559_transaction_hash(b"\x01" + raw[1:])


if __name__ == "__main__":
    unittest.main()
