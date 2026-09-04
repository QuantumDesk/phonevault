#!/usr/bin/env python3

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import usb.core

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aoa_client


class FakeOut:
    def __init__(self):
        self.payload = None

    def write(self, payload, timeout):
        self.payload = bytes(payload)


class FakeIn:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def read(self, _size, timeout):
        try:
            return next(self.chunks)
        except StopIteration as exception:
            raise usb.core.USBTimeoutError() from exception


class ExchangeTest(unittest.TestCase):
    def exchange(self, chunks, request=None):
        outgoing = FakeOut()
        result = aoa_client.exchange(
            FakeIn(chunks), outgoing, request or {"id": "request-1", "method": "getAddress"}, 10
        )
        return result, json.loads(outgoing.payload)

    def test_accepts_one_correlated_fragmented_response(self):
        result, sent = self.exchange(
            [b'{"id":"request-1",', b'"status":"ok"}\n']
        )
        self.assertEqual("request-1", sent["id"])
        self.assertEqual("ok", result["status"])

    def test_rejects_mismatched_response_id(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.exchange([b'{"id":"stale","status":"ok"}\n'])

    def test_rejects_multiple_frames_in_one_exchange(self):
        with self.assertRaisesRegex(ValueError, "more than one"):
            self.exchange([b'{"id":"request-1"}\n{"id":"request-1"}\n'])

    def test_rejects_oversized_response(self):
        with patch.object(aoa_client, "MAX_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                self.exchange([b"123456789"])

    def test_requires_request_id(self):
        with self.assertRaisesRegex(ValueError, "non-empty"):
            self.exchange([], {"method": "getAddress"})


class DeviceSelectionTest(unittest.TestCase):
    def test_requires_exactly_one_google_android_device(self):
        first = type("Device", (), {"idVendor": aoa_client.GOOGLE_VENDOR_ID})()
        second = type("Device", (), {"idVendor": aoa_client.GOOGLE_VENDOR_ID})()
        with patch("usb.core.find", return_value=iter([first, second])):
            with self.assertRaisesRegex(RuntimeError, "exactly one"):
                aoa_client.find_android_device()


class SignedTransactionValidationTest(unittest.TestCase):
    SIGNED = (
        "0x02f86d83aa36a780843b9aca008477359400825208"
        "9411111111111111111111111111111111111111118080c080"
        "a08fea69f8d5274d05db3283e8859f852c5c49600b0fd43eeb936e52797ff6a1eb"
        "a0552f96d381d40f3683e144a7fb52bc9eb92019f4fd5f1835bdbf72b5a6a6a1a9"
    )

    @staticmethod
    def request():
        return {
            "id": "request-1",
            "method": "signEip1559",
            "chainId": "0xaa36a7",
            "nonce": "0x0",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "maxFeePerGas": "0x77359400",
            "gasLimit": "0x5208",
            "to": "0x1111111111111111111111111111111111111111",
            "value": "0x0",
            "data": "0x",
        }

    def response(self):
        return {
            "id": "request-1",
            "status": "approved",
            "address": "0x5d57809c668b6fa32396f3176df830ba3b49400f",
            "signedTransaction": self.SIGNED,
            "transactionHash": (
                "0x8e4958ec81904b4397d3d095d316fbac072551ccc74b93b67acaa811d03e67b8"
            ),
        }

    SIGNER = "0x5d57809c668b6fa32396f3176df830ba3b49400f"

    def test_independently_matches_every_signed_field(self):
        aoa_client.validate_response(self.request(), self.response(), expected_signer=self.SIGNER)

    def test_requires_a_pinned_signer_for_signatures(self):
        # A self-consistent (valid signature + matching claimed address) response from an
        # UNKNOWN device must not pass: identity comes from pairing, not from the response.
        with self.assertRaisesRegex(ValueError, "no pinned signer"):
            aoa_client.validate_response(self.request(), self.response())
        with self.assertRaisesRegex(ValueError, "not a valid address"):
            aoa_client.validate_response(self.request(), self.response(), expected_signer="nope")

    def test_pairing_file_round_trip_and_validation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/nested/paired-signer.json"
            self.assertIsNone(aoa_client.load_paired_signer(path))
            aoa_client.save_paired_signer(path, self.SIGNER.upper().replace("0X", "0x"))
            self.assertEqual(aoa_client.load_paired_signer(path), self.SIGNER)
            self.assertEqual(oct(__import__("os").stat(path).st_mode & 0o777), oct(0o600))
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"address": "0x1234"}')
            with self.assertRaisesRegex(ValueError, "malformed"):
                aoa_client.load_paired_signer(path)
            with self.assertRaisesRegex(ValueError, "invalid signer address"):
                aoa_client.save_paired_signer(path, "0xzz")
        self.assertEqual(len(aoa_client.address_fingerprint(self.SIGNER)), 8)

    def test_pairing_file_permissions_are_enforced_not_assumed(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/paired-signer.json"
            # A pre-existing world-readable file is REPLACED by a 0600 one, not reused.
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            os.chmod(path, 0o666)
            aoa_client.save_paired_signer(path, self.SIGNER)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))
            self.assertEqual(aoa_client.load_paired_signer(path), self.SIGNER)
            self.assertFalse(any(name.endswith(".tmp") for name in os.listdir(tmp)), "no temp left behind")
            # A loosened file is refused on load.
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ValueError, "group/world accessible"):
                aoa_client.load_paired_signer(path)
            os.chmod(path, 0o600)
            # A symlink in place of the file is refused on load and on save.
            link = f"{tmp}/link.json"
            os.symlink(path, link)
            with self.assertRaisesRegex(ValueError, "symlink"):
                aoa_client.load_paired_signer(link)
            with self.assertRaisesRegex(ValueError, "symlink"):
                aoa_client.save_paired_signer(link, self.SIGNER)
            self.assertEqual(aoa_client.load_paired_signer(path), self.SIGNER, "target untouched")
            # A directory is not a pairing file.
            os.mkdir(f"{tmp}/dir.json")
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                aoa_client.load_paired_signer(f"{tmp}/dir.json")

    def test_rejects_field_substitution_in_signed_payload(self):
        request = self.request()
        request["gasLimit"] = "0x5209"
        with self.assertRaisesRegex(ValueError, "gasLimit does not match"):
            aoa_client.validate_response(request, self.response())

    def test_recomputes_transaction_hash_instead_of_trusting_it(self):
        response = self.response()
        response["transactionHash"] = (
            "0x8e4958ec81904b4397d3d095d316fbac072551ccc74b93b67acaa811d03e67b9"
        )
        with self.assertRaisesRegex(ValueError, "transactionHash does not match"):
            aoa_client.validate_response(self.request(), response)

    def test_recovers_signer_and_rejects_a_forged_address_claim(self):
        response = self.response()
        response["address"] = "0x6a9987e384e67432d7a8b84fac9f880406039618"
        with self.assertRaisesRegex(ValueError, "not produced by the claimed address"):
            aoa_client.validate_response(self.request(), response, expected_signer=self.SIGNER)

    def test_rejects_signature_from_a_different_signer_than_expected(self):
        # A valid signature from address A is not acceptable if the host expected address B.
        with self.assertRaisesRegex(ValueError, "expected signer"):
            aoa_client.validate_response(
                self.request(), self.response(),
                expected_signer="0x1111111111111111111111111111111111111111")
        # Case-insensitive match against the address fetched earlier passes.
        aoa_client.validate_response(
            self.request(), self.response(),
            expected_signer="0x5D57809C668B6FA32396F3176DF830BA3B49400F")

    def test_rejects_signature_whose_parity_bit_was_flipped(self):
        # Flipping yParity recovers a different key, so the claimed address no longer matches.
        response = self.response()
        signed = bytearray(bytes.fromhex(response["signedTransaction"][2:]))
        # yParity is the RLP item just before r: locate it as the byte before the 0xa0 r prefix.
        r_prefix = signed.find(bytes.fromhex("a08fea69f8"))
        self.assertGreater(r_prefix, 0)
        self.assertEqual(signed[r_prefix - 1], 0x80)  # yParity 0 encodes as 0x80
        signed[r_prefix - 1] = 0x01
        response["signedTransaction"] = "0x" + signed.hex()
        response["transactionHash"] = "0x" + aoa_client.evm_verify.keccak256(bytes(signed)).hex()
        with self.assertRaisesRegex(ValueError, "not produced by the claimed address"):
            aoa_client.validate_response(self.request(), response, expected_signer=self.SIGNER)

    def test_rejects_unexpected_fields_in_approval(self):
        response = self.response()
        response["hostNote"] = "ignored?"
        with self.assertRaisesRegex(ValueError, "malformed approved"):
            aoa_client.validate_response(self.request(), response)

    def test_accepts_schema_exact_rejection_without_signature(self):
        aoa_client.validate_response(
            self.request(), {"id": "request-1", "status": "rejected"}
        )


if __name__ == "__main__":
    unittest.main()
