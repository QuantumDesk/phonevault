#!/usr/bin/env python3

import errno
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


class FakePhone:
    """A phone as UsbDeviceManager + f_accessory behave (same model as the companion's tests)."""

    def __init__(self, mode, app_reads=True):
        self.mode, self.app_reads = mode, app_reads  # mode: adb | idle | stale | live | gone
        self.idle_is_accessory = mode == "idle"
        self.address, self.start_pending = 10, False
        self.handshakes = self.resets = 0

    def scan(self):
        if self.mode == "gone":
            return []
        return [aoa_client.Seen(self.address, self.mode != "adb", (1, self.address))]

    def handshake(self, dev):
        assert dev == self.address
        self.handshakes += 1
        if self.mode in ("adb", "idle"):  # the function set changes: re-enumerates, attached
            self.mode = "live" if self.app_reads else "stale"
            self.address += 1
        else:  # unchanged function set: nothing happens, START stays pending
            self.start_pending = True

    def reset(self, dev):
        assert dev == self.address
        self.resets += 1
        if self.mode in ("live", "stale"):
            if self.start_pending:
                self.mode = "live" if self.app_reads else "stale"
            else:
                self.mode = "idle" if self.idle_is_accessory else "adb"
                self.address += 1
            self.start_pending = False

    def open_reading(self, dev, wait):
        if dev != self.address:
            raise usb.core.USBError("gone", errno=errno.ENODEV)
        return ("in", "out") if self.mode == "live" else None

    def pause(self, seconds):
        pass


class ConnectTest(unittest.TestCase):
    def test_live_session_is_used_without_handshake(self):
        phone = FakePhone("live")
        self.assertEqual(("in", "out"), aoa_client.connect(phone))
        self.assertEqual((0, 0), (phone.handshakes, phone.resets))

    def test_plain_android_phone_is_switched(self):
        phone = FakePhone("adb")
        aoa_client.connect(phone)
        self.assertEqual((1, 0), (phone.handshakes, phone.resets))

    def test_idle_beta2_accessory_gets_identity_and_re_enumerates(self):
        phone = FakePhone("idle")
        aoa_client.connect(phone)
        self.assertEqual((1, 0), (phone.handshakes, phone.resets))

    def test_stale_session_is_attached_afresh_by_start_and_reset(self):
        phone = FakePhone("stale")
        self.assertEqual(("in", "out"), aoa_client.connect(phone))
        self.assertEqual((1, 1), (phone.handshakes, phone.resets))

    def test_nothing_reading_after_recovery_says_replug(self):
        phone = FakePhone("stale", app_reads=False)
        with self.assertRaisesRegex(aoa_client.NotReadingError, "unplug and replug"):
            aoa_client.connect(phone)
        self.assertEqual((1, 1), (phone.handshakes, phone.resets))

    def test_no_phone(self):
        with self.assertRaisesRegex(RuntimeError, "No Google Android USB device"):
            aoa_client.connect(FakePhone("gone"))

    def test_zero_length_probe(self):
        class Out:
            def __init__(self, outcomes):
                self.outcomes, self.writes = list(outcomes), []

            def write(self, payload, timeout):
                self.writes.append(bytes(payload))
                outcome = self.outcomes.pop(0)
                if outcome is not None:
                    raise outcome

        reading = Out([usb.core.USBTimeoutError("t"), None])
        self.assertTrue(aoa_client.phone_reads(reading, 5))
        self.assertEqual([b"", b""], reading.writes)
        with patch.object(aoa_client.time, "monotonic", side_effect=[0, 0, 0.6, 0.6, 9, 9]):
            self.assertFalse(aoa_client.phone_reads(Out([usb.core.USBTimeoutError("t")] * 3), 1))
        with self.assertRaises(usb.core.USBError):
            aoa_client.phone_reads(Out([usb.core.USBError("gone", errno=errno.ENODEV)]), 5)


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



class MessageSignatureValidationTest(unittest.TestCase):
    """Vectors shared with the phone's JVM tests and the companion's Rust tests."""
    VECTORS = json.loads((Path(__file__).resolve().parent.parent / "app" / "src" / "test" / "resources"
                          / "message-signing-vectors.json").read_text(encoding="utf-8"))

    def vector(self, name):
        return next(v for v in self.VECTORS["vectors"] if v["name"] == name)

    def approved(self, vector):
        return {"id": "m-1", "status": "approved", "address": self.VECTORS["signer"],
                "signature": vector["signature"], "digest": vector["digest"]}

    def test_personal_sign_digest_and_signature_match_the_vector(self):
        v = self.vector("personal-hello")
        message = bytes.fromhex(v["message"][2:])
        digest = aoa_client.personal_message_digest(message)
        self.assertEqual("0x" + digest.hex(), v["digest"])
        request = {"id": "m-1", "method": "personal_sign", "chainId": "0x1", "message": v["message"]}
        aoa_client.validate_message_response(request, self.approved(v), digest, self.VECTORS["signer"])

    def test_typed_data_signature_must_cover_the_expected_digest(self):
        v = self.vector("eip712-mail")
        request = {"id": "m-1", "method": "eth_signTypedData_v4", "chainId": "0x1", "typedData": v["typedData"]}
        digest = bytes.fromhex(v["digest"][2:])
        aoa_client.validate_message_response(request, self.approved(v), digest, self.VECTORS["signer"])
        other = bytes.fromhex(self.vector("permit2-single")["digest"][2:])
        with self.assertRaisesRegex(ValueError, "phone signed digest"):
            aoa_client.validate_message_response(request, self.approved(v), other, self.VECTORS["signer"])
        with self.assertRaisesRegex(ValueError, "expected signer"):
            aoa_client.validate_message_response(
                request, self.approved(v), digest, "0x1111111111111111111111111111111111111111")
        forged = dict(self.approved(v), signature=self.vector("permit2-single")["signature"])
        with self.assertRaises(ValueError):
            aoa_client.validate_message_response(request, forged, digest, self.VECTORS["signer"])
        with self.assertRaisesRegex(ValueError, "malformed"):
            aoa_client.validate_message_response(
                request, dict(self.approved(v), extra="x"), digest, self.VECTORS["signer"])

class AttestResponseValidationTest(unittest.TestCase):
    REQUEST = {"id": "a1", "method": "attest", "challenge": "ab" * 32}

    def ok(self, **changes):
        response = {"id": "a1", "status": "ok", "version": "1",
                    "address": "0x52908400098527886e0f7030069857d2e4169ee7", "securityLevel": "StrongBox",
                    "certificates": "MAA=,MAA=", "signature": "0x" + "30" * 70}
        response.update(changes)
        return response

    def test_accepts_the_protocol_shape(self):
        aoa_client.validate_attest_response(self.REQUEST, self.ok())
        aoa_client.validate_attest_response(self.REQUEST, self.ok(), "0x52908400098527886E0F7030069857D2E4169EE7")
        aoa_client.validate_attest_response(self.REQUEST, {"id": "a1", "status": "error", "error": "x"})

    def test_refuses_drift(self):
        for bad in (self.ok(extra="x"), self.ok(version="2"), self.ok(securityLevel="Software"),
                    self.ok(certificates="MAA="), self.ok(signature="3006"), self.ok(id="a2"),
                    self.ok(address="0x52908400098527886E0F7030069857D2E4169EE7")):
            with self.assertRaises(ValueError):
                aoa_client.validate_attest_response(self.REQUEST, bad)
        with self.assertRaises(ValueError):
            aoa_client.validate_attest_response(self.REQUEST, self.ok(), "0x1111111111111111111111111111111111111111")


class AccountNumberingTest(unittest.TestCase):
    """getAddress names Ledger Live numbering; listAddresses answers are checked strictly."""

    # "abandon x11 about": Standard m/44'/60'/0'/0/i and Ledger Live m/44'/60'/i'/0/0 (bip_utils 2.9.3;
    # the phone's AccountNumberingTest cross-checks them with web3j).
    STANDARD = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
                "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"]
    LEDGER = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265",
              "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231"]

    def test_get_address_with_scheme(self):
        req = {"id": "g", "method": "getAddress"}
        base = {"id": "g", "status": "ok", "address": self.LEDGER[1], "account": "2", "wallet": "standard"}
        aoa_client.validate_response(req, base)
        aoa_client.validate_response(req, dict(base, scheme="ledger-live"))
        for bad in (dict(base, scheme="standard"), dict(base, scheme="ledger"), dict(base, scheme=1)):
            with self.assertRaises(ValueError):
                aoa_client.validate_response(req, bad)

    def test_eip55(self):
        for a in self.STANDARD + self.LEDGER:
            self.assertEqual(aoa_client.eip55(a.lower()), a)

    def request(self, scheme="ledger-live", count="3"):
        return {"id": "l", "method": "listAddresses", "scheme": scheme, "count": count}

    def test_list_addresses_ok_and_rejected(self):
        ok = {"id": "l", "status": "ok", "scheme": "ledger-live", "addresses": ",".join(self.LEDGER)}
        self.assertEqual(aoa_client.validate_list_addresses_response(self.request(), ok), self.LEDGER)
        self.assertEqual(aoa_client.validate_list_addresses_response(self.request(), ok, self.STANDARD[0].lower()), self.LEDGER)
        self.assertEqual(aoa_client.validate_list_addresses_response(self.request(), {"id": "l", "status": "rejected"}), [])
        self.assertEqual(aoa_client.validate_list_addresses_response(
            self.request(), {"id": "l", "status": "error", "error": "x"}), [])

    def test_list_addresses_refuses_drift(self):
        ok = {"id": "l", "status": "ok", "scheme": "ledger-live", "addresses": ",".join(self.LEDGER)}
        for bad in (dict(ok, id="m"), dict(ok, scheme="standard"), dict(ok, extra="1"),
                    dict(ok, addresses=",".join(self.LEDGER[:2])),
                    dict(ok, addresses=",".join(self.LEDGER + self.STANDARD[1:2])),
                    dict(ok, addresses=",".join(a.lower() for a in self.LEDGER)),
                    dict(ok, addresses=",".join([self.LEDGER[0], self.LEDGER[1], self.LEDGER[1]])),
                    dict(ok, addresses=" " + ",".join(self.LEDGER)),
                    dict(ok, addresses=self.LEDGER), {"id": "l", "status": "rejected", "x": "1"}):
            with self.assertRaises(ValueError):
                aoa_client.validate_list_addresses_response(self.request(), bad)
        with self.assertRaises(ValueError):  # Account 1 is not the paired address
            aoa_client.validate_list_addresses_response(self.request(), ok, "0x" + "11" * 20)

    def test_list_addresses_request_shape(self):
        r = aoa_client.request_for(argparse_ns(command="list-addresses", scheme="standard", count="5"))
        self.assertEqual(list(r), ["id", "method", "scheme", "count"])
        self.assertEqual((r["method"], r["scheme"], r["count"]), ("listAddresses", "standard", "5"))


class RequestOptionsTest(unittest.TestCase):
    """--from (multi-account phones) and --host-simulation (the Mac's claim) work together."""

    def sign_args(self, **extra):
        import argparse
        base = dict(command="sign", chain_id="0x1", nonce="0x0", priority_fee="0x1", max_fee="0x2",
                    gas_limit="0x5208", to="0x" + "aa" * 20, value="0x1", data="0x",
                    sender=None, host_simulation=None)
        base.update(extra)
        return argparse.Namespace(**base)

    def test_plain_request_has_neither_optional_field(self):
        request = aoa_client.request_for(self.sign_args())
        self.assertNotIn("from", request)
        self.assertNotIn("hostSimulation", request)

    def test_from_and_host_simulation_together(self):
        import tempfile
        claim = {"changes": [{"asset": "native", "delta": "-1"}], "node": "n", "block": "0x1"}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(claim, f)
        self.addCleanup(Path(f.name).unlink)
        sender = "0x" + "AB" * 20
        request = aoa_client.request_for(self.sign_args(sender=sender, host_simulation=f.name))
        self.assertEqual(request["from"], sender.lower())
        self.assertEqual(request["hostSimulation"], claim)
        self.assertEqual(request["method"], "signEip1559")


class BitcoinTest(unittest.TestCase):
    """btc-account / btc-show / btc-sign request shapes and answer schema checks."""

    FIXTURES = json.loads((Path(__file__).resolve().parent.parent / "app/src/test/resources/btc/psbt-e2e.json").read_text())

    def args(self, command, **extra):
        import argparse
        base = dict(command=command, network="testnet", type="p2wpkh", account="1")
        base.update(extra)
        return argparse.Namespace(**base)

    def test_requests_are_schema_exact_and_psbt_comes_last(self):
        import base64
        import tempfile
        request = aoa_client.request_for(self.args("btc-account", network="bitcoin", type="p2tr", account="3"))
        self.assertEqual(list(request), ["id", "method", "network", "type", "account"])
        show = aoa_client.request_for(self.args("btc-show", change="1", index="7"))
        self.assertEqual(list(show), ["id", "method", "network", "type", "account", "change", "index"])
        psbt = self.FIXTURES["cases"][0]["psbt"]
        for content in (psbt.encode() + b"\n", base64.b64decode(psbt)):
            with tempfile.NamedTemporaryFile("wb", suffix=".psbt", delete=False) as f:
                f.write(content)
            self.addCleanup(Path(f.name).unlink)
            sign = aoa_client.request_for(argparse_ns(command="btc-sign", network="bitcoin", psbt=f.name))
            self.assertEqual(list(sign), ["id", "method", "network", "psbt"])
            self.assertEqual(sign["psbt"], psbt)
            line = json.dumps(sign, separators=(",", ":"))
            self.assertIn('"method":"btcSignPsbt"', line[:200])

    def test_account_answer_checks(self):
        request = {"id": "a", "method": "btcGetAccount", "network": "bitcoin", "type": "p2tr", "account": "1"}
        xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
        ok = {"id": "a", "status": "ok", "fingerprint": "73c5da0a", "path": "m/86'/0'/0'", "xpub": xpub,
              "descriptor": "tr([73c5da0a/86h/0h/0h]" + xpub + "/<0;1>/*)#xf07c0qd"}
        aoa_client.validate_btc_response(request, ok)
        aoa_client.validate_btc_response(request, {"id": "a", "status": "rejected"})
        for bad in (dict(ok, path="m/84'/0'/0'"), dict(ok, extra="1"), dict(ok, fingerprint="73C5DA0A"),
                    dict(ok, descriptor="wpkh" + ok["descriptor"][2:])):
            with self.assertRaises(ValueError):
                aoa_client.validate_btc_response(request, bad)

    def test_signed_psbt_must_grow(self):
        psbt = self.FIXTURES["cases"][1]["psbt"]
        request = {"id": "s", "method": "btcSignPsbt", "network": "bitcoin", "psbt": psbt}
        with self.assertRaises(ValueError):
            aoa_client.validate_btc_response(request, {"id": "s", "status": "approved", "psbt": psbt})


def argparse_ns(**kw):
    import argparse
    return argparse.Namespace(**kw)


if __name__ == "__main__":
    unittest.main()
