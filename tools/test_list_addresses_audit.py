#!/usr/bin/env python3
"""Audit tests for `aoa_client.py list-addresses` (account numbering)."""

from pathlib import Path
import sys
import types
import unittest

try:
    import usb.core  # noqa: F401
except ImportError:  # only the pure validators are exercised; no USB needed
    _usb = types.ModuleType("usb")
    _usb.core = types.ModuleType("usb.core")
    _usb.util = types.ModuleType("usb.util")
    sys.modules.update({"usb": _usb, "usb.core": _usb.core, "usb.util": _usb.util})

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aoa_client

STD = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"]
LL = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265"]


def request(scheme="ledger-live", count="2"):
    return {"id": "l1", "method": "listAddresses", "scheme": scheme, "count": count}


def ok(req, addresses):
    return {"id": req["id"], "status": "ok", "scheme": req["scheme"], "addresses": ",".join(addresses)}


class ListAddressesAudit(unittest.TestCase):
    def test_strict_shape(self):
        req = request()
        self.assertEqual(aoa_client.validate_list_addresses_response(req, ok(req, LL), STD[0]), LL)
        for bad in (
            dict(ok(req, LL), extra="1"),
            dict(ok(req, LL), scheme="standard"),
            ok(req, [a.lower() for a in LL]),
            ok(req, [LL[0], LL[0]]),
            ok(req, LL[:1]),
            dict(ok(req, LL), addresses=LL),
        ):
            with self.assertRaises(ValueError):
                aoa_client.validate_list_addresses_response(req, bad, STD[0])

    def test_pinned_non_account1_signer_does_not_reject_the_genuine_wallet(self):
        """`pair` pins whatever account is active (any Account N). list-addresses compares the first
        listed address with the pin only when the pin is Account 1; a pinned Account 2+ is looked
        for in the list, with a clear warning (not a refusal) when it isn't there."""
        req = request()
        addresses = aoa_client.validate_list_addresses_response(req, ok(req, LL))
        # Standard Account 2 pinned, Ledger Live list: not in it -> a warning, the wallet isn't refused
        warning = aoa_client.check_list_against_pairing(addresses, {"address": STD[1].lower(), "account": "2"})
        self.assertRegex(warning, "Account 2.*not among these 2 addresses")
        # an older pairing file without an account number: the same membership check
        self.assertIsNotNone(aoa_client.check_list_against_pairing(addresses, {"address": STD[1].lower(), "account": None}))
        # the pinned account is in the list: nothing to say
        std = aoa_client.validate_list_addresses_response(request("standard"), ok(request("standard"), STD))
        self.assertIsNone(aoa_client.check_list_against_pairing(std, {"address": STD[1].lower(), "account": "2"}))
        self.assertIsNone(aoa_client.check_list_against_pairing(std, {"address": STD[1].lower(), "account": None}))
        # a pinned Account 1 must be first: another wallet is refused
        self.assertIsNone(aoa_client.check_list_against_pairing(addresses, {"address": LL[0].lower(), "account": "1"}))
        with self.assertRaisesRegex(ValueError, "not the paired wallet"):
            aoa_client.check_list_against_pairing(addresses, {"address": "0x" + "11" * 20, "account": "1"})
        # nothing pinned: nothing to compare
        self.assertIsNone(aoa_client.check_list_against_pairing(addresses, None))

    def test_pairing_records_the_account_number(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pairing.json")
            aoa_client.save_paired_signer(path, STD[1], "2")
            self.assertEqual(aoa_client.load_pairing(path), {"address": STD[1].lower(), "account": "2"})
            self.assertEqual(aoa_client.load_paired_signer(path), STD[1].lower())
            aoa_client.save_paired_signer(path, STD[0])
            self.assertEqual(aoa_client.load_pairing(path)["account"], None)
            with self.assertRaises(ValueError):
                aoa_client.save_paired_signer(path, STD[0], "0")


if __name__ == "__main__":
    unittest.main()
