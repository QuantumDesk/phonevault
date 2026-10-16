#!/usr/bin/env python3
"""Audit proofs for `aoa_client.py list-addresses` (account numbering)."""

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

    def test_finding_pinned_non_account1_signer_rejects_the_genuine_wallet(self):
        """FINDING (low, fail-closed): `pair` pins whatever account is active (any Account N);
        list-addresses then defaults expected_first to that pin and refuses the user's own wallet
        with "this is not the paired wallet" whenever the pinned account is not Account 1."""
        req = request()
        pinned_account_2 = STD[1]  # what `pair` stores when Account 2 was active
        with self.assertRaisesRegex(ValueError, "not the paired wallet"):
            aoa_client.validate_list_addresses_response(req, ok(req, LL), pinned_account_2)


if __name__ == "__main__":
    unittest.main()
