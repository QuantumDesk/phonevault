#!/usr/bin/env python3
"""Run one Phone Vault gate module: vaultgate.py GATE [ARGS...]

Run by path (python3 vault-os/scripts/vaultgate.py ...), never with -m: Python then puts
this directory on sys.path instead of the working directory, so the gate imports this
checkout's vaultgates package (and the standard library) from any directory.
"""

import importlib
import sys

GATES = {
    "production-target-files": "vaultgates.production_target_files",
    "release-source": "vaultgates.release_source",
    "owner-provisioning-policy": "vaultgates.owner_provisioning",
    "patch-provenance": "vaultgates.patch_provenance",
    "overrides": "vaultgates.overrides",
    "bluejay-check-build": "vaultgates.bluejay_check_build",
    "adb-keys-links": "vaultgates.adb_keys_links",
}


def main(argv):
    if not argv or argv[0] not in GATES:
        print("usage: vaultgate.py {" + ",".join(GATES) + "} [ARGS...]", file=sys.stderr)
        return 2
    module = importlib.import_module(GATES[argv[0]])
    return module.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
