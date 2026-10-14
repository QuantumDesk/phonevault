"""Patch provenance: every imported (GrapheneOS) patch is a pinned, reviewed allowlist record
with its original authorship; every other patch is Phone Vault's own.

  vaultgate.py patch-provenance REPOSITORY_ROOT
"""

import hashlib
import pathlib
import re
import sys


def main(argv):
    root = pathlib.Path(argv[0]).resolve()
    patch_root = root / "vault-os/patches"
    catalog_path = patch_root / "README.md"
    if not catalog_path.is_file():
        raise SystemExit("patch provenance failed: missing vault-os/patches/README.md")
    catalog = catalog_path.read_text(encoding="utf-8")

    # Every external import is an explicit allowlist record. The digest pins the
    # reviewed mail-patch bytes, including original authorship and commit message.
    imports = {
        "frameworks-base/0001-reject-ambiguous-recovery-signatures.patch": {
            "sha256": "03fb0e744b0616cbf12e126499dfb5ce9e8b3f89d2c5a56b4e8fb6eb44026db0",
            "commit": "4a3b6b70826c2a6efdbba28c87c9a88f52a33850",
            "author": "Daniel Micay <daniel.micay@grapheneos.org>",
            "subject": "fix upstream RecoverySystem.verifyPackage vulnerability",
        },
        "frameworks-base/0002-disable-apex-installation-on-user-builds.patch": {
            "sha256": "65b29f0a550478d0040b2ce19c672c0417b05f2aab7c50bb7916bdef197b4d01",
            "commit": "b471ebaaac9a190e3c61b51e5671573d2af5f45d",
            "author": "Dmitry Muhomor <muhomor.dmitry@gmail.com>",
            "subject": "don't allow to install APEXes on user builds",
        },
    }

    patches = sorted(patch_root.rglob("*.patch"))
    if not patches:
        raise SystemExit("patch provenance failed: patch inventory is empty")

    for relative, expected in imports.items():
        path = patch_root / relative
        if not path.is_file():
            raise SystemExit(f"patch provenance failed: missing approved import {relative}")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected["sha256"]:
            raise SystemExit(
                f"patch provenance failed: reviewed bytes changed for {relative}: {digest}"
            )
        text = data.decode("utf-8")
        required_headers = (
            f"From {expected['commit']} Mon Sep 17 00:00:00 2001",
            f"From: {expected['author']}",
            f"Subject: [PATCH] {expected['subject']}",
        )
        for header in required_headers:
            if header not in text:
                raise SystemExit(
                    f"patch provenance failed: {relative} lacks original header: {header}"
                )
        upstream_url = (
            "https://github.com/GrapheneOS/platform_frameworks_base/commit/"
            + expected["commit"]
        )
        if upstream_url not in catalog:
            raise SystemExit(
                f"patch provenance failed: catalog lacks upstream URL for {relative}"
            )

    approved_paths = {str((patch_root / item).resolve()) for item in imports}
    for path in patches:
        if str(path.resolve()) in approved_paths:
            continue
        text = path.read_text(encoding="utf-8")
        author_match = re.search(r"(?m)^From:\s*(.+)$", text)
        if author_match and "Phone Vault Project <build@phonevault.invalid>" not in author_match.group(1):
            relative = path.relative_to(patch_root)
            raise SystemExit(
                "patch provenance failed: unregistered external author in "
                f"{relative}: {author_match.group(1)}"
            )

    if "Vault OS does not fork GrapheneOS wholesale" not in catalog:
        raise SystemExit("patch provenance failed: selective-import boundary is undocumented")
    if "They must not be represented as GrapheneOS work." not in catalog:
        raise SystemExit("patch provenance failed: Phone Vault patch ownership is ambiguous")

    print(
        f"Patch provenance passed: {len(imports)} pinned GrapheneOS imports, "
        f"{len(patches) - len(imports)} project patches."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
