# Linux build container

The Android host tools are Linux x86-64 binaries. On Apple Silicon this image
runs as `linux/amd64` through Docker Desktop's Rosetta emulation. It is expected
to be substantially slower than a native x86-64 Linux workstation.

Rosetta is a development convenience, not a release build environment. ART's
x86-64 `dex2oat` can abort under emulation when a compressed heap reference is
mapped above 4 GiB. A local bring-up build may set `WITH_DEXPREOPT=false` to
avoid that host-only step; production artifacts must be rebuilt with dexpreopt
enabled on native x86-64 Linux and pass the same target-files gates.

The source and output live in the named `phone-vault-lineage` Docker volume so
they use Docker's case-sensitive Linux filesystem. The host project is mounted
read-only at `/workspace`; `install-overlay.sh` copies reviewed Vault OS files
into the source checkout.

Give Docker Desktop as much RAM as you can (64 GB works) and a large disk. The
official LineageOS guidance for version 21 and newer is 400 GB, so the build may
require a larger external disk or a native Linux host. Ccache is capped at
5 GB and source sync is depth-limited to reduce local use.
