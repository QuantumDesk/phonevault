#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
docker build \
  --platform linux/amd64 \
  --tag phone-vault-lineage-builder:24.04 \
  "${ROOT}/build-container"
