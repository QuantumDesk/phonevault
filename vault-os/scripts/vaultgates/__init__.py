"""Phone Vault release gates and the Android file-format parsers they share.

The bash gates in vault-os/scripts/ and vault-os/dev-ladder*/ run these modules through
vault-os/scripts/vaultgate.py, which puts vault-os/scripts (and not the caller's working
directory) on sys.path, so a gate behaves the same from any directory.

Shared parsers:
  init_props  Android init property files (property_service.cpp LoadProperties, ExpandProps)
  init_rc     Android init .rc tokenizer (init/tokenizer.cpp) and section keywords
  overrides   Blueprint `overrides: [...]` lists and their absence from target-files
"""
