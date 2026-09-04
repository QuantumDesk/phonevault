# No blanket keep for web3j: R8 tree-shakes to the classes the signer actually references
# (Credentials, Bip32ECKeyPair, MnemonicUtils, Sign, Numeric, RLP …). Nothing on the signing
# path is reached via reflection, so Jackson-based WalletFile support, the unused Bouncy Castle
# algorithm families (GOST, PQC, …) and the rest are removed from the release DEX.
# vault-os/tests/test-app-build-policy.sh greps the release DEX to keep it that way.
-dontwarn org.slf4j.**
-dontwarn com.google.errorprone.annotations.FormatMethod
-dontwarn javax.annotation.Nullable
-dontwarn com.fasterxml.jackson.**
-dontwarn org.bouncycastle.**
