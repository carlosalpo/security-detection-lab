# Verification

The release is checked with unit and integration tests and a separate installed-CLI matrix. The fixtures' expected alert contracts are independent of the detection engine. Successful verification includes expected nonzero exits: the deliberate expectation mismatch must exit 1, and conflicting event payloads must exit 2 without creating output.

Local commands and CI are documented in the README. CI uploads the generated replay packages for each supported Python version. Published capture evidence and release provenance are added after the final source revision is verified.
