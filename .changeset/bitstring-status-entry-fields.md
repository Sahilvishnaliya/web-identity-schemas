---
"web-identity-schemas": patch
---

Preserve the BitstringStatusListEntry spec fields (statusSize, statusMessage, statusReference) on CredentialStatus instead of silently stripping them during parsing, per the BitstringStatus List spec §2.1
