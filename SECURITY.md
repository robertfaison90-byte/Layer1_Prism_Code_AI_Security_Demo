# Security policy

This is a reference tool for local model artifact provenance. It is not a complete model security platform. Send suspected vulnerabilities privately to the maintainer using GitHub private vulnerability reporting after repository setup, or an approved private channel. Do not post exploit details or sensitive material publicly before a fix. The repository owner should configure a dedicated contact and response time before publication.

Trust model: an independently obtained public key is mandatory. A tag and key obtained together from an untrusted source do not authenticate the signer. Keep private keys outside Git; rotate/revoke compromised keys through a deployment-specific policy. Do not load untrusted model files even after digest verification; tagging proves only who signed these bytes and that they are unchanged relative to the signature, not model safety or training quality.
