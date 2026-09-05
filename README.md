# Guild Passport

Guild Passport is a consent-first portable credential record. The deployer authorizes issuers; an issuer drafts a passport; the subject consents; validators bind issuer-registry and credential evidence before activation. Only the issuer may revoke an active passport.

Issuer and subject identities are normalized as address strings at the calldata boundary. IDs cannot be reused, sources must use independent HTTPS hosts, and all claim codes and digests are validator checked. Run `python -m pytest -q` and `genvm-lint contract/guild_passport.py`.
