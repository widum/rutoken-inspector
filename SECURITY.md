# Security policy

## Important data handling

- Never post signing private keys, `.key` containers, token PINs, PFX/PKCS#12, secret files or private backups in public issues.
- Before attaching a diagnostic log, remove names, serial numbers, personal identifiers, usernames, file paths and certificate subjects.
- Use a separate test token and a non-production key for functional tests.
- Confirm any file-writing operations before running them; keep separate offline backups.
- Private security reports should be sent through a private communication channel set up by repository maintainers. Public issue reports must contain only sanitized reproduction steps.

## Scope

This application is an independent diagnostic tool and is not security-certified or endorsed by token or crypto-provider manufacturers.
