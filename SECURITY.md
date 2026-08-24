# Security and Safety Scope

Operation ShadowVault is a defensive training project. It generates CSV log records that represent a fictional ransomware incident and analyzes those records.

The repository does not contain or execute:

- Malware or ransomware payloads.
- File-encryption or destructive routines.
- Credential-dumping implementations.
- Exploit code, persistence mechanisms, or command-and-control infrastructure.
- Real credentials, personal data, production hostnames, or routable attacker addresses.

All external addresses use IANA documentation space. Do not use this project as evidence that a detection is production ready without validation on authorized telemetry.

The optional `meta-shadowvault` layer installs audit watches and log forwarding
only. It does not contain active-response, exploitation, persistence, or attack
simulation code. Its default TCP syslog configuration is intended for the
isolated lab network; production deployments must use authenticated encryption,
device-specific credentials or certificates, data minimization, and an approved
retention policy.

If you find an unsafe file or exposed secret in a fork, remove it from public access and report it privately to the repository owner.
