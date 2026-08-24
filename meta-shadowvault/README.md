# meta-shadowvault

Optional Yocto/OpenEmbedded layer for a monitored ShadowVault embedded Linux endpoint.

## Compatibility

- Yocto Project 6.0 "Wrynose" LTS (preferred)
- Yocto Project 5.0 "Scarthgap" LTS
- `openembedded-core` plus `meta-openembedded/meta-oe`

## Contents

- `shadowvault-soc-image`: minimal image with OpenSSH, audit, rsyslog, and the telemetry policy.
- `shadowvault-telemetry`: audit watches and queued TCP syslog forwarding.
- `linux-yocto_%.bbappend`: enables kernel audit support for `linux-yocto` targets.
- `rsyslog_%.bbappend`: ensures the `imfile` input module is available.

Set the collector at build time:

```bitbake
SHADOWVAULT_LOG_HOST = "10.10.5.20"
SHADOWVAULT_LOG_PORT = "514"
```

Do not add `debug-tweaks`, empty root passwords, private keys, or production
credentials to the public layer. For a non-`linux-yocto` BSP, enable equivalent
kernel audit options in that BSP's kernel configuration.

Full build and validation instructions are in [`../docs/YOCTO_INTEGRATION.md`](../docs/YOCTO_INTEGRATION.md).
