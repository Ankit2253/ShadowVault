SUMMARY = "Hardened embedded Linux endpoint for the ShadowVault SOC lab"
DESCRIPTION = "A minimal Yocto image with Linux auditing and queued TCP syslog forwarding."
LICENSE = "MIT"

inherit core-image

IMAGE_FEATURES:append = " ssh-server-openssh"
IMAGE_FEATURES:remove = "allow-empty-password empty-root-password"

IMAGE_INSTALL:append = " \
    auditd \
    rsyslog \
    shadowvault-telemetry \
"

# Do not add debug-tweaks or hard-coded credentials. Provision an SSH key in a
# private deployment layer when interactive access is required.
