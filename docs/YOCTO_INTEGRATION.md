# Yocto Embedded Endpoint Integration

This optional path adds an embedded Linux endpoint to the ShadowVault SOC lab.
It does not alter the labelled Windows ransomware benchmark.

## Data flow

```text
Yocto endpoint
  ├─ Linux audit rules
  └─ system and SSH logs
          │
          ▼ TCP syslog (isolated lab)
      Wazuh server
          │
          ▼ authorized JSON export
  ShadowVault Yocto adapter
          │
          ▼
  ATT&CK-mapped alerts and incident timeline
```

The preferred target is Yocto Project 6.0 "Wrynose" LTS. The Yocto Project
lists it as supported until April 2030:
<https://docs.yoctoproject.org/dev/ref-manual/release-process.html>

## 1. Prepare a Linux build host

Use a distribution supported by the selected Yocto release and follow the
official host package and storage requirements:
<https://docs.yoctoproject.org/ref-manual/system-requirements.html>

Windows is not a native Yocto build host. Use a dedicated Linux VM or host. WSL2
can be useful for experimentation, but the Yocto documentation does not treat it
as a validated production build environment.

## 2. Add the layer

Clone matching branches of Poky and meta-openembedded, initialize the build
environment, and add both `meta-oe` and this repository's layer:

```bash
git clone -b wrynose https://git.yoctoproject.org/poky
git clone -b wrynose https://git.openembedded.org/meta-openembedded
source poky/oe-init-build-env build-shadowvault
bitbake-layers add-layer ../meta-openembedded/meta-oe
bitbake-layers add-layer /absolute/path/to/ShadowVault/meta-shadowvault
```

Add lab-specific settings to `conf/local.conf`:

```bitbake
MACHINE = "qemux86-64"
SHADOWVAULT_LOG_HOST = "10.10.5.20"
SHADOWVAULT_LOG_PORT = "514"
```

Build the image:

```bash
bitbake shadowvault-soc-image
```

The layer deliberately avoids hard-coded passwords and `debug-tweaks`. Add an
SSH public key through a private deployment layer if interactive access is
required.

## 3. Configure Wazuh to receive the device logs

The image forwards `.info` and higher messages over TCP. On the Wazuh server,
add an authorized lab subnet inside `<ossec_config>`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.10.30.0/24</allowed-ips>
  <local_ip>10.10.5.20</local_ip>
</remote>
```

`allowed-ips` is mandatory for a Wazuh syslog listener. Restart the manager
after validating the configuration. Current Wazuh guidance is here:
<https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html>

TCP/514 is acceptable only inside the isolated learning network. For real
devices, use an authenticated and encrypted relay design and document data
retention, access control, and certificate rotation.

## 4. Convert an authorized Wazuh export

Export only the Yocto endpoint records from the Wazuh Indexer `_search` API and
save the JSON response locally. Never commit credentials or production logs.

```bash
python scripts/convert_wazuh_yocto.py \
  wazuh-yocto-search.json \
  yocto_device_events.csv
```

The converter understands Wazuh `_search` responses, extracts standard SSH and
ShadowVault audit records, and writes the canonical schema shown in
`data/samples/yocto_device_events.csv`.

Upload the four core CSV files plus the optional Yocto CSV in the Streamlit
dashboard. ShadowVault adds embedded-endpoint findings to the investigation but
does not calculate synthetic benchmark metrics for uploaded data.

## 5. Detection coverage

| Behavior | ATT&CK | Evidence |
|---|---|---|
| Repeated SSH authentication failures | T1110.001 | Five failures from one source within ten minutes |
| Privileged command from a non-root account | T1548.003 | Audit record keyed `shadowvault_privileged` |
| Audit, logging, or SSH configuration change | T1562.001 | Audit watches under `/etc/audit`, `/etc/rsyslog*`, and `sshd_config` |

## 6. Validation checklist

1. Run `bitbake-layers show-layers` and confirm `shadowvault` is present.
2. Build `shadowvault-soc-image` without `debug-tweaks`.
3. Confirm audit and rsyslog services are active on the target.
4. Generate a harmless test message with `logger` and confirm it reaches Wazuh.
5. Confirm only the lab subnet is accepted by the Wazuh syslog listener.
6. Convert a bounded Wazuh export and run the included Python tests.
7. Document the image revision, layer commit, device identifier, and evidence timestamps.

The repository CI performs parser, detector, and static layer-policy checks. A
successful BitBake build and device test must be recorded separately because the
full Yocto toolchain is intentionally not downloaded in lightweight CI.
