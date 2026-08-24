SUMMARY = "Audit and syslog policy for a ShadowVault embedded endpoint"
DESCRIPTION = "Installs defensive audit watches and a queued TCP forwarder for the SOC lab."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = " \
    file://30-shadowvault.rules \
    file://90-shadowvault-forward.conf \
"

S = "${WORKDIR}"

SHADOWVAULT_LOG_HOST ?= "10.10.5.20"
SHADOWVAULT_LOG_PORT ?= "514"

do_install() {
    install -d ${D}${sysconfdir}/audit/rules.d
    install -m 0640 ${WORKDIR}/30-shadowvault.rules \
        ${D}${sysconfdir}/audit/rules.d/30-shadowvault.rules

    install -d ${D}${sysconfdir}/rsyslog.d
    sed \
        -e 's/@SHADOWVAULT_LOG_HOST@/${SHADOWVAULT_LOG_HOST}/g' \
        -e 's/@SHADOWVAULT_LOG_PORT@/${SHADOWVAULT_LOG_PORT}/g' \
        ${WORKDIR}/90-shadowvault-forward.conf \
        > ${D}${sysconfdir}/rsyslog.d/90-shadowvault-forward.conf
    chmod 0640 ${D}${sysconfdir}/rsyslog.d/90-shadowvault-forward.conf
}

RDEPENDS:${PN} = "auditd rsyslog"

CONFFILES:${PN} += " \
    ${sysconfdir}/audit/rules.d/30-shadowvault.rules \
    ${sysconfdir}/rsyslog.d/90-shadowvault-forward.conf \
"
