"""Convert Wazuh Indexer search results into ShadowVault Yocto telemetry."""

import re

import pandas as pd

from utils import YOCTO_LOG_FILENAME, YOCTO_LOG_SCHEMA, normalize_log_frame


FAILED_SSH_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<account>\S+) "
    r"from (?P<remote_ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
AUDIT_KEY_RE = re.compile(r"key=(?:\"|%22)?shadowvault_(?P<key>[a-z_]+)", re.IGNORECASE)
QUOTED_FIELD_RE = re.compile(r"(?P<name>name|path|exe|acct)=\"(?P<value>[^\"]+)\"")


def _deep_get(record, path, default=""):
    if path in record:
        return record[path]
    value = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def _first(record, *paths, default=""):
    for path in paths:
        value = _deep_get(record, path)
        if value not in (None, ""):
            return value
    return default


def _hits(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ValueError("Wazuh export must be a JSON object or a list of records")
    hits = _deep_get(payload, "hits.hits", default=None)
    if hits is None:
        return [payload]
    return hits


def _audit_fields(message):
    return {match.group("name"): match.group("value") for match in QUOTED_FIELD_RE.finditer(message)}


def wazuh_payload_to_frame(payload):
    """Convert a Wazuh ``_search`` JSON response to the canonical Yocto frame."""
    rows = []
    for hit in _hits(payload):
        source = hit.get("_source", hit) if isinstance(hit, dict) else {}
        message = str(_first(source, "full_log", "message"))
        program = str(_first(source, "predecoder.program_name", "data.program"))
        account = str(_first(
            source,
            "data.srcuser",
            "data.dstuser",
            "data.audit.acct",
            "data.audit.loginuid",
        ))
        remote_ip = str(_first(source, "data.srcip", "data.remote_ip"))
        path = str(_first(source, "data.audit.file.name", "data.path"))
        result = str(_first(source, "data.status", "data.audit.success", default="Unknown"))
        event_type = "SYSTEM_LOG"

        ssh_match = FAILED_SSH_RE.search(message)
        if program.lower() == "sshd" and ssh_match:
            event_type = "AUTH_FAILURE"
            account = ssh_match.group("account")
            remote_ip = ssh_match.group("remote_ip")
            result = "Failure"

        decoded_audit_key = str(_first(source, "data.audit.key", "data.key"))
        audit_key_match = AUDIT_KEY_RE.search(message)
        if decoded_audit_key or audit_key_match:
            audit_key = decoded_audit_key.lower().removeprefix("shadowvault_")
            if not audit_key and audit_key_match:
                audit_key = audit_key_match.group("key").lower()
            fields = _audit_fields(message)
            account = fields.get("acct", account)
            if audit_key in {"audit_config", "log_config", "ssh_config"}:
                event_type = "CONFIG_CHANGE"
                path = path or fields.get("name", fields.get("path", ""))
            elif audit_key == "privileged":
                event_type = "PRIVILEGED_EXEC"
                path = str(_first(source, "data.audit.exe")) or path or fields.get("exe", "")
            if result.lower() in {"yes", "true", "success"} or "success=yes" in message.lower():
                result = "Success"

        rows.append({
            "Timestamp": _first(source, "timestamp", "@timestamp"),
            "Hostname": _first(source, "agent.name", "predecoder.hostname", "data.hostname"),
            "SourceIP": _first(source, "agent.ip", "location"),
            "Program": program,
            "EventType": event_type,
            "Account": account,
            "RemoteIP": remote_ip,
            "Path": path,
            "Result": result,
            "Message": message,
        })

    frame = pd.DataFrame(rows, columns=YOCTO_LOG_SCHEMA)
    return normalize_log_frame(frame, YOCTO_LOG_FILENAME)
