#!/usr/bin/python
"""
Example Violation Action Script (didactic): Syslog notification on a single event

This script follows the "Minimal Building Blocks" blueprint exactly.
Use case: when DDOS_EVENT == DDOS_INDICATOR_EXCEED, send one syslog line to an
external syslog server with key runtime context.

Assumptions (based on probe results in this environment)
- Python runtime: /usr/bin/python (Python 3.x)
- Third-party modules like requests are not available
- stdout/stderr may not be visible, so we use UDP syslog as output

Building Blocks referenced below:
1 Metadata and Configuration
2 Input Collection
3 Trigger Check
4 Run Identifier and Start Marker
5 Action Execution
6 Result Reporting and Error Handling
7 Exit Behavior and Idempotency
"""

# ===== Building Block 1: Metadata and Configuration =====
import os
import socket
import datetime
import time

SYSLOG_SERVER = "<<syslog-server-mgmt-ip>>"
SYSLOG_PORT = 514
LOG_TAG = "DDOS_EXAMPLE_MIN"

# Syslog PRI = facility(local0=16) * 8 + severity(info=6)
FACILITY_LOCAL0 = 16
SEVERITY_INFO = 6
PRI = FACILITY_LOCAL0 * 8 + SEVERITY_INFO

# Only act on this event in this simple example
ALLOWED_EVENTS = {"DDOS_INDICATOR_EXCEED"}


def _syslog_timestamp_utc():
    return datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")


def _safe(value, default="-", max_len=220):
    if value is None:
        return default
    s = str(value).replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _send_syslog(message):
    """
    Sends one UDP syslog message to the external syslog server.
    """
    host = socket.gethostname()
    line = "<%d>%s %s %s: %s" % (PRI, _syslog_timestamp_utc(), host, LOG_TAG, message)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(line.encode("utf-8", "ignore"), (SYSLOG_SERVER, SYSLOG_PORT))
    s.close()


# ===== Building Block 2: Input Collection =====
def _collect_inputs():
    """
    Read the DDOS_* variables that are expected in this environment.
    Keep it small and predictable.
    """
    return {
        "ddos_event": os.environ.get("DDOS_EVENT", ""),
        "dst_name": os.environ.get("DDOS_DST_NAME", ""),
        "dst_port": os.environ.get("DDOS_DST_PORT", ""),
        "protocol": os.environ.get("DDOS_PROTOCOL", ""),
        "threshold": os.environ.get("DDOS_THRESHOLD", ""),
        "alert_type": os.environ.get("DDOS_ALERT_TYPE", ""),
    }


# ===== Building Block 3: Trigger Check (Eligibility) =====
def _should_act(inputs):
    """
    Only act for allowed DDOS_EVENT values.
    """
    return inputs.get("ddos_event") in ALLOWED_EVENTS


def main():
    started = time.time()

    # ===== Building Block 2: Input Collection =====
    inputs = _collect_inputs()

    # ===== Building Block 3: Trigger Check =====
    if not _should_act(inputs):
        return 0

    # ===== Building Block 4: Run Identifier and Start Marker =====
    run_id = "%d-%d" % (int(time.time()), os.getpid())
    _send_syslog(
        "stage=start run_id=%s event=%s dst=%s proto=%s threshold=%s"
        % (
            _safe(run_id),
            _safe(inputs.get("ddos_event")),
            _safe(inputs.get("dst_name")),
            _safe(inputs.get("protocol")),
            _safe(inputs.get("threshold")),
        )
    )

    ok = True
    err = ""

    try:
        # ===== Building Block 5: Action Execution =====
        # Simple action: emit a single structured notification line.
        _send_syslog(
            "stage=action run_id=%s action=notify event=%s dst=%s dst_port=%s proto=%s threshold=%s alert=%s"
            % (
                _safe(run_id),
                _safe(inputs.get("ddos_event")),
                _safe(inputs.get("dst_name")),
                _safe(inputs.get("dst_port")),
                _safe(inputs.get("protocol")),
                _safe(inputs.get("threshold")),
                _safe(inputs.get("alert_type")),
            )
        )

    except Exception as e:
        # ===== Building Block 6: Result Reporting and Error Handling =====
        ok = False
        err = _safe(e)

    # ===== Building Block 6: Result Reporting and Error Handling =====
    duration_ms = int((time.time() - started) * 1000)
    _send_syslog(
        "stage=end run_id=%s ok=%s duration_ms=%s err=%s"
        % (_safe(run_id), str(ok).lower(), str(duration_ms), _safe(err))
    )

    # ===== Building Block 7: Exit Behavior and Idempotency =====
    # This script is idempotent because it only logs.
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())