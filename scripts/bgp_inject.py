#!/usr/bin/python
"""
bgp_inject.py
BGP inject when DDOS_EVENT equals DDOS_ZONE_ESCALATION

Building Block 1 Metadata and Configuration
Building Block 2 Input Collection
Building Block 3 Trigger Check
Building Block 4 Run Identifier and Start Marker
Building Block 5 Action Execution
Building Block 6 Result Reporting and Error Handling
Building Block 7 Exit Behavior and Idempotency
"""

import os
import time
import json
import ssl
import socket
import datetime
import urllib.request

SYSLOG_SERVER = "<<syslog-server-mgmt-ip>>"
SYSLOG_PORT = 514
LOG_TAG = "DDOS_BGP_INJECT"

AXAPI_HOST = "<<mitigator-mgmt-ip>>"
AXAPI_USER = "admin"
AXAPI_PASS = "<<password>>"
AXAPI_BASE = "https://%s/axapi/v3" % AXAPI_HOST

BGP_ASN = "65003"
PREFIX = "10.109.201.136/29"

INJECT_EVENT = "DDOS_ZONE_ESCALATION"

FACILITY_LOCAL0 = 16
SEVERITY_INFO = 6
PRI = FACILITY_LOCAL0 * 8 + SEVERITY_INFO

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def ts():
    return datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")


def safe(v, default="-", max_len=220):
    if v is None:
        return default
    s = str(v).replace("\n", " ").replace("\r", " ").strip()
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def syslog_send(msg):
    host = socket.gethostname()
    line = "<%d>%s %s %s: %s" % (PRI, ts(), host, LOG_TAG, msg)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(line.encode("utf-8", "ignore"), (SYSLOG_SERVER, SYSLOG_PORT))
    s.close()


def http_post_json(url, payload, signature=None, timeout=8):
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if signature:
        headers["Authorization"] = "A10 %s" % signature
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as r:
        body = r.read().decode("utf-8", errors="replace")
        return r.status, body


def axapi_login():
    url = AXAPI_BASE + "/auth"
    payload = {"credentials": {"username": AXAPI_USER, "password": AXAPI_PASS}}
    status, body = http_post_json(url, payload, timeout=5)
    resp = json.loads(body)
    sig = resp.get("authresponse", {}).get("signature", "")
    if not sig:
        raise RuntimeError("auth missing signature status=%s body=%s" % (status, body[:200]))
    return sig


def clideploy(signature, command_list):
    url = AXAPI_BASE + "/clideploy"
    payload = {"commandList": command_list}
    return http_post_json(url, payload, signature=signature, timeout=10)


def bgp_state(signature):
    _, bgp = clideploy(signature, ["show ip bgp", "exit"])
    _, cfg = clideploy(signature, ["show running-config | section router bgp", "exit"])
    in_bgp = PREFIX in bgp
    in_cfg = ("network %s" % PREFIX) in cfg
    return in_bgp, in_cfg


def inputs():
    return {
        "ddos_event": safe(os.environ.get("DDOS_EVENT", "")),
        "dst_name": safe(os.environ.get("DDOS_DST_NAME", "")),
        "dst_port": safe(os.environ.get("DDOS_DST_PORT", "")),
        "protocol": safe(os.environ.get("DDOS_PROTOCOL", "")),
        "threshold": safe(os.environ.get("DDOS_THRESHOLD", "")),
        "alert_type": safe(os.environ.get("DDOS_ALERT_TYPE", "")),
    }


def should_act(inp):
    return inp.get("ddos_event") == INJECT_EVENT


def main():
    started = time.time()
    inp = inputs()

    run_id = "%d-%d" % (int(time.time()), os.getpid())
    will_act = should_act(inp)

    syslog_send(
        "stage=start run_id=%s event=%s will_act=%s dst=%s proto=%s threshold=%s alert=%s"
        % (
            safe(run_id),
            safe(inp["ddos_event"]),
            str(will_act).lower(),
            safe(inp["dst_name"]),
            safe(inp["protocol"]),
            safe(inp["threshold"]),
            safe(inp["alert_type"]),
        )
    )

    if not will_act:
        syslog_send("stage=end run_id=%s ok=true duration_ms=0 note=skipped" % safe(run_id))
        return 0

    ok = True
    err = ""
    in_bgp = False
    in_cfg = False
    note = ""

    try:
        sig = axapi_login()
        in_bgp, in_cfg = bgp_state(sig)

        if in_bgp and in_cfg:
            note = "already_injected"
        else:
            syslog_send("stage=action run_id=%s action=inject prefix=%s asn=%s" % (safe(run_id), PREFIX, BGP_ASN))
            clideploy(sig, ["router bgp %s" % BGP_ASN, "network %s" % PREFIX, "exit"])
            in_bgp, in_cfg = bgp_state(sig)

    except Exception as e:
        ok = False
        err = safe(e)

    duration_ms = int((time.time() - started) * 1000)
    syslog_send(
        "stage=end run_id=%s ok=%s duration_ms=%s prefix=%s in_bgp=%s in_cfg=%s note=%s err=%s"
        % (
            safe(run_id),
            str(ok).lower(),
            str(duration_ms),
            PREFIX,
            str(in_bgp).lower(),
            str(in_cfg).lower(),
            safe(note, default=""),
            safe(err, default=""),
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
