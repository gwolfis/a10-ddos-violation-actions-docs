#!/usr/bin/env python3
import json
import re
import ssl
import time
import uuid
import urllib.request
import urllib.error

# ====== CONFIG ======
TPS_HOST = "<<mitigator-mgmt-ip>>"
TPS_USER = "admin"
TPS_PASS = "<<password>>"
TPS_AXAPI_BASE = f"https://{TPS_HOST}/axapi/v3"

SYSLOG_FILE = "/var/log/tps.log"
OUT_JSONL = "/var/log/ddos_script_observability.jsonl"
OUT_HUMAN = "/var/log/ddos_watch_human.log"

# Trigger on script executions and level changes
TRIGGERS = (
    "Script:",
    "move to level",
)

# Avoid spamming snapshots during bursts
MIN_SECONDS_BETWEEN_SNAPSHOTS = 2

# What we want to validate / summarize
EXPECTED_PREFIX = "10.109.201.136/29"
PREFIX_FILTER = "10.109.201."  # Only show relevant prefixes in readable summary
BODY_SNIPPET_LEN = 600  # Keep JSONL compact; full text isn't needed most of the time

# ====== SSL (ignore cert validation; lab-friendly) ======
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ====== REGEX PARSERS ======
RE_SCRIPT = re.compile(
    r"Script:\s+(?P<script>[^ ]+)\s+Type:\s+(?P<type>\w+)\s+Status:\s+(?P<status>\w+)\.",
    re.IGNORECASE,
)
RE_LEVEL = re.compile(r"move to level\s+(?P<level>\d+)", re.IGNORECASE)
RE_ZONE = re.compile(r"\[(?P<zone>zone[^\]\s]+)\]", re.IGNORECASE)
RE_TRAFFIC = re.compile(r"\[traffic-type\s+(?P<traffic>[^\]]+)\]", re.IGNORECASE)
RE_SRC_DST = re.compile(r"\[(?P<src>\d+\.\d+\.\d+\.\d+)->(?P<dst>[^\]]+)\]", re.IGNORECASE)
RE_DDET_ID = re.compile(r"\[DDET\]<\d+>\s+(?P<ddet_id>\d+):", re.IGNORECASE)

RE_BGP_PREFIX_COUNT = re.compile(r"Total number of prefixes\s+(?P<count>\d+)", re.IGNORECASE)
RE_BGP_PREFIX_LINE = re.compile(r"^\*>\s+(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)", re.IGNORECASE)


# ====== IO HELPERS ======
def write_jsonl(obj):
    with open(OUT_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def write_human(line: str):
    with open(OUT_HUMAN, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def shorten(text: str, limit: int) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + " ..."


def follow(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")


def line_is_trigger(line):
    low = line.lower()
    for t in TRIGGERS:
        if t.lower() in low:
            return True
    return False


# ====== AXAPI ======
def http_request(method, path, payload=None, signature=None, timeout=8):
    url = TPS_AXAPI_BASE + path
    headers = {"Content-Type": "application/json"}
    if signature:
        headers["Authorization"] = f"A10 {signature}"

    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as r:
            raw = r.read()
            text = raw.decode("utf-8", errors="replace")
            return r.status, dict(r.headers), text
    except urllib.error.HTTPError as e:
        raw = e.read()
        text = raw.decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTPError status={e.code} body_snippet={text[:200]!r}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"URLError reason={e.reason!r}")


def axapi_login():
    status, headers, text = http_request(
        "POST",
        "/auth",
        payload={"credentials": {"username": TPS_USER, "password": TPS_PASS}},
        timeout=5,
    )
    try:
        resp = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError(f"Auth non-JSON status={status} body_snippet={text[:200]!r}")

    sig = resp.get("authresponse", {}).get("signature", "")
    if not sig:
        raise RuntimeError(f"Auth missing signature status={status} body_snippet={text[:200]!r}")
    return sig


def clideploy_text(signature, command_list):
    status, headers, text = http_request(
        "POST",
        "/clideploy",
        payload={"commandList": command_list},
        signature=signature,
        timeout=10,
    )
    return {"http_status": status, "body": text}


# ====== PARSING / READABLE SUMMARY ======
def parse_event_summary(line: str) -> dict:
    summary = {
        "raw": line,
        "ddet_id": None,
        "script": None,
        "script_type": None,
        "script_status": None,
        "level": None,
        "zone": None,
        "traffic_type": None,
        "src_ip": None,
        "dst_id": None,
    }

    m = RE_DDET_ID.search(line)
    if m:
        summary["ddet_id"] = m.group("ddet_id")

    m = RE_SCRIPT.search(line)
    if m:
        summary["script"] = m.group("script")
        summary["script_type"] = m.group("type")
        summary["script_status"] = m.group("status")

    m = RE_LEVEL.search(line)
    if m:
        try:
            summary["level"] = int(m.group("level"))
        except ValueError:
            summary["level"] = None

    m = RE_TRAFFIC.search(line)
    if m:
        summary["traffic_type"] = m.group("traffic").strip()

    m = RE_SRC_DST.search(line)
    if m:
        summary["src_ip"] = m.group("src").strip()
        summary["dst_id"] = m.group("dst").strip()
        if summary["zone"] is None and m.group("dst").lower().startswith("zone"):
            summary["zone"] = m.group("dst").strip()

    m = RE_ZONE.search(line)
    if m and summary["zone"] is None:
        summary["zone"] = m.group("zone").strip()

    return summary


def extract_bgp_summary(show_ip_bgp_text: str) -> dict:
    count = None
    m = RE_BGP_PREFIX_COUNT.search(show_ip_bgp_text)
    if m:
        try:
            count = int(m.group("count"))
        except ValueError:
            count = None

    prefixes = []
    for ln in show_ip_bgp_text.splitlines():
        mm = RE_BGP_PREFIX_LINE.match(ln.strip())
        if not mm:
            continue
        pfx = mm.group("prefix")
        if PREFIX_FILTER and PREFIX_FILTER not in pfx:
            continue
        prefixes.append(pfx)

    return {"prefix_count": count, "relevant_prefixes": prefixes}


def build_readable(event_summary: dict, bgp_body: str, bgp_cfg_body: str) -> dict:
    bgp_info = extract_bgp_summary(bgp_body)

    prefix_in_table = EXPECTED_PREFIX in bgp_body
    prefix_in_cfg = f"network {EXPECTED_PREFIX}" in bgp_cfg_body

    return {
        "ddet_id": event_summary.get("ddet_id"),
        "zone": event_summary.get("zone"),
        "traffic_type": event_summary.get("traffic_type"),
        "level": event_summary.get("level"),
        "script": event_summary.get("script"),
        "script_status": event_summary.get("script_status"),
        "expected_prefix": EXPECTED_PREFIX,
        "expected_prefix_in_bgp_table": prefix_in_table,
        "expected_prefix_in_bgp_config": prefix_in_cfg,
        "bgp_prefix_count": bgp_info.get("prefix_count"),
        "bgp_relevant_prefixes": bgp_info.get("relevant_prefixes"),
    }


def mk_human(ts: str, event: dict, readable: dict) -> str:
    zone = readable.get("zone") or event.get("zone") or "-"
    lvl = readable.get("level")
    traffic = readable.get("traffic_type") or event.get("traffic_type") or "-"
    script = readable.get("script") or event.get("script") or "-"
    status = readable.get("script_status") or event.get("script_status") or "-"
    ddet = readable.get("ddet_id") or event.get("ddet_id") or "-"

    pfx = readable.get("expected_prefix")
    in_tbl = readable.get("expected_prefix_in_bgp_table")
    in_cfg = readable.get("expected_prefix_in_bgp_config")
    cnt = readable.get("bgp_prefix_count")

    return (
        f"{ts} ddet_id={ddet} zone={zone} traffic={traffic} level={lvl} "
        f"script={script} status={status} "
        f"expected_prefix={pfx} in_bgp={in_tbl} in_cfg={in_cfg} bgp_count={cnt}"
    )


# ====== MAIN LOOP ======
def main():
    sig = ""
    last_login = 0.0
    last_snapshot = 0.0

    for line in follow(SYSLOG_FILE):
        if not line_is_trigger(line):
            continue

        now = time.time()
        if (now - last_snapshot) < MIN_SECONDS_BETWEEN_SNAPSHOTS:
            continue
        last_snapshot = now

        run_id = str(uuid.uuid4())
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        event_summary = parse_event_summary(line)

        try:
            if (not sig) or ((now - last_login) > 300):
                sig = axapi_login()
                last_login = now

            bgp = clideploy_text(sig, ["show ip bgp", "exit"])
            bgp_cfg = clideploy_text(sig, ["show running-config | section router bgp", "exit"])

            bgp_body = bgp.get("body", "")
            bgp_cfg_body = bgp_cfg.get("body", "")

            readable = build_readable(event_summary, bgp_body, bgp_cfg_body)

            # Human-readable log lines (every entry starts with timestamp)
            write_human(mk_human(ts, event_summary, readable))
            pfxs = readable.get("bgp_relevant_prefixes", [])
            if pfxs:
                write_human(f"{ts} prefixes={','.join(pfxs)}")

            # JSONL record (structured), keep bodies as snippets to reduce noise
            record = {
                "ts": ts,
                "run_id": run_id,
                "trigger_line": line,
                "event_summary": event_summary,
                "readable": readable,
                "axapi": {
                    "show_ip_bgp": {
                        "http_status": bgp.get("http_status"),
                        "body_snippet": shorten(bgp_body, BODY_SNIPPET_LEN),
                    },
                    "show_bgp_config": {
                        "http_status": bgp_cfg.get("http_status"),
                        "body_snippet": shorten(bgp_cfg_body, BODY_SNIPPET_LEN),
                    },
                },
            }
            write_jsonl(record)

        except Exception as e:
            err = str(e)
            write_human(f"{ts} ERROR trigger={event_summary.get('raw')} err={err}")
            write_jsonl(
                {
                    "ts": ts,
                    "run_id": run_id,
                    "trigger_line": line,
                    "event_summary": event_summary,
                    "error": err,
                }
            )


if __name__ == "__main__":
    main()