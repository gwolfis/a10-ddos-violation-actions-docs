#!/usr/bin/python
import os
import sys
import time
import socket
import datetime

SYSLOG_SERVER = "<<syslog-server-mgmt-ip>>"
SYSLOG_PORT = 514
TAG = "DDOS_PROBE_V2"

FACILITY_LOCAL0 = 16
SEVERITY_INFO = 6
PRI = FACILITY_LOCAL0 * 8 + SEVERITY_INFO

MAX_ENV_LINES = 150
MAX_VALUE_LEN = 220

def _ts():
    return datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")

def syslog_send(msg):
    try:
        host = socket.gethostname()
        line = "<%d>%s %s %s: %s" % (PRI, _ts(), host, TAG, msg)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(line.encode("utf-8", "ignore"), (SYSLOG_SERVER, SYSLOG_PORT))
        s.close()
    except Exception:
        pass

def safe(v):
    if v is None:
        return ""
    v = str(v)
    if len(v) > MAX_VALUE_LEN:
        return v[:MAX_VALUE_LEN] + "..."
    return v

def which(cmd):
    path = os.environ.get("PATH", "")
    for d in path.split(":"):
        if not d:
            continue
        p = d + "/" + cmd
        try:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        except Exception:
            pass
    return ""

def try_import(name):
    try:
        __import__(name)
        return True, ""
    except Exception as e:
        return False, safe(e)

def probe_env():
    syslog_send("section=env start python=%s" % safe(sys.version.replace("\n", " ")))
    keys = sorted([k for k in os.environ.keys() if k.startswith("DDOS_")])
    syslog_send("section=env ddos_keys_count=%s ddos_event=%s" % (len(keys), safe(os.environ.get("DDOS_EVENT"))))

    n = 0
    for k in keys:
        if n >= MAX_ENV_LINES:
            syslog_send("section=env truncated lines=%s" % MAX_ENV_LINES)
            break
        syslog_send("env %s=%s" % (k, safe(os.environ.get(k))))
        n += 1
    syslog_send("section=env end")

def probe_imports():
    modules = [
        "os","sys","time","datetime","json","base64","socket","ssl",
        "re","subprocess",
        "urllib","urllib2","httplib",
        "requests","yaml","paramiko","OpenSSL",
        "Crypto","cryptography","netaddr","ipaddress","lxml"
    ]

    ok_list = []
    bad_list = []

    syslog_send("section=imports start")
    for m in modules:
        ok, err = try_import(m)
        if ok:
            ok_list.append(m)
            syslog_send("import module=%s ok=true" % m)
        else:
            bad_list.append(m)
            syslog_send("import module=%s ok=false err=%s" % (m, err))
    syslog_send("section=imports summary ok=%s missing=%s" % (len(ok_list), len(bad_list)))
    if bad_list:
        syslog_send("section=imports missing_list=%s" % ",".join(bad_list))
    syslog_send("section=imports end")

def probe_shell_tools():
    syslog_send("section=shell start")

    interpreters = [
        "sh","bash","ash","busybox","python","python2","python3"
    ]
    tools = [
        "curl","wget","logger","nc","netcat","socat",
        "grep","sed","awk","cut","tr","head","tail",
        "ping","ip","ifconfig","route","ss","netstat"
    ]

    present = []
    missing = []

    for c in interpreters + tools:
        p = which(c)
        if p:
            present.append(c)
            syslog_send("tool name=%s present=true path=%s" % (c, p))
        else:
            missing.append(c)
            syslog_send("tool name=%s present=false" % c)

    syslog_send("section=shell summary present=%s missing=%s" % (len(present), len(missing)))
    syslog_send("section=shell end")

def main():
    run_id = "%d-%d" % (int(time.time()), os.getpid())
    syslog_send("run start run_id=%s ddos_event=%s" % (run_id, safe(os.environ.get("DDOS_EVENT"))))
    probe_env()
    probe_imports()
    probe_shell_tools()
    syslog_send("run end run_id=%s" % run_id)

if __name__ == "__main__":
    main()
