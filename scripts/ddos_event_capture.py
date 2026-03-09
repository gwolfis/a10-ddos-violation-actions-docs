#!/usr/bin/python
import os
import socket
import datetime
import time

SYSLOG_SERVER = "<<syslog-server-mgmt-ip>>"
SYSLOG_PORT = 514
TAG = "DDOS_EVENT_CAPTURE_L1"
#TAG = "DDOS_EVENT_CAPTURE_L2"
#TAG = "DDOS_EVENT_CAPTURE_L3"

FACILITY_LOCAL0 = 16
SEVERITY_INFO = 6
PRI = FACILITY_LOCAL0 * 8 + SEVERITY_INFO

def ts():
    return datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")

def safe(v):
    if v is None:
        return "-"
    s = str(v).replace("\n", " ").replace("\r", " ")
    return s

def send(msg):
    host = socket.gethostname()
    line = "<%d>%s %s %s: %s" % (PRI, ts(), host, TAG, msg)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(line.encode("utf-8", "ignore"), (SYSLOG_SERVER, SYSLOG_PORT))
    s.close()

def main():
    run_id = "%d-%d" % (int(time.time()), os.getpid())

    event = os.environ.get("DDOS_EVENT")
    dst = os.environ.get("DDOS_DST_NAME")
    port = os.environ.get("DDOS_DST_PORT")
    proto = os.environ.get("DDOS_PROTOCOL")
    thresh = os.environ.get("DDOS_THRESHOLD")
    alert = os.environ.get("DDOS_ALERT_TYPE")

    send("run_id=%s event=%s dst=%s proto=%s dst_port=%s threshold=%s alert=%s" %
         (safe(run_id), safe(event), safe(dst), safe(proto), safe(port), safe(thresh), safe(alert)))

if __name__ == "__main__":
    main()