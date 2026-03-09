# A10 DDoS Defend – Violation Action Execute Scripts

This documentation explains how to use **Violation Action → Execute Script** in  
A10 DDoS Defend (TPS / Mitigator) and A10 Control.

The goal is to make script-based automation predictable and observable in real
deployments.

The official documentation describes the feature conceptually, but it does not
fully explain:

- the runtime environment of Execute Scripts
- how events are delivered to scripts
- how to reliably debug and validate script behavior
- how to build safe automation workflows

This documentation fills those gaps using a **probe-driven and observability-first approach**.

**Security note on AXAPI credentials**

Some script examples in this documentation use the `admin` account when interacting with AXAPI.  
This is done purely for simplicity and readability in lab examples.

In production environments it is considered a **security best practice** to create a dedicated automation account instead of using the `admin` user.

The recommended approach is to:

- Create a **separate service account** for automation scripts  
- Grant only the **minimum required privileges** needed for the specific task  
- Avoid using shared administrative credentials in scripts  
- Store credentials securely and restrict access to the script files

Using a dedicated least-privilege account reduces the potential impact of credential exposure and helps align with common operational security policies.

---

# What this documentation covers

This guide focuses on three core areas.

## 1 Understanding the Execute Script runtime

Violation Action scripts run inside a restricted runtime environment on the TPS.

Important characteristics discovered in lab testing include:

- Python runtime available but **standard library only**
- Limited shell utilities
- Output typically **not visible locally**
- Debugging must be done through **external logging**

Understanding these constraints is essential before developing scripts.

---

## 2 Building observability

Because script output is not easily visible on the TPS itself, this guide first
introduces an **observability pipeline** based on:

- TPS syslog forwarding
- External syslog server
- Python watcher (`ddos_watch`)
- AXAPI snapshots for device state verification

This allows you to see exactly:

- when scripts execute
- which events triggered them
- what actions they performed
- what the device state was at that moment

---

## 3 Building automation use cases

Once the runtime and observability model are understood, Violation Action
scripts can be used for several automation scenarios.

The most common use cases include:

### Network automation
- BGP prefix injection
- BGP prefix withdrawal
- Traffic diversion during attacks

### Integration workflows
- Cloud scrubbing provider signals
- Ticketing or SOC notifications
- ChatOps integration

### Operational automation
- Incident journaling
- Observability triggers
- Forensic logging

---

# Recommended reading order

The documentation is structured to follow the same order used during the lab
validation process.

1. **Building Observability for Violation Action Scripts**  
   How to capture script events and device state.

2. **Violation Action Script Runtime Reality**  
   What the Execute Script environment actually supports.

3. **Script Development Blueprint**  
   A consistent structure for writing reliable scripts.

4. **Understanding DDOS Events**  
   How events such as `DDOS_INDICATOR_EXCEED`,
   `DDOS_ZONE_ESCALATION`, and `DDOS_ZONE_DE_ESCALATION`
   are delivered depending on the attachment point.

5. **Use Case Examples – BGP Automation**  
   Injecting and withdrawing prefixes based on DDoS escalation.

6. **Combined Script Example**  
   Using a single script that decides between inject and withdraw.

7. **Integration Use Cases**  
   Signaling external platforms such as cloud scrubbing providers.

8. **Additional Use Case Ideas**  
   Further automation patterns for observability, security, and operations.

---

# Design principles used in this guide

All examples in this documentation follow the same design principles.

### Observability first
Every script should produce clear external logging so execution can be verified.

### Idempotent actions
Scripts should never break if executed multiple times.

### Minimal runtime dependencies
Scripts must work with the Python standard library only.

### External validation
Device state should always be verified externally through AXAPI or CLI.

---

# Intended audience

This guide is intended for:

- network engineers deploying **A10 DDoS Defend**
- automation engineers building **mitigation workflows**
- operators integrating **TPS events with SOC or orchestration platforms**

---

# Disclaimer

The examples in this documentation were developed and validated in a lab
environment.

Actual behavior of `DDOS_EVENT` delivery and attachment points may vary depending
on:

- ACOS / TPS version
- configuration structure
- protocol type
- mitigation policy design

Always validate behavior using **event probes** before enabling production
automation.