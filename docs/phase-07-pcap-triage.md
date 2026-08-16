# Phase 07 — TraceHound: PCAP Triage & Behavioral Analysis

> **Manual Analyst Workflow → Python Automation → Timing Heuristics → Multi-PCAP Validation → Analyst Leads**

---

## Phase Overview

The first six phases of this project built the lab, established baseline traffic, introduced Zeek and Suricata, and completed three progressively harder investigations: **BLACK SIGNAL**, **GHOST CHANNEL**, and **NIGHTFALL**.

By the end of those investigations, the same first-pass tasks kept recurring:

- establish capture size and duration
- identify dominant protocols and conversations
- count TCP connection attempts and responses
- extract repeated DNS queries
- calculate inter-event timing
- compare repeated TLS sessions
- inspect HTTP paths, User-Agents, and response codes
- decide which observations deserved deeper review

Phase 7 asked:

> **Can the repetitive parts of that workflow be automated without automating the analyst's conclusion?**

The result was **TraceHound**, a Python + Scapy PCAP triage utility derived from techniques that had already been performed manually in the lab.

TraceHound does not replace Wireshark, TShark, Zeek, Suricata, or analyst reasoning. It moves an analyst from an unfamiliar PCAP to a concise set of evidence-backed leads faster.

---

# Design Principle — Evidence Before Verdict

The project keeps three layers separate:

```text
Raw evidence
    ↓
Tool observation
    ↓
Analyst inference
```

A repeated DNS cadence can be measured from timestamps. TraceHound can call it a **periodicity candidate**. It cannot call it command-and-control without additional evidence.

A URI can contain traversal syntax. TraceHound can surface a **path traversal pattern**. It cannot claim successful file disclosure unless the response proves it.

The tool therefore uses language such as:

```text
worth review
candidate
repeated activity
analyst validation required
```

rather than:

```text
malware detected
C2 confirmed
host compromised
attack successful
```

---

# Development Environment

| Component | Role |
|---|---|
| Kali Linux VM | TraceHound development and PCAP analysis |
| Python 3.13.12 | Runtime |
| Scapy | Packet parsing |
| TShark | Independent field extraction and validation |
| capinfos | Independent capture metadata validation |
| Phase 4–6 PCAPs | Behavioral regression / validation set |

The Python runtime was independently recorded as `3.13.12`. Scapy is required, but this public write-up does **not** claim an exact Scapy minor version unless that version is re-verified from the development environment.

Final source:

```text
tools/pcap-triage/tracehound.py
```

Development checkpoints were kept locally; the repository contains the finished tool only.

---

# v0.1 — Capture Summary

The first version established a reliable base:

- packet count
- total bytes
- duration
- protocol distribution
- top bidirectional IP conversations

Against NIGHTFALL, TraceHound reported:

```text
Packets    : 90
Bytes      : 10796
Duration   : 342.302 seconds
TCP        : 73
UDP        : 13
ARP        : 4
```

The dominant conversation was:

```text
192.168.0.147 <-> 192.168.0.194
73 packets
```

![TraceHound capture summary](../evidence/images/phase7_01_tracehound_capture_summary.png)

`capinfos` independently returned 90 packets and a `342.301555` second duration. TShark independently returned `TCP 73`, `UDP 13`, and `ARP 4`.

> **TraceHound output was not trusted merely because TraceHound produced it. Important features had to be independently reproduced before acceptance.**

---

# v0.2 — TCP Connection Triage

TraceHound extracted initial client SYN packets and correlated SYN-ACK and RST responses.

NIGHTFALL reconstructed the seven-port pattern:

```text
22
80
443
8080
8443
9443
9999
```

TCP/8080 stood apart:

```text
8080 → 6 SYN, 6 SYN-ACK, 0 RST
```

The other six tested ports each produced a reset.

![TraceHound TCP connection triage](../evidence/images/phase7_02_tracehound_tcp_connection_triage.png)

The tool surfaced:

```text
multi-port connection pattern worth review
```

rather than automatically calling it a scan.

Independent TShark filters matched the showcased NIGHTFALL counts.

---

# v0.3 — DNS Triage

BLACK SIGNAL was used to validate DNS extraction.

TraceHound found:

```text
Total DNS queries : 8
Unique domains    : 1
Querying hosts    : 1

pulse.blacksignal.test : 8 queries
```

![TraceHound DNS triage](../evidence/images/phase7_03_tracehound_dns_triage.png)

Repetition alone was not the important behavior. The next requirement was timing.

---

# v0.4 — DNS Timing & Periodicity

BLACK SIGNAL's captured intervals were:

```text
10.169s
10.117s
10.042s
10.141s
10.143s
4.903s
5.035s
```

The retry-like tail pulled the simple mean down to `8.650s`, while the median remained `10.117s`.

To avoid letting a small number of outliers hide the dominant pattern, TraceHound added interval clustering using a tolerance of:

```text
max(1 second, candidate × 15%)
```

The result:

```text
Dominant interval : 10.122s
Pattern support   : 5/7 intervals (71.4%)
Outside pattern   : 2 intervals
Timing confidence : HIGH
```

![TraceHound BLACK SIGNAL periodicity](../evidence/images/phase7_04_tracehound_black_signal_periodicity.png)

The correct conclusion remained:

> **A dominant recurring DNS timing pattern exists and deserves analyst review.**

The query timestamps and interval sequence were independently reproduced with TShark before acceptance.

---

# v0.5 — Jitter-Aware TCP Session Timing

GHOST CHANNEL used six encrypted sessions separated by deliberately variable delays:

```text
8.196s
13.114s
9.119s
15.163s
7.172s
```

TraceHound added coefficient-of-variation analysis:

```text
CV = population standard deviation / mean interval
```

Result:

```text
Connections           : 6
Mean interval         : 10.553s
Standard deviation    : 3.061s
Coefficient variation : 29.0%
Timing pattern        : JITTERED
Timing confidence     : MEDIUM
```

![TraceHound GHOST CHANNEL jitter analysis](../evidence/images/phase7_05_tracehound_ghost_channel_jitter.png)

This described the statistical character of the traffic without assigning malicious intent.

---

# v0.6 — TLS ClientHello SNI Correlation

The TLS parser was not restricted to TCP/443 because GHOST CHANNEL used TCP/9443.

TraceHound extracted:

```text
ClientHello SNI observations : 6
Unique SNI names             : 1
sync.ghostchannel.test       : 6 observations
```

and correlated them with:

```text
192.168.0.147 -> 192.168.0.194:9443
```

![TraceHound TLS SNI triage](../evidence/images/phase7_06_tracehound_tls_sni_triage.png)

The combined evidence was stronger than timing alone:

```text
repeated TCP sessions
        +
moderate timing jitter
        +
same TLS SNI
```

But the encrypted payload remained unavailable, so the result stayed **worth analyst review**, not `C2 confirmed`.

---

# v0.7 — HTTP Triage

NIGHTFALL required plaintext HTTP parsing.

TraceHound extracted:

- request method
- request path
- User-Agent
- source/destination
- destination port
- response status code

It reconstructed all five requests:

```text
/update.dat
/eicar.com
/../../../../etc/passwd
/checkin?id=imac&status=ok
/checkin?id=imac&status=ok
```

and counted:

```text
HTTP requests      : 5
Unique paths       : 4
Unique User-Agents : 4
200 responses      : 2
404 responses      : 3
```

It surfaced the traversal-shaped URI as a path anomaly.

![TraceHound NIGHTFALL HTTP triage](../evidence/images/phase7_07_tracehound_nightfall_http_triage.png)

The tool did **not** claim successful traversal because the earlier manual investigation proved the request received HTTP 404 and no `/etc/passwd` contents were returned.

---

# v1.0 — Analyst Leads

The final version consolidated stronger observations into:

```text
[ANALYST LEADS]
```

Current lead types:

```text
MULTI-PORT ACTIVITY
RECURRING TCP TIMING
REPEATED TLS IDENTITY
DNS PERIODICITY
REPEATED HTTP ACTIVITY
HTTP PATH ANOMALY
```

Each lead contains evidence, context, assessment, and a `REVIEW` priority.

TraceHound intentionally does not assign business severity or maliciousness from packet structure alone.

---

# Final Multi-PCAP Validation

The finished v1.0 code was replayed against all three investigation PCAPs with the same generic logic and no case-specific expected answers hardcoded into the script.

```text
BLACK SIGNAL
  → DNS PERIODICITY

GHOST CHANNEL
  → RECURRING TCP TIMING
  → REPEATED TLS IDENTITY

NIGHTFALL
  → MULTI-PORT ACTIVITY
  → RECURRING TCP TIMING
  → REPEATED HTTP ACTIVITY
  → HTTP PATH ANOMALY
```

![TraceHound final multi-PCAP validation](../evidence/images/phase7_08_tracehound_final_multi_pcap_validation.png)

The script did not contain the following as expected answers:

```text
pulse.blacksignal.test
sync.ghostchannel.test
/update.dat
/eicar.com
/checkin?id=imac&status=ok
/../../../../etc/passwd
```

Those values were extracted from the captures at runtime.

---

# What TraceHound Automates

```text
read packet capture
      ↓
summarize protocols and conversations
      ↓
extract TCP / DNS / TLS / HTTP evidence
      ↓
calculate repeated timing behavior
      ↓
surface candidate patterns
      ↓
produce analyst leads
```

It helps answer questions such as:

- Which hosts dominate the capture?
- Which destination ports were contacted?
- Which services responded differently?
- Which domains repeat?
- Are repeated events regular or jittered?
- Do repeated TLS sessions share an SNI?
- Which HTTP resources repeat?
- Are there path patterns worth reviewing?

---

# What TraceHound Does Not Automate

TraceHound does **not** answer contextual questions such as:

```text
Is this malware?
Is this command-and-control?
Was exploitation successful?
Is this user behavior legitimate?
How severe is this activity?
Does this represent compromise?
```

NIGHTFALL demonstrates why. The generic TCP timing engine saw six TCP/8080 sessions and classified their spacing as jittered with medium confidence. Statistically that was correct. Analytically, those sessions represented multiple HTTP actions: artifact retrievals, a traversal attempt, and repeated check-ins.

> **A statistically recurring service pattern is an investigative lead, not proof that every session belongs to one behavioral sequence.**

---

# Technical Architecture

Major logical areas in `tracehound.py` include:

```text
packet loading / iteration
protocol classification
IP conversation tracking
TCP state triage
TCP session timestamp collection
DNS extraction and timing
TLS ClientHello / SNI parsing
HTTP request / response parsing
behavioral heuristics
analyst lead consolidation
report rendering
```

State is primarily stored with Python `Counter`, `defaultdict`, lists, and sets. Sets are used where duplicate session or TLS observations could otherwise inflate certain behavioral analyses.

---

# Heuristic Design

### Multi-Port Review

A source/destination pair is surfaced when at least four destination ports are observed. This is a review threshold, **not** a scan signature.

### DNS Periodicity

DNS periodicity requires at least four events and three intervals. The dominant cluster uses:

```text
max(1.0 second, candidate interval × 15%)
```

Confidence depends on event count, cluster support, and variation inside the dominant cluster.

### TCP Timing

Repeated TCP timing uses coefficient of variation and describes patterns as:

```text
REGULAR
JITTERED
VARIABLE
IRREGULAR
```

These are statistical descriptions, not maliciousness labels.

### Repeated TLS Identity

The Analyst Leads stage requires at least four observations of the same SNI on the same source/destination/service tuple.

### Repeated HTTP Paths

A path repeated at least twice can be surfaced for review.

### Traversal Review

Common literal or encoded parent-directory patterns are surfaced. The presence of syntax does not prove successful file access.

---

# Validation Philosophy

Feature development followed a consistent pattern:

```text
build feature
    ↓
run TraceHound
    ↓
state exactly what it claims
    ↓
reproduce the claim with an independent tool
    ↓
accept or fix the implementation
```

Examples included:

- `capinfos` vs capture metadata
- TShark vs protocol counts
- TShark conversations vs host summaries
- TShark SYN/SYN-ACK/RST filters vs TCP triage
- TShark DNS timestamps vs periodicity
- TShark TCP SYN timestamps vs jitter analysis
- TShark TLS fields vs SNI extraction
- TShark HTTP fields vs URI and response-code counts

This reduced the risk of trusting the tool merely because it was self-written.

---

# v1.0 Limitations

### IPv4-Focused Deep Analysis

Capture summaries and basic conversation handling can observe IPv6, and DNS source extraction has an IPv6 path. However, the validated deep TCP connection, timing, TLS SNI, and HTTP analysis path is primarily implemented inside the IPv4 TCP flow.

The showcased Phase 4–6 validation captures are IPv4. IPv6 behavioral parity is therefore **not claimed**.

### Raw TCP Flag Counts Can Include Retransmissions

Initial SYN sessions are deduplicated for repeated-session timing, but displayed SYN / SYN-ACK / RST triage counters are packet-observation counts rather than a full TCP-state reconstruction engine. Retransmissions can influence those raw counters in other captures.

### Multi-Port Review Is Not Time-Windowed

The v1.0 multi-port heuristic does not require the observed ports to occur within a strict time window. Long captures can therefore surface legitimate multi-service activity.

### DNS Timing Uses Observed Query Events

Retries or retransmission-like behavior can influence DNS interval series. The full interval sequence and outliers remain visible to the analyst.

The detailed DNS timing section also uses the generic phrase `periodicity candidate; analyst review required` once enough events exist for analysis, including LOW-confidence cases. The final **Analyst Leads** stage is stricter and promotes DNS periodicity only at HIGH or MEDIUM confidence. The confidence field is the controlling signal.

### No Full TCP Reassembly

HTTP or TLS metadata split across packets can be missed because the tool parses individual packet payloads rather than performing full stream reassembly.

### Metadata Is Not Payload Meaning

TLS SNI is visible before encryption; encrypted application payload meaning is not.

### Timing Can Produce False Leads

Backups, health checks, monitoring, software updates, and other legitimate automation can generate regular or jittered traffic.

### Grouping Is Simplified

Repeated TCP timing is grouped by source IP, destination IP, and destination port. Different application actions against one service can therefore be grouped into one timing series.

### Incomplete Captures Change Conclusions

Packet loss, capture filters, or beginning capture mid-session can change counts, timing, and response correlation.

### Pattern Recognition Is Not Exploit Validation

A repeated domain, traversal-shaped path, or multi-port pattern describes network evidence. It does not establish intent, compromise, or impact on its own.

These boundaries are why every final report ends with:

```text
First-pass triage complete. Analyst review required.
```

---

# Raw Validation Captures

The original project PCAPs are preserved locally and their SHA-256 hashes are recorded in the repository.

They are intentionally not distributed in the public portfolio repository because packet captures can preserve network metadata beyond the fields highlighted in the write-ups.

External readers can inspect the code, screenshots, hashes, custom rule, and analysis documents, but cannot replay the exact private lab captures from this repository alone.

---

# Skills Demonstrated

- Python security scripting
- Scapy packet parsing
- PCAP iteration and metadata extraction
- TCP flag analysis
- conversation aggregation
- statistical timing analysis
- coefficient-of-variation reasoning
- tolerance-based interval clustering
- DNS behavior analysis
- TLS ClientHello / SNI extraction
- plaintext HTTP parsing
- defensive pattern heuristics
- false-positive-aware analyst language
- independent tool validation
- regression testing across multiple investigation datasets
- translating manual analyst workflows into repeatable automation

---

# Interview Talking Point

> **After manually completing three network investigations, I built TraceHound to automate the repetitive first-pass triage I kept performing by hand. It parses PCAPs with Scapy, summarizes conversations, evaluates TCP connection behavior, measures DNS and TCP timing, extracts TLS SNI and plaintext HTTP metadata, and surfaces evidence-backed analyst leads. I independently validated each major feature with TShark or capinfos and replayed the same generic tool against all three prior cases. The important design choice was that it never claims C2 or compromise from heuristics alone — it automates evidence collection while leaving final interpretation to the analyst.**

---

# Final Result

The project progression became:

```text
Capture traffic
      ↓
Understand normal behavior
      ↓
Investigate suspicious behavior manually
      ↓
Correlate with Zeek and Suricata
      ↓
Identify and close a detection gap
      ↓
Automate repetitive triage with TraceHound
```

TraceHound successfully surfaced the defining behaviors of BLACK SIGNAL, GHOST CHANNEL, and NIGHTFALL using the same generic analysis code.

> **Automation is most useful when it makes evidence easier to find without pretending to replace the analyst who must interpret it.**
