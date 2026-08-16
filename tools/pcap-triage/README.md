# TraceHound

> **PCAP Triage & Behavioral Analysis**

TraceHound is a lightweight Python utility built during Phase 7 of the **Network Detection & Packet Forensics Home Lab** to automate repetitive first-pass PCAP triage without replacing analyst judgment.

The tool reads packet captures with Scapy, extracts observable network behavior, calculates timing patterns, and consolidates stronger observations into an **Analyst Leads** section for deeper manual review.

> **Packets provide the evidence. TraceHound surfaces the leads. The analyst decides what they mean.**

---

## Why I Built It

The first six phases of this project required repeated manual work across Wireshark, TShark, Zeek, and Suricata: identifying conversations, counting connection attempts, extracting DNS queries, comparing timestamps, reconstructing HTTP activity, and deciding which patterns deserved more attention.

TraceHound was built only after those workflows had been performed manually.

The goal was therefore not to create another generic packet parser. It was to automate repetitive triage while preserving the distinction between:

1. **Raw evidence** — what the packets contain.
2. **Tool observation** — what TraceHound calculates or surfaces.
3. **Analyst inference** — what the behavior may mean in context.

TraceHound deliberately avoids claims such as `C2 detected`, `malware confirmed`, or `host compromised` when the PCAP does not prove them.

---

## Capabilities

TraceHound v1.0 performs:

- capture packet, byte, and duration summaries
- protocol distribution
- top IP conversation ranking
- TCP SYN / SYN-ACK / RST triage
- multi-port connection-pattern review
- repeated TCP session timing analysis
- jitter-aware timing classification using coefficient of variation
- DNS query extraction and repeated-domain counting
- DNS inter-query interval analysis
- dominant periodicity clustering with outlier tolerance
- TLS ClientHello SNI extraction, including non-standard TLS ports
- repeated TLS identity correlation
- plaintext HTTP method, path, response-code, and User-Agent extraction
- repeated HTTP resource identification
- traversal-like HTTP path review
- consolidated behavioral **Analyst Leads**

---

## Requirements

The project validation used Python 3.13.12. TraceHound requires **Scapy** for packet parsing.

The repository intentionally does not claim an exact Scapy minor version unless that version is independently re-verified from the development environment.

Install dependencies from the repository root:

```bash
python3 -m pip install -r requirements.txt
```

or install Scapy directly:

```bash
python3 -m pip install scapy
```

Check the local versions if needed:

```bash
python3 --version
python3 -c "import scapy; print(scapy.__version__)"
```

---

## Usage

Make the script executable:

```bash
chmod +x tracehound.py
```

Run it against a PCAP file:

```bash
./tracehound.py capture.pcap
```

or:

```bash
python3 tracehound.py capture.pcap
```

Example from this lab:

```bash
./tracehound.py ~/network-forensics-lab/pcaps/phase6_nightfall_blind_case.pcap
```

Project validation used `.pcap` captures. PCAPNG compatibility is not advertised as validated in v1.0.

---

## Report Structure

A full report can contain:

```text
[CAPTURE SUMMARY]
[PROTOCOL DISTRIBUTION]
[TOP IP CONVERSATIONS]
[TCP CONNECTION TRIAGE]
[TCP SESSION TIMING ANALYSIS]
[TLS CLIENT HELLO TRIAGE]
[HTTP REQUEST TRIAGE]
[DNS TRIAGE]
[DNS TIMING ANALYSIS]
[ANALYST LEADS]
```

Sections remain visible even when a protocol is absent so the analyst can quickly see what was and was not present in the capture.

---

## TCP Connection Triage

TraceHound groups initial SYN attempts by source, destination, and destination port, then correlates server SYN-ACK and RST behavior.

Example NIGHTFALL output:

```text
PORT       SYN   SYN-ACK    RST   RESPONSE
22           1         0      1   RST observed
80           1         0      1   RST observed
443          1         0      1   RST observed
8080         6         6      0   SYN-ACK observed
8443         1         0      1   RST observed
9443         1         0      1   RST observed
9999         1         0      1   RST observed
```

If one source contacts at least four destination ports, TraceHound surfaces a **multi-port connection pattern worth review**.

It does **not** automatically call that behavior reconnaissance or scanning.

---

## Repeated TCP Timing

For repeated TCP sessions to the same source/destination/service tuple, TraceHound calculates:

```text
mean interval
median interval
minimum interval
maximum interval
standard deviation
coefficient of variation
```

The coefficient of variation is used to describe timing as regular, jittered, variable, or irregular.

GHOST CHANNEL produced:

```text
Connections          : 6
Intervals            : 8.196s, 13.114s, 9.119s, 15.163s, 7.172s
Mean interval        : 10.553s
Coefficient variation: 29.0%
Timing pattern       : JITTERED
Timing confidence    : MEDIUM
```

This is surfaced as a **recurring connection timing candidate**, not confirmed command-and-control activity.

---

## DNS Periodicity Analysis

TraceHound records timestamps for repeated queries from the same source to the same domain and calculates inter-query intervals.

A simple average can hide useful structure when retries or outliers are present. To avoid that, TraceHound searches for the strongest interval cluster using a bounded tolerance and reports both the dominant interval and how many intervals support it.

BLACK SIGNAL produced:

```text
Events               : 8
Intervals            : 10.169s, 10.117s, 10.042s, 10.141s, 10.143s, 4.903s, 5.035s
Mean interval        : 8.650s
Median interval      : 10.117s
Dominant interval    : 10.122s
Pattern support      : 5/7 intervals (71.4%)
Outside pattern      : 2 interval(s)
Timing confidence    : HIGH
```

The two shorter intervals remained visible rather than being discarded. The tool therefore surfaced the dominant cadence while preserving the retry-like tail for analyst interpretation.

---

## TLS SNI Analysis

TraceHound inspects TCP payloads for TLS ClientHello records and extracts Server Name Indication values directly.

This is intentionally not restricted to TCP/443.

During GHOST CHANNEL, the tool correlated six repeated connections to TCP/9443 with six ClientHello observations containing:

```text
sync.ghostchannel.test
```

That produced the lead:

```text
REPEATED TLS IDENTITY
```

The SNI is evidence of the TLS identity requested by the client. It does not prove the encrypted payload's purpose.

---

## HTTP Triage

TraceHound parses plaintext HTTP requests contained in individual TCP payloads and extracts:

- method
- path / URI
- User-Agent
- source and destination
- destination port
- response status code

During NIGHTFALL it reconstructed:

```text
GET /update.dat
GET /eicar.com
GET /../../../../etc/passwd
GET /checkin?id=imac&status=ok
GET /checkin?id=imac&status=ok
```

It also identified:

```text
200 responses: 2
404 responses: 3
```

and surfaced the traversal-like path:

```text
/../../../../etc/passwd
```

as an HTTP path anomaly worth review.

A traversal-shaped request is not treated as proof of successful exploitation.

---

## Analyst Leads

TraceHound v1.0 ends with a condensed behavioral summary so an analyst can see the strongest observations without reading every raw section first.

Current lead categories are:

```text
MULTI-PORT ACTIVITY
RECURRING TCP TIMING
REPEATED TLS IDENTITY
DNS PERIODICITY
REPEATED HTTP ACTIVITY
HTTP PATH ANOMALY
```

Each lead records:

```text
Evidence
Context
Assessment
Priority
```

Priority is intentionally limited to `REVIEW` in v1.0. TraceHound is a triage utility, not a risk-scoring or maliciousness engine.

---

## Validation

TraceHound was replayed against the three PCAP investigations already completed manually in this project.

### BLACK SIGNAL

TraceHound surfaced:

```text
DNS PERIODICITY
```

It independently extracted eight queries to `pulse.blacksignal.test` and identified a dominant interval of approximately `10.122s` with `5/7` interval support.

### GHOST CHANNEL

TraceHound surfaced:

```text
RECURRING TCP TIMING
REPEATED TLS IDENTITY
```

It independently reconstructed six repeated TLS sessions to TCP/9443, classified their spacing as jittered with a `29.0%` coefficient of variation, and extracted the repeated SNI `sync.ghostchannel.test` six times.

### NIGHTFALL

TraceHound surfaced:

```text
MULTI-PORT ACTIVITY
RECURRING TCP TIMING
REPEATED HTTP ACTIVITY
HTTP PATH ANOMALY
```

It independently found the seven-port connection pattern, distinguished TCP/8080 from the reset services, reconstructed the five HTTP requests, identified the repeated check-in path, and surfaced the traversal-like URI.

---

## Independent Verification

During development, important outputs were checked against independent packet-analysis tools before being accepted.

Validation included:

- `capinfos` for packet count and capture duration
- TShark protocol counts
- TShark IP conversation statistics
- independent SYN / SYN-ACK / RST counts
- DNS query counts and timestamps
- TCP session timestamps
- TLS ClientHello SNI extraction
- HTTP request URI counts
- HTTP response-code counts

The final multi-PCAP run demonstrated that the same generic code produced different analyst leads for BLACK SIGNAL, GHOST CHANNEL, and NIGHTFALL without hardcoding their domains, paths, User-Agents, or expected answers.

---

## v1.0 Implementation Boundaries

These boundaries are documented deliberately because a triage tool is most useful when the analyst understands how it can mislead them.

### IPv4-Focused Deep Analysis

Capture summaries and basic conversation handling can see IPv6, and DNS source extraction has an IPv6 path. However, the validated deep TCP connection, timing, TLS SNI, and HTTP analysis path in v1.0 is primarily implemented inside the IPv4 TCP processing flow.

The three project validation PCAPs used for the showcased TraceHound results are IPv4. IPv6 behavioral parity is therefore **not claimed**.

### Raw TCP Flag Counts Can Include Retransmissions

TraceHound deduplicates initial SYN sessions for repeated-session timing, but the displayed raw TCP SYN / SYN-ACK / RST triage counters are packet-observation counts rather than a full TCP-state reconstruction engine. Retransmissions can therefore influence those raw counts in other captures.

### Multi-Port Review Is Not a Time-Windowed Scan Detector

The v1.0 multi-port heuristic surfaces a source/destination pair after at least four destination ports are observed. It does not currently require those contacts to occur inside a strict time window.

This means long captures can surface legitimate multi-service activity. The result is intentionally labelled **worth review**, not `scan detected`.

### DNS Timing Includes Observed Query Events

Repeated DNS queries are analyzed as observed packet events. Retries or retransmission-like behavior can therefore influence interval series. BLACK SIGNAL intentionally demonstrated why the complete interval sequence and outliers should remain visible to the analyst.

### Detailed LOW-Confidence DNS Wording Is Conservative-but-Broad

The detailed DNS timing section uses the generic phrase `periodicity candidate; analyst review required` once enough events exist for timing analysis, even when the calculated confidence is LOW. The final **Analyst Leads** stage is stricter and promotes DNS periodicity only when the assessment reaches HIGH or MEDIUM confidence.

The confidence field should therefore be read as the controlling evidence signal; the generic detailed-section verdict is not a maliciousness conclusion.

### No Full TCP Reassembly

TraceHound reads packet payloads directly. HTTP or TLS metadata fragmented across multiple packets may therefore be missed.

### Metadata Is Not Payload Meaning

TLS SNI can be extracted before encryption, but encrypted application data cannot be interpreted without decryption material.

### Timing Can Produce False Leads

Backups, monitoring agents, software updates, health checks, and legitimate polling can all generate regular or jittered recurring traffic.

### Grouping Is Simplified

Repeated TCP timing is grouped by source IP, destination IP, and destination port. Multiple application actions against one service can therefore be grouped into one statistical timing series.

The NIGHTFALL TCP/8080 timing lead demonstrates this limitation: six sessions were statistically recurring, but they represented several different HTTP actions rather than one proven callback sequence.

### Incomplete Captures Change Conclusions

Packet loss, capture filters, or starting a capture mid-session can change counts, intervals, and response correlation.

### Pattern Recognition Is Not Exploit Validation

A suspicious path, repeated domain, or multi-port sequence describes the network evidence. It does not establish intent, compromise, or impact on its own.

These limitations are why every final report ends with:

```text
First-pass triage complete. Analyst review required.
```

---

## Raw Validation Captures

The original project PCAPs are preserved locally with SHA-256 hashes recorded in the repository, but they are intentionally not distributed in the public portfolio repository because packet captures can retain network metadata beyond the fields shown in the write-ups.

That decision protects the original evidence while making the reproducibility boundary explicit: external readers can inspect the code, screenshots, hashes, rule, and analysis documents, but cannot replay the exact private lab captures from this repository alone.

---

## Project Context

TraceHound was created in **Phase 7** after the manual investigation phases were complete.

The development path was deliberate:

```text
manual packet analysis
        ↓
repeat the analyst workflow
        ↓
identify repetitive triage tasks
        ↓
build generic extraction logic
        ↓
validate against known investigations
        ↓
consolidate behavioral analyst leads
```

This kept the tool grounded in investigation work rather than building features simply for appearance.

---

## Philosophy

> **Automation should accelerate analysis — not replace analyst reasoning.**

TraceHound surfaces what deserves attention.

The analyst still decides what the evidence proves.
