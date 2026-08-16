# TraceHound

> **PCAP Triage & Behavioral Analysis**

TraceHound is a lightweight Python utility built during Phase 7 of the **Network Detection & Packet Forensics Home Lab** to automate repetitive first-pass PCAP triage without replacing analyst judgment.

The tool reads packet captures with Scapy, extracts observable network behavior, calculates timing patterns, and consolidates stronger observations into an **Analyst Leads** section for deeper manual review.

> **Packets provide the evidence. TraceHound surfaces the leads. The analyst decides what they mean.**

---

## Why I Built It

The first six phases of this project required repeated manual work across Wireshark, TShark, Zeek, and Suricata: identifying conversations, counting connection attempts, extracting DNS queries, comparing timestamps, reconstructing HTTP activity, and deciding which patterns deserved more attention.

TraceHound was built only after those workflows had been performed manually.

The goal was therefore not to create another generic packet parser. It was to automate the repetitive parts of network triage while preserving the distinction between:

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

Developed and validated with:

```text
Python 3.13
Scapy 2.7.x
```

Install Scapy if required:

```bash
python3 -m pip install scapy
```

Check the installed version:

```bash
python3 -c "import scapy; print(scapy.__version__)"
```

---

## Usage

Make the script executable:

```bash
chmod +x tracehound.py
```

Run it against a PCAP or PCAPNG file:

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

The coefficient of variation is then used to describe the timing as regular, jittered, variable, or irregular.

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

TraceHound was not validated only against synthetic unit tests. It was replayed against the three PCAP investigations already completed manually in this project.

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

## Limitations

TraceHound is intentionally a **first-pass triage** utility.

Current limitations include:

- no full TCP stream reassembly
- HTTP parsing is primarily limited to complete plaintext request/response lines present in individual TCP payloads
- encrypted payload contents are not decrypted
- TLS visibility is limited to metadata available before encryption, such as ClientHello SNI
- packet loss or incomplete captures can change counts and timing results
- repeated traffic may be legitimate automation
- multi-port behavior may be legitimate service discovery or administration
- timing analysis groups repeated TCP sessions by source, destination, and destination port, so unrelated application actions to the same service can be grouped together
- the NIGHTFALL TCP/8080 timing lead demonstrates this limitation: six sessions were statistically recurring, but they represented several different HTTP actions rather than a single proven callback sequence
- traversal syntax proves the request pattern, not successful file disclosure

TraceHound should therefore be used to prioritize deeper investigation with Wireshark, TShark, Zeek, Suricata, and analyst reasoning.

---

## Project Context

TraceHound was created in **Phase 7** of the Network Detection & Packet Forensics Home Lab after the manual investigation phases were complete.

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
