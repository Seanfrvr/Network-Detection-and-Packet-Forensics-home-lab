# Architecture & Investigation Flow

> **Physical endpoint → packet evidence → telemetry → detection → analyst validation → automation**

This project was designed as one connected blue-team workflow rather than a set of isolated labs. The diagrams below show how traffic moved through the environment, how the same preserved evidence was reused across tools, and how the investigation process evolved into TraceHound.

---

## 1. Lab & Evidence Architecture

```mermaid
flowchart LR
    A["Physical iMac\n192.168.0.147\nControlled traffic source"]
    B["Local LAN"]
    C["Kali Linux VM\n192.168.0.194\nBridged capture + analysis node"]
    D["Preserved PCAP Evidence\nSHA-256 integrity tracked"]
    E["MacBook Host\nTemporary transfer bridge"]
    F["Ubuntu Sensor\nOffline network-analysis node"]
    G["Zeek\nStructured network telemetry"]
    H["Suricata\nIDS replay + detection logic"]
    I["Wireshark / TShark\nPacket reconstruction + validation"]
    J["TraceHound\nPCAP triage + behavioral leads"]
    K["Analyst Conclusion\nEvidence-backed, scoped findings"]

    A -->|"HTTP / TLS / DNS / controlled case traffic"| B
    B --> C
    C -->|"capture"| D
    D --> I
    D --> E
    E --> F
    F --> G
    F --> H
    D --> J
    I --> K
    G --> K
    H --> K
    J --> K
```

### Why this architecture mattered

The same packet evidence could be inspected manually, converted into Zeek telemetry, replayed through Suricata, and later processed by TraceHound without regenerating the traffic for each tool.

That created a simple trust model:

```text
Generate activity once
        ↓
Preserve the PCAP
        ↓
Hash the evidence
        ↓
Analyze the same artifact through multiple tools
        ↓
Compare findings
        ↓
State only what the evidence supports
```

---

## 2. Investigation Progression

```mermaid
flowchart TD
    P1["Phase 01\nLab Architecture\nDHCP troubleshooting + ICMP validation"]
    P2["Phase 02\nKnown-Good Baselines\nHTTP plaintext vs TLS metadata"]
    P3["Phase 03\nTelemetry Layer\nZeek + Suricata offline replay"]
    P4["Phase 04 — BLACK SIGNAL\nPeriodic DNS behavior"]
    P5["Phase 05 — GHOST CHANNEL\nJittered encrypted TLS sessions"]
    P6["Phase 06 — NIGHTFALL\nBlind PCAP investigation"]
    DG["Detection Gap\nTraffic visible, desired alert absent"]
    CR["Custom Suricata Rule\nSID 1000001"]
    RP["Same-PCAP Replay\nEvidence unchanged"]
    AL["Custom Alert Fires\nDetection logic validated"]
    P7["Phase 07 — TraceHound\nManual workflow converted to automation"]

    P1 --> P2 --> P3 --> P4 --> P5 --> P6
    P6 --> DG --> CR --> RP --> AL
    AL --> P7
```

The progression was intentional. TraceHound came last because the repetitive workflow needed to be understood manually before it was automated.

---

## 3. NIGHTFALL Detection-Engineering Loop

```mermaid
flowchart LR
    A["Blind NIGHTFALL PCAP"]
    B["Manual packet reconstruction"]
    C["Zeek correlation"]
    D["Suricata file / HTTP visibility"]
    E["0 matching EICAR alert\nunder active lab ruleset"]
    F["Ruleset coverage review"]
    G["Custom SID 1000001"]
    H["Replay exact same PCAP"]
    I["NIGHTFALL EICAR alert fires"]
    J["Validated conclusion:\nEvidence stayed constant; detection logic changed"]

    A --> B
    A --> C
    A --> D
    D --> E
    E --> F
    F --> G
    G --> H
    A -. "same preserved evidence" .-> H
    H --> I
    I --> J
```

This is the central detection-engineering result of the project. Suricata had already reconstructed the relevant HTTP/file transaction, so the missing alert was treated as a coverage problem relative to the lab objective rather than a visibility failure.

---

## 4. TraceHound Analyst Pipeline

```mermaid
flowchart TD
    A["Raw PCAP"]
    B["Capture Summary\nPackets • bytes • duration"]
    C["Protocol + Conversation Triage"]
    D["TCP Analysis\nSYN / SYN-ACK / RST\nRepeated session timing"]
    E["DNS Analysis\nQueries + periodicity"]
    F["TLS Analysis\nClientHello SNI correlation"]
    G["HTTP Analysis\nMethods • paths • UA • status"]
    H["Behavioral Heuristics"]
    I["ANALYST LEADS"]
    J["Manual Validation\nWireshark • TShark • Zeek • Suricata"]
    K["Scoped Analyst Conclusion"]

    A --> B --> C
    C --> D
    C --> E
    C --> F
    C --> G
    D --> H
    E --> H
    F --> H
    G --> H
    H --> I
    I --> J
    J --> K
```

TraceHound deliberately stops at **analyst leads**. It does not turn heuristics into unsupported verdicts such as `C2 confirmed`, `malware detected`, or `host compromised`.

---

## 5. Evidence Model

The entire project follows one rule:

```mermaid
flowchart LR
    E["Raw Evidence"] --> O["Tool Observation"] --> I["Analyst Inference"] --> C["Defensible Conclusion"]
```

Examples:

| Evidence | Tool observation | Defensible conclusion |
|---|---|---|
| Repeated DNS timestamps | Dominant ~10s interval with retry-like tail | Periodic DNS behavior worth review |
| Six TLS ClientHellos to one SNI | Repeated TLS identity + jittered timing | Encrypted recurring communication worth review |
| Traversal-shaped HTTP URI + HTTP 404 | Path anomaly observed | Traversal attempt observed; success not proven |
| EICAR content transferred + no matching stock alert | Traffic visible, desired detection absent | Detection coverage gap relative to lab objective |
| Same PCAP + custom SID fires | Detection result changes after rule change | Custom detection closed the tested coverage gap |

---

## Final Architecture Principle

> **Packets provide the evidence. Telemetry organizes it. Detection logic interprets patterns. The analyst decides what the evidence actually proves.**
