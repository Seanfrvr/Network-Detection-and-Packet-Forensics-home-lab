# Architecture & Investigation Flow

> **Physical endpoint → packet evidence → telemetry → detection → analyst validation → automation**

This project is one connected blue-team workflow rather than a set of isolated labs. The diagrams below separate the **physical/virtual topology** from the **evidence-analysis flow** so the environment is not mistaken for several independent physical hosts.

---

## 1. Physical & Virtual Lab Topology

```mermaid
flowchart LR
    IMAC["Physical iMac<br/>192.168.0.147<br/>Controlled endpoint / traffic source"]
    LAN["Local LAN"]

    subgraph MB["MacBook Pro Late 2013 — physical host"]
        direction TB
        VBOX["VirtualBox<br/>VMs used sequentially to fit host resources"]
        KALI["Kali Linux VM<br/>192.168.0.194 when bridged<br/>Capture + Wireshark/TShark + TraceHound"]
        UBUNTU["Ubuntu VM<br/>Offline sensor / analysis role<br/>Zeek + Suricata"]
        HOST["macOS host workspace<br/>Temporary PCAP transfer bridge<br/>Project files + screenshots"]

        VBOX --> KALI
        VBOX --> UBUNTU
    end

    IMAC <-->|"controlled HTTP / TLS / DNS / case traffic"| LAN
    LAN <-->|"bridged lab traffic"| KALI
    KALI -->|"captured PCAP"| HOST
    HOST -->|"same preserved PCAP"| UBUNTU
```

### Why this topology mattered

The physical iMac generated controlled traffic without consuming MacBook VM resources. The MacBook was the virtualization host, while Kali and Ubuntu were used in different analysis roles rather than pretending to be separate physical systems.

Kali handled capture, manual packet analysis, and TraceHound development. Ubuntu later processed preserved captures through Zeek and Suricata. The MacBook host acted only as a temporary evidence-transfer bridge between those VM workflows.

---

## 2. Evidence & Analysis Architecture

```mermaid
flowchart LR
    A["Controlled activity"]
    B["Preserved PCAP<br/>SHA-256 integrity tracked"]
    C["Wireshark / TShark<br/>Packet reconstruction + validation"]
    D["Zeek<br/>Structured network telemetry"]
    E["Suricata<br/>IDS replay + detection logic"]
    F["TraceHound<br/>PCAP triage + behavioral leads"]
    G["Analyst conclusion<br/>Evidence-backed + scoped"]

    A --> B
    B --> C
    B --> D
    B --> E
    B --> F
    C --> G
    D --> G
    E --> G
    F --> G
```

The important design decision was reuse of the **same preserved evidence**. Traffic did not need to be regenerated for every tool.

```text
Generate controlled activity once
        ↓
Preserve the PCAP
        ↓
Hash the evidence
        ↓
Analyze the same artifact through multiple tools
        ↓
Compare observations
        ↓
State only what the evidence supports
```

---

## 3. Investigation Progression

```mermaid
flowchart TD
    P1["Phase 01<br/>Lab Architecture<br/>DHCP troubleshooting + ICMP validation"]
    P2["Phase 02<br/>Known-Good Baselines<br/>HTTP plaintext vs TLS metadata"]
    P3["Phase 03<br/>Telemetry Layer<br/>Zeek + Suricata offline replay"]
    P4["Phase 04 — BLACK SIGNAL<br/>Periodic DNS behavior"]
    P5["Phase 05 — GHOST CHANNEL<br/>Jittered encrypted TLS sessions"]
    P6["Phase 06 — NIGHTFALL<br/>Blind PCAP investigation"]
    DG["Detection Gap<br/>Traffic visible; desired alert absent"]
    CR["Custom Suricata Rule<br/>SID 1000001"]
    RP["Same-PCAP Replay<br/>Evidence unchanged"]
    AL["Custom Alert Fires<br/>Detection logic validated"]
    P7["Phase 07 — TraceHound<br/>Manual workflow converted to automation"]

    P1 --> P2 --> P3 --> P4 --> P5 --> P6
    P6 --> DG --> CR --> RP --> AL
    AL --> P7
```

The progression was intentional. TraceHound came last because the repetitive workflow was understood manually before it was automated.

---

## 4. NIGHTFALL Detection-Engineering Loop

```mermaid
flowchart LR
    A["Blind NIGHTFALL PCAP"]
    B["Manual packet reconstruction"]
    C["Zeek correlation"]
    D["Suricata HTTP / file visibility"]
    E["No matching EICAR alert<br/>under the active pre-custom ruleset"]
    F["Ruleset coverage review"]
    G["Custom SID 1000001"]
    H["Replay exact same PCAP"]
    I["NIGHTFALL EICAR alert fires"]
    J["Validated result<br/>Evidence stayed constant;<br/>detection logic changed"]

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

This is the central detection-engineering result of the project. Suricata had already reconstructed the relevant HTTP/file transaction, so the missing alert was treated as a **coverage problem relative to the lab objective**, not a visibility failure.

---

## 5. TraceHound Analyst Pipeline

```mermaid
flowchart TD
    A["Raw PCAP"]
    B["Capture Summary<br/>Packets • bytes • duration"]
    C["Protocol + Conversation Triage"]
    D["TCP Analysis<br/>SYN / SYN-ACK / RST<br/>Repeated session timing"]
    E["DNS Analysis<br/>Queries + periodicity"]
    F["TLS Analysis<br/>ClientHello SNI correlation"]
    G["HTTP Analysis<br/>Methods • paths • UA • status"]
    H["Behavioral Heuristics"]
    I["ANALYST LEADS"]
    J["Manual Validation<br/>Wireshark • TShark • Zeek • Suricata"]
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

## 6. Evidence Model

```mermaid
flowchart LR
    E["Raw Evidence"] --> O["Tool Observation"] --> I["Analyst Inference"] --> C["Defensible Conclusion"]
```

| Evidence | Tool observation | Defensible conclusion |
|---|---|---|
| Repeated DNS timestamps | Dominant ~10 s interval with retry-like tail | Periodic DNS behavior worth review |
| Six TLS ClientHellos to one SNI | Repeated TLS identity + jittered timing | Encrypted recurring communication worth review |
| Traversal-shaped HTTP URI + HTTP 404 | Path anomaly observed | Traversal attempt observed; success not proven |
| EICAR content transferred + no matching alert | Traffic visible; desired detection absent | Detection coverage gap relative to the lab objective |
| Same PCAP + custom SID fires | Detection result changes after rule change | Custom detection closed the tested coverage gap |

---

## Final Architecture Principle

> **Packets provide the evidence. Telemetry organizes it. Detection logic evaluates patterns. The analyst decides what those patterns mean and what the evidence actually proves.**
