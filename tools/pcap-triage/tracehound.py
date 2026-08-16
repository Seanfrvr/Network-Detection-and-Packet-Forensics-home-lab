#!/usr/bin/env python3

import argparse
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import (
    PcapReader,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
)

from scapy.layers.tls.all import (
    TLS,
    TLSClientHello,
    TLS_Ext_ServerName,
)


HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE",
}


def human_bytes(value):
    """Return a human-readable byte value."""

    units = ["B", "KB", "MB", "GB"]
    size = float(value)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"

        size /= 1024


def classify_protocol(packet):
    """Classify packet by primary network/transport protocol."""

    if ARP in packet:
        return "ARP"

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    if ICMP in packet:
        return "ICMP"

    if IPv6 in packet and packet[IPv6].nh == 58:
        return "ICMPv6"

    if IP in packet:
        return "Other IPv4"

    if IPv6 in packet:
        return "Other IPv6"

    return "Other"


def get_ip_pair(packet):
    """Return a bidirectional IP conversation pair."""

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    else:
        return None

    return tuple(sorted((src, dst)))


def calculate_intervals(timestamps):
    """Calculate inter-event intervals."""

    if len(timestamps) < 2:
        return []

    return [
        timestamps[index] - timestamps[index - 1]
        for index in range(1, len(timestamps))
    ]


def find_dominant_interval_cluster(intervals):
    """Find the strongest cluster of similar intervals."""

    if not intervals:
        return []

    best_cluster = []

    for candidate in intervals:

        tolerance = max(
            1.0,
            candidate * 0.15,
        )

        cluster = [
            interval
            for interval in intervals
            if abs(interval - candidate) <= tolerance
        ]

        if len(cluster) > len(best_cluster):
            best_cluster = cluster

        elif len(cluster) == len(best_cluster) and cluster:

            current_spread = (
                statistics.pstdev(cluster)
                if len(cluster) > 1
                else 0.0
            )

            best_spread = (
                statistics.pstdev(best_cluster)
                if len(best_cluster) > 1
                else 0.0
            )

            if current_spread < best_spread:
                best_cluster = cluster

    return best_cluster


def periodicity_assessment(event_count, intervals):
    """Assess repeated DNS timing."""

    if event_count < 4 or len(intervals) < 3:
        return {
            "level": "INSUFFICIENT",
            "reason": "not enough repeated events for timing assessment",
            "cluster": [],
            "support": 0.0,
            "dominant_interval": None,
            "variation": None,
        }

    cluster = find_dominant_interval_cluster(
        intervals
    )

    if not cluster:
        return {
            "level": "LOW",
            "reason": "no dominant interval pattern identified",
            "cluster": [],
            "support": 0.0,
            "dominant_interval": None,
            "variation": None,
        }

    dominant_interval = statistics.mean(
        cluster
    )

    variation = (
        statistics.pstdev(cluster) / dominant_interval
        if len(cluster) > 1 and dominant_interval > 0
        else 0.0
    )

    support = len(cluster) / len(intervals)

    if (
        event_count >= 5
        and support >= 0.60
        and variation <= 0.15
    ):

        level = "HIGH"

        reason = (
            "dominant recurring interval with "
            "strong timing consistency"
        )

    elif (
        event_count >= 4
        and support >= 0.50
        and variation <= 0.30
    ):

        level = "MEDIUM"

        reason = (
            "repeated timing pattern worth analyst review"
        )

    else:

        level = "LOW"

        reason = (
            "repetition exists but timing consistency is weak"
        )

    return {
        "level": level,
        "reason": reason,
        "cluster": cluster,
        "support": support,
        "dominant_interval": dominant_interval,
        "variation": variation,
    }


def tcp_timing_assessment(event_count, intervals):
    """Assess jitter-aware repeated TCP session timing."""

    if event_count < 4 or len(intervals) < 3:
        return {
            "level": "INSUFFICIENT",
            "pattern": "UNKNOWN",
            "reason": (
                "not enough repeated TCP sessions "
                "for timing assessment"
            ),
            "cv": None,
        }

    mean_interval = statistics.mean(
        intervals
    )

    if mean_interval <= 0:
        return {
            "level": "LOW",
            "pattern": "IRREGULAR",
            "reason": "invalid or zero timing interval",
            "cv": None,
        }

    deviation = statistics.pstdev(
        intervals
    )

    cv = deviation / mean_interval

    if event_count >= 5 and cv <= 0.10:

        return {
            "level": "HIGH",
            "pattern": "REGULAR",
            "reason": (
                "highly regular recurring TCP "
                "connection timing"
            ),
            "cv": cv,
        }

    if event_count >= 5 and cv <= 0.35:

        return {
            "level": "MEDIUM",
            "pattern": "JITTERED",
            "reason": (
                "repeated TCP connection timing "
                "with moderate jitter"
            ),
            "cv": cv,
        }

    if event_count >= 4 and cv <= 0.50:

        return {
            "level": "LOW",
            "pattern": "VARIABLE",
            "reason": (
                "repeated TCP sessions exist but "
                "timing variation is substantial"
            ),
            "cv": cv,
        }

    return {
        "level": "LOW",
        "pattern": "IRREGULAR",
        "reason": (
            "repeated TCP sessions show weak "
            "timing consistency"
        ),
        "cv": cv,
    }


def extract_tls_sni(packet):
    """Extract TLS SNI from a ClientHello."""

    if TCP not in packet:
        return []

    try:
        payload = bytes(
            packet[TCP].payload
        )

    except Exception:
        return []

    if len(payload) < 5:
        return []

    if payload[0] != 0x16:
        return []

    try:
        tls_record = TLS(
            payload
        )

    except Exception:
        return []

    if TLSClientHello not in tls_record:
        return []

    client_hello = tls_record[
        TLSClientHello
    ]

    if not client_hello.ext:
        return []

    names = []

    for extension in client_hello.ext:

        if not isinstance(
            extension,
            TLS_Ext_ServerName,
        ):
            continue

        if not extension.servernames:
            continue

        for server_name in extension.servernames:

            value = server_name.servername

            if isinstance(value, bytes):

                value = value.decode(
                    "utf-8",
                    errors="replace",
                )

            value = (
                str(value)
                .rstrip(".")
                .lower()
            )

            if value:
                names.append(value)

    return names


def parse_http_request(payload):
    """Extract a plaintext HTTP request."""

    if not payload:
        return None

    text = payload.decode(
        "latin-1",
        errors="replace",
    )

    lines = text.split(
        "\r\n"
    )

    if not lines:
        return None

    parts = lines[0].split(
        " "
    )

    if len(parts) < 3:
        return None

    method = parts[0].upper()
    path = parts[1]
    version = parts[2]

    if method not in HTTP_METHODS:
        return None

    if not version.startswith("HTTP/"):
        return None

    user_agent = "-"

    for line in lines[1:]:

        if line.lower().startswith(
            "user-agent:"
        ):

            user_agent = line.split(
                ":",
                1,
            )[1].strip()

    return {
        "method": method,
        "path": path,
        "user_agent": user_agent,
    }


def parse_http_response(payload):
    """Extract an HTTP response status code."""

    if not payload:
        return None

    text = payload.decode(
        "latin-1",
        errors="replace",
    )

    first_line = text.split(
        "\r\n",
        1,
    )[0]

    parts = first_line.split(
        " ",
        2,
    )

    if len(parts) < 2:
        return None

    if not parts[0].startswith("HTTP/"):
        return None

    try:
        return int(parts[1])

    except ValueError:
        return None


def http_path_review(path):
    """Surface HTTP path patterns worth analyst review."""

    lowered = path.lower()

    traversal_tokens = (
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e",
    )

    if any(
        token in lowered
        for token in traversal_tokens
    ):

        return "path traversal pattern present"

    return None


def analyze_pcap(pcap_path):

    packet_count = 0
    total_bytes = 0

    first_timestamp = None
    last_timestamp = None

    protocols = Counter()

    conversations = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
        }
    )

    tcp_attempts = defaultdict(
        lambda: {
            "syn": 0,
            "synack": 0,
            "rst": 0,
        }
    )

    tcp_syn_timestamps = defaultdict(
        list
    )

    seen_syn_sessions = set()

    dns_queries = Counter()
    dns_sources = Counter()
    dns_source_domains = Counter()

    dns_timestamps = defaultdict(
        list
    )

    tls_sni_counts = Counter()
    tls_sni_flows = Counter()

    seen_tls_hellos = set()

    http_methods = Counter()
    http_paths = Counter()
    http_user_agents = Counter()
    http_status_codes = Counter()

    http_details = []
    http_path_reviews = Counter()

    seen_http_requests = set()
    seen_http_responses = set()

    with PcapReader(
        str(pcap_path)
    ) as capture:

        for packet in capture:

            packet_count += 1

            packet_size = len(packet)
            total_bytes += packet_size

            timestamp = float(
                packet.time
            )

            if first_timestamp is None:
                first_timestamp = timestamp

            last_timestamp = timestamp

            protocols[
                classify_protocol(packet)
            ] += 1

            pair = get_ip_pair(
                packet
            )

            if pair:

                conversations[
                    pair
                ]["packets"] += 1

                conversations[
                    pair
                ]["bytes"] += packet_size

            # =========================================================
            # TCP TRIAGE
            # =========================================================

            if IP in packet and TCP in packet:

                src = packet[IP].src
                dst = packet[IP].dst

                sport = int(
                    packet[TCP].sport
                )

                dport = int(
                    packet[TCP].dport
                )

                sequence = int(
                    packet[TCP].seq
                )

                flags = int(
                    packet[TCP].flags
                )

                syn = bool(
                    flags & 0x02
                )

                rst = bool(
                    flags & 0x04
                )

                ack = bool(
                    flags & 0x10
                )

                # -----------------------------------------------------
                # TCP CONNECTION ATTEMPTS
                # -----------------------------------------------------

                if syn and not ack:

                    key = (
                        src,
                        dst,
                        dport,
                    )

                    tcp_attempts[
                        key
                    ]["syn"] += 1

                    session_key = (
                        src,
                        dst,
                        sport,
                        dport,
                        sequence,
                    )

                    if session_key not in seen_syn_sessions:

                        seen_syn_sessions.add(
                            session_key
                        )

                        tcp_syn_timestamps[
                            (
                                src,
                                dst,
                                dport,
                            )
                        ].append(
                            timestamp
                        )

                elif syn and ack:

                    key = (
                        dst,
                        src,
                        sport,
                    )

                    tcp_attempts[
                        key
                    ]["synack"] += 1

                elif rst:

                    reverse_key = (
                        dst,
                        src,
                        sport,
                    )

                    if reverse_key in tcp_attempts:

                        tcp_attempts[
                            reverse_key
                        ]["rst"] += 1

                # -----------------------------------------------------
                # TLS CLIENT HELLO / SNI
                # -----------------------------------------------------

                sni_names = extract_tls_sni(
                    packet
                )

                for sni in sni_names:

                    hello_key = (
                        src,
                        dst,
                        sport,
                        dport,
                        sequence,
                        sni,
                    )

                    if hello_key in seen_tls_hellos:
                        continue

                    seen_tls_hellos.add(
                        hello_key
                    )

                    tls_sni_counts[
                        sni
                    ] += 1

                    tls_sni_flows[
                        (
                            src,
                            dst,
                            dport,
                            sni,
                        )
                    ] += 1

                # -----------------------------------------------------
                # TCP PAYLOAD
                # -----------------------------------------------------

                try:

                    payload = bytes(
                        packet[TCP].payload
                    )

                except Exception:

                    payload = b""

                # -----------------------------------------------------
                # HTTP REQUEST TRIAGE
                # -----------------------------------------------------

                request = parse_http_request(
                    payload
                )

                if request:

                    request_key = (
                        src,
                        dst,
                        sport,
                        dport,
                        sequence,
                        request["method"],
                        request["path"],
                    )

                    if request_key not in seen_http_requests:

                        seen_http_requests.add(
                            request_key
                        )

                        http_methods[
                            request["method"]
                        ] += 1

                        http_paths[
                            request["path"]
                        ] += 1

                        http_user_agents[
                            request["user_agent"]
                        ] += 1

                        http_details.append(
                            {
                                "src": src,
                                "dst": dst,
                                "port": dport,
                                "method": request["method"],
                                "path": request["path"],
                                "user_agent": request["user_agent"],
                            }
                        )

                        review = http_path_review(
                            request["path"]
                        )

                        if review:

                            http_path_reviews[
                                (
                                    request["path"],
                                    review,
                                )
                            ] += 1

                # -----------------------------------------------------
                # HTTP RESPONSE TRIAGE
                # -----------------------------------------------------

                status = parse_http_response(
                    payload
                )

                if status is not None:

                    response_key = (
                        src,
                        dst,
                        sport,
                        dport,
                        sequence,
                        status,
                    )

                    if response_key not in seen_http_responses:

                        seen_http_responses.add(
                            response_key
                        )

                        http_status_codes[
                            status
                        ] += 1

            # =========================================================
            # DNS TRIAGE + TIMING
            # =========================================================

            if (
                DNS in packet
                and packet[DNS].qr == 0
                and DNSQR in packet
            ):

                query_name = packet[
                    DNSQR
                ].qname

                if isinstance(
                    query_name,
                    bytes,
                ):

                    query_name = query_name.decode(
                        "utf-8",
                        errors="replace",
                    )

                query_name = (
                    query_name
                    .rstrip(".")
                    .lower()
                )

                if IP in packet:

                    dns_source = packet[
                        IP
                    ].src

                elif IPv6 in packet:

                    dns_source = packet[
                        IPv6
                    ].src

                else:

                    dns_source = "unknown"

                dns_queries[
                    query_name
                ] += 1

                dns_sources[
                    dns_source
                ] += 1

                dns_source_domains[
                    (
                        dns_source,
                        query_name,
                    )
                ] += 1

                dns_timestamps[
                    (
                        dns_source,
                        query_name,
                    )
                ].append(
                    timestamp
                )

    if (
        first_timestamp is not None
        and last_timestamp is not None
    ):

        duration = (
            last_timestamp
            - first_timestamp
        )

    else:

        duration = 0.0

    return {
        "packets": packet_count,
        "bytes": total_bytes,
        "duration": duration,
        "protocols": protocols,
        "conversations": conversations,
        "tcp_attempts": tcp_attempts,
        "tcp_syn_timestamps": tcp_syn_timestamps,
        "dns_queries": dns_queries,
        "dns_sources": dns_sources,
        "dns_source_domains": dns_source_domains,
        "dns_timestamps": dns_timestamps,
        "tls_sni_counts": tls_sni_counts,
        "tls_sni_flows": tls_sni_flows,
        "http_methods": http_methods,
        "http_paths": http_paths,
        "http_user_agents": http_user_agents,
        "http_status_codes": http_status_codes,
        "http_details": http_details,
        "http_path_reviews": http_path_reviews,
    }


def print_tcp_triage(tcp_attempts):

    print("\n[TCP CONNECTION TRIAGE]")

    if not tcp_attempts:

        print(
            "No TCP connection attempts found."
        )

        return

    grouped = defaultdict(
        list
    )

    for (
        src,
        dst,
        port,
    ), stats in tcp_attempts.items():

        grouped[
            (
                src,
                dst,
            )
        ].append(
            (
                port,
                stats,
            )
        )

    ranked_groups = sorted(
        grouped.items(),
        key=lambda item: (
            len(item[1]),
            sum(
                stats["syn"]
                for _, stats in item[1]
            ),
        ),
        reverse=True,
    )

    for (
        src,
        dst,
    ), ports in ranked_groups:

        ports.sort(
            key=lambda item: item[0]
        )

        unique_ports = len(
            ports
        )

        total_attempts = sum(
            stats["syn"]
            for _, stats in ports
        )

        print()
        print(
            f"{src} -> {dst}"
        )

        print(
            f"Distinct destination ports : "
            f"{unique_ports}"
        )

        print(
            f"TCP connection attempts    : "
            f"{total_attempts}"
        )

        if unique_ports >= 4:

            print(
                "Analyst note               : "
                "multi-port connection pattern worth review"
            )

        print()

        print(
            f"{'PORT':<8}"
            f"{'SYN':>6}"
            f"{'SYN-ACK':>10}"
            f"{'RST':>7}"
            f"   RESPONSE"
        )

        print(
            "-" * 46
        )

        for port, stats in ports:

            if stats["synack"] > 0:

                response = (
                    "SYN-ACK observed"
                )

            elif stats["rst"] > 0:

                response = (
                    "RST observed"
                )

            else:

                response = (
                    "No response observed"
                )

            print(
                f"{port:<8}"
                f"{stats['syn']:>6}"
                f"{stats['synack']:>10}"
                f"{stats['rst']:>7}"
                f"   {response}"
            )


def print_tcp_timing(results):

    print(
        "\n[TCP SESSION TIMING ANALYSIS]"
    )

    ranked = sorted(
        results[
            "tcp_syn_timestamps"
        ].items(),
        key=lambda item: len(
            item[1]
        ),
        reverse=True,
    )

    candidates_found = False

    for (
        src,
        dst,
        port,
    ), timestamps in ranked:

        if len(timestamps) < 4:
            continue

        candidates_found = True

        timestamps = sorted(
            timestamps
        )

        intervals = calculate_intervals(
            timestamps
        )

        assessment = tcp_timing_assessment(
            len(timestamps),
            intervals,
        )

        mean_interval = statistics.mean(
            intervals
        )

        median_interval = statistics.median(
            intervals
        )

        deviation = statistics.pstdev(
            intervals
        )

        print()

        print(
            f"Source               : {src}"
        )

        print(
            f"Destination          : {dst}"
        )

        print(
            f"Destination port     : {port}"
        )

        print(
            f"Connections          : {len(timestamps)}"
        )

        print(
            "Intervals            : "
            + ", ".join(
                f"{interval:.3f}s"
                for interval in intervals
            )
        )

        print(
            f"Mean interval        : "
            f"{mean_interval:.3f}s"
        )

        print(
            f"Median interval      : "
            f"{median_interval:.3f}s"
        )

        print(
            f"Minimum interval     : "
            f"{min(intervals):.3f}s"
        )

        print(
            f"Maximum interval     : "
            f"{max(intervals):.3f}s"
        )

        print(
            f"Std deviation        : "
            f"{deviation:.3f}s"
        )

        if assessment["cv"] is not None:

            print(
                f"Coefficient variation: "
                f"{assessment['cv'] * 100:.1f}%"
            )

        print(
            f"Timing pattern       : "
            f"{assessment['pattern']}"
        )

        print(
            f"Timing confidence    : "
            f"{assessment['level']}"
        )

        print(
            f"Analyst note         : "
            f"{assessment['reason']}"
        )

        if assessment["level"] in (
            "HIGH",
            "MEDIUM",
        ):

            verdict = (
                "recurring connection timing candidate; "
                "analyst review required"
            )

        else:

            verdict = (
                "repeated connection activity; "
                "analyst review required"
            )

        print(
            f"Verdict              : {verdict}"
        )

    if not candidates_found:

        print(
            "No TCP service with enough repeated "
            "sessions for timing analysis."
        )


def print_tls_triage(results):

    print(
        "\n[TLS CLIENT HELLO TRIAGE]"
    )

    sni_counts = results[
        "tls_sni_counts"
    ]

    sni_flows = results[
        "tls_sni_flows"
    ]

    total = sum(
        sni_counts.values()
    )

    if total == 0:

        print(
            "No TLS ClientHello SNI values found."
        )

        return

    print(
        f"ClientHello SNI observations : "
        f"{total}"
    )

    print(
        f"Unique SNI names             : "
        f"{len(sni_counts)}"
    )

    print(
        "\n[TOP TLS SNI VALUES]"
    )

    for sni, count in (
        sni_counts.most_common(10)
    ):

        marker = ""

        if count >= 3:
            marker = "  <-- repeated"

        print(
            f"{sni:<40} "
            f"{count:>4} observations"
            f"{marker}"
        )

    print(
        "\n[TLS SNI FLOW ACTIVITY]"
    )

    ranked = sorted(
        sni_flows.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for (
        src,
        dst,
        port,
        sni,
    ), count in ranked[:15]:

        print(
            f"{src} -> {dst}:{port} "
            f"| {sni} "
            f"| observations={count}"
        )

        if count >= 4:

            print(
                "  Analyst note: repeated TLS sessions "
                "using the same SNI worth review"
            )


def print_http_triage(results):

    print(
        "\n[HTTP REQUEST TRIAGE]"
    )

    total_requests = sum(
        results[
            "http_methods"
        ].values()
    )

    if total_requests == 0:

        print(
            "No plaintext HTTP requests found."
        )

        return

    print(
        f"HTTP requests        : {total_requests}"
    )

    print(
        f"Unique paths         : "
        f"{len(results['http_paths'])}"
    )

    print(
        f"Unique user-agents   : "
        f"{len(results['http_user_agents'])}"
    )

    print(
        "\n[HTTP METHODS]"
    )

    for method, count in (
        results[
            "http_methods"
        ].most_common()
    ):

        print(
            f"{method:<10} "
            f"{count:>4}"
        )

    print(
        "\n[HTTP PATH ACTIVITY]"
    )

    for path, count in (
        results[
            "http_paths"
        ].most_common(15)
    ):

        marker = ""

        if count >= 2:
            marker = "  <-- repeated"

        print(
            f"{path:<45} "
            f"{count:>3}"
            f"{marker}"
        )

    print(
        "\n[HTTP RESPONSE STATUS]"
    )

    if results[
        "http_status_codes"
    ]:

        for status, count in sorted(
            results[
                "http_status_codes"
            ].items()
        ):

            print(
                f"{status:<8} "
                f"{count:>4} responses"
            )

    else:

        print(
            "No HTTP response status lines found."
        )

    print(
        "\n[HTTP USER-AGENTS]"
    )

    for user_agent, count in (
        results[
            "http_user_agents"
        ].most_common(10)
    ):

        print(
            f"{user_agent:<40} "
            f"{count:>3}"
        )

    print(
        "\n[HTTP REQUEST DETAILS]"
    )

    for item in results[
        "http_details"
    ][:20]:

        print(
            f"{item['src']} -> "
            f"{item['dst']}:{item['port']} "
            f"| {item['method']} "
            f"{item['path']} "
            f"| UA={item['user_agent']}"
        )

    if results[
        "http_path_reviews"
    ]:

        print(
            "\n[HTTP PATH REVIEW]"
        )

        for (
            path,
            reason,
        ), count in results[
            "http_path_reviews"
        ].items():

            print()

            print(
                f"Path                 : {path}"
            )

            print(
                f"Observed             : "
                f"{count} request(s)"
            )

            print(
                f"Analyst note         : {reason}"
            )

            print(
                "Verdict              : "
                "request pattern worth analyst review"
            )


def print_dns_triage(results):

    print(
        "\n[DNS TRIAGE]"
    )

    dns_queries = results[
        "dns_queries"
    ]

    dns_sources = results[
        "dns_sources"
    ]

    dns_source_domains = results[
        "dns_source_domains"
    ]

    total_queries = sum(
        dns_queries.values()
    )

    if total_queries == 0:

        print(
            "No DNS queries found."
        )

        return

    print(
        f"Total DNS queries   : {total_queries}"
    )

    print(
        f"Unique domains      : "
        f"{len(dns_queries)}"
    )

    print(
        f"Querying hosts      : "
        f"{len(dns_sources)}"
    )

    print(
        "\n[TOP QUERIED DOMAINS]"
    )

    for domain, count in (
        dns_queries.most_common(10)
    ):

        marker = ""

        if count >= 3:
            marker = "  <-- repeated"

        print(
            f"{domain:<40} "
            f"{count:>4} queries"
            f"{marker}"
        )

    print(
        "\n[DNS SOURCE ACTIVITY]"
    )

    ranked_sources = sorted(
        dns_source_domains.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for (
        source,
        domain,
    ), count in ranked_sources[:15]:

        print(
            f"{source:<18} -> "
            f"{domain:<35} "
            f"{count:>4}"
        )


def print_dns_timing(results):

    print(
        "\n[DNS TIMING ANALYSIS]"
    )

    dns_timestamps = results[
        "dns_timestamps"
    ]

    candidates_found = False

    ranked = sorted(
        dns_timestamps.items(),
        key=lambda item: len(
            item[1]
        ),
        reverse=True,
    )

    for (
        source,
        domain,
    ), timestamps in ranked:

        if len(timestamps) < 4:
            continue

        candidates_found = True

        timestamps = sorted(
            timestamps
        )

        intervals = calculate_intervals(
            timestamps
        )

        assessment = periodicity_assessment(
            len(timestamps),
            intervals,
        )

        print()

        print(
            f"Source               : {source}"
        )

        print(
            f"Domain               : {domain}"
        )

        print(
            f"Events               : "
            f"{len(timestamps)}"
        )

        print(
            "Intervals            : "
            + ", ".join(
                f"{interval:.3f}s"
                for interval in intervals
            )
        )

        print(
            f"Mean interval        : "
            f"{statistics.mean(intervals):.3f}s"
        )

        print(
            f"Median interval      : "
            f"{statistics.median(intervals):.3f}s"
        )

        print(
            f"Minimum interval     : "
            f"{min(intervals):.3f}s"
        )

        print(
            f"Maximum interval     : "
            f"{max(intervals):.3f}s"
        )

        if assessment[
            "dominant_interval"
        ] is not None:

            print(
                f"Dominant interval    : "
                f"{assessment['dominant_interval']:.3f}s"
            )

            print(
                f"Pattern support      : "
                f"{len(assessment['cluster'])}/"
                f"{len(intervals)} intervals "
                f"({assessment['support'] * 100:.1f}%)"
            )

            outside_count = (
                len(intervals)
                - len(
                    assessment["cluster"]
                )
            )

            if outside_count:

                print(
                    f"Outside pattern      : "
                    f"{outside_count} interval(s)"
                )

        print(
            f"Timing confidence    : "
            f"{assessment['level']}"
        )

        print(
            f"Analyst note         : "
            f"{assessment['reason']}"
        )

        print(
            "Verdict              : "
            "periodicity candidate; "
            "analyst review required"
        )

    if not candidates_found:

        print(
            "No repeated DNS activity with enough "
            "events for timing analysis."
        )



def print_analyst_leads(results):
    """
    Summarize the strongest behavioral observations surfaced
    during first-pass PCAP triage.

    These are analyst leads, not maliciousness verdicts.
    """

    leads = []

    # ---------------------------------------------------------
    # MULTI-PORT TCP ACTIVITY
    # ---------------------------------------------------------

    grouped_tcp = defaultdict(list)

    for (src, dst, port), stats in results["tcp_attempts"].items():
        grouped_tcp[(src, dst)].append(
            (port, stats)
        )

    for (src, dst), ports in grouped_tcp.items():

        unique_ports = len(ports)

        if unique_ports < 4:
            continue

        responding_ports = sorted(
            port
            for port, stats in ports
            if stats["synack"] > 0
        )

        reset_ports = sorted(
            port
            for port, stats in ports
            if stats["rst"] > 0
        )

        evidence = (
            f"{src} -> {dst} contacted "
            f"{unique_ports} destination ports."
        )

        detail_parts = []

        if responding_ports:
            detail_parts.append(
                "SYN-ACK observed on "
                + ", ".join(
                    str(port)
                    for port in responding_ports
                )
            )

        if reset_ports:
            detail_parts.append(
                "RST observed on "
                + ", ".join(
                    str(port)
                    for port in reset_ports
                )
            )

        leads.append(
            {
                "type": "MULTI-PORT ACTIVITY",
                "evidence": evidence,
                "detail": "; ".join(detail_parts),
                "assessment": (
                    "connection pattern worth analyst review"
                ),
            }
        )

    # ---------------------------------------------------------
    # RECURRING TCP SESSION TIMING
    # ---------------------------------------------------------

    for (
        src,
        dst,
        port,
    ), timestamps in results["tcp_syn_timestamps"].items():

        timestamps = sorted(
            timestamps
        )

        if len(timestamps) < 4:
            continue

        intervals = calculate_intervals(
            timestamps
        )

        assessment = tcp_timing_assessment(
            len(timestamps),
            intervals,
        )

        if assessment["level"] not in (
            "HIGH",
            "MEDIUM",
        ):
            continue

        mean_interval = statistics.mean(
            intervals
        )

        leads.append(
            {
                "type": "RECURRING TCP TIMING",
                "evidence": (
                    f"{src} -> {dst}:{port} produced "
                    f"{len(timestamps)} TCP sessions."
                ),
                "detail": (
                    f"{assessment['pattern']} timing; "
                    f"mean interval {mean_interval:.3f}s; "
                    f"confidence {assessment['level']}."
                ),
                "assessment": (
                    "recurring connection timing candidate"
                ),
            }
        )

    # ---------------------------------------------------------
    # REPEATED TLS SNI
    # ---------------------------------------------------------

    for (
        src,
        dst,
        port,
        sni,
    ), count in results["tls_sni_flows"].items():

        if count < 4:
            continue

        leads.append(
            {
                "type": "REPEATED TLS IDENTITY",
                "evidence": (
                    f"{src} -> {dst}:{port} used "
                    f"SNI {sni} {count} times."
                ),
                "detail": (
                    "Repeated TLS sessions shared "
                    "the same ClientHello SNI."
                ),
                "assessment": (
                    "encrypted recurring communication "
                    "worth analyst review"
                ),
            }
        )

    # ---------------------------------------------------------
    # DNS PERIODICITY
    # ---------------------------------------------------------

    for (
        source,
        domain,
    ), timestamps in results["dns_timestamps"].items():

        timestamps = sorted(
            timestamps
        )

        if len(timestamps) < 4:
            continue

        intervals = calculate_intervals(
            timestamps
        )

        assessment = periodicity_assessment(
            len(timestamps),
            intervals,
        )

        if assessment["level"] not in (
            "HIGH",
            "MEDIUM",
        ):
            continue

        dominant = assessment[
            "dominant_interval"
        ]

        support_count = len(
            assessment["cluster"]
        )

        leads.append(
            {
                "type": "DNS PERIODICITY",
                "evidence": (
                    f"{source} queried {domain} "
                    f"{len(timestamps)} times."
                ),
                "detail": (
                    f"Dominant interval {dominant:.3f}s; "
                    f"support {support_count}/"
                    f"{len(intervals)} intervals; "
                    f"confidence {assessment['level']}."
                ),
                "assessment": (
                    "periodicity candidate; "
                    "analyst review required"
                ),
            }
        )

    # ---------------------------------------------------------
    # REPEATED HTTP PATHS
    # ---------------------------------------------------------

    for path, count in results[
        "http_paths"
    ].most_common():

        if count < 2:
            continue

        leads.append(
            {
                "type": "REPEATED HTTP ACTIVITY",
                "evidence": (
                    f"{path} observed "
                    f"{count} times."
                ),
                "detail": (
                    "Repeated requests to the same "
                    "HTTP resource were observed."
                ),
                "assessment": (
                    "request repetition worth "
                    "analyst review"
                ),
            }
        )

    # ---------------------------------------------------------
    # HTTP PATH ANOMALIES
    # ---------------------------------------------------------

    for (
        path,
        reason,
    ), count in results[
        "http_path_reviews"
    ].items():

        leads.append(
            {
                "type": "HTTP PATH ANOMALY",
                "evidence": (
                    f"{path} observed "
                    f"{count} time(s)."
                ),
                "detail": reason,
                "assessment": (
                    "request pattern worth "
                    "analyst review"
                ),
            }
        )

    # ---------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------

    print(
        "\n[ANALYST LEADS]"
    )

    if not leads:

        print(
            "No behavioral leads met the current "
            "TraceHound review heuristics."
        )

        return

    print(
        f"Behavioral leads surfaced : "
        f"{len(leads)}"
    )

    print(
        "Interpretation             : "
        "leads require analyst validation"
    )

    for index, lead in enumerate(
        leads,
        start=1,
    ):

        print()

        print(
            f"[{index}] {lead['type']}"
        )

        print(
            f"Evidence             : "
            f"{lead['evidence']}"
        )

        if lead["detail"]:

            print(
                f"Context              : "
                f"{lead['detail']}"
            )

        print(
            f"Assessment           : "
            f"{lead['assessment']}"
        )

        print(
            "Priority             : REVIEW"
        )

def print_report(pcap_path, results):

    print()

    print(
        "=" * 62
    )

    print(
        "TRACEHOUND"
    )

    print(
        "PCAP Triage & Behavioral Analysis"
    )

    print(
        "=" * 62
    )

    print(
        "\n[CAPTURE SUMMARY]"
    )

    print(
        f"File       : "
        f"{pcap_path.name}"
    )

    print(
        f"Packets    : "
        f"{results['packets']}"
    )

    print(
        f"Bytes      : "
        f"{results['bytes']} "
        f"({human_bytes(results['bytes'])})"
    )

    print(
        f"Duration   : "
        f"{results['duration']:.3f} seconds"
    )

    print(
        "\n[PROTOCOL DISTRIBUTION]"
    )

    if results["protocols"]:

        for protocol, count in (
            results[
                "protocols"
            ].most_common()
        ):

            percentage = (
                count
                / results["packets"]
                * 100
                if results["packets"]
                else 0
            )

            print(
                f"{protocol:<12} "
                f"{count:>6} packets "
                f"({percentage:>5.1f}%)"
            )

    else:

        print(
            "No packets found."
        )

    print(
        "\n[TOP IP CONVERSATIONS]"
    )

    ranked = sorted(
        results[
            "conversations"
        ].items(),
        key=lambda item: (
            item[1]["packets"]
        ),
        reverse=True,
    )

    if not ranked:

        print(
            "No IPv4/IPv6 conversations found."
        )

    else:

        for index, (
            pair,
            stats,
        ) in enumerate(
            ranked[:10],
            start=1,
        ):

            host_a, host_b = pair

            print(
                f"{index:>2}. "
                f"{host_a} <-> {host_b} "
                f"| packets={stats['packets']} "
                f"| bytes={human_bytes(stats['bytes'])}"
            )

    print_tcp_triage(
        results[
            "tcp_attempts"
        ]
    )

    print_tcp_timing(
        results
    )

    print_tls_triage(
        results
    )

    print_http_triage(
        results
    )

    print_dns_triage(
        results
    )

    print_dns_timing(
        results
    )

    print_analyst_leads(
        results
    )

    print(
        "\n" + "=" * 62
    )

    print(
        "First-pass triage complete. "
        "Analyst review required."
    )

    print(
        "=" * 62
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "TraceHound - "
            "PCAP triage and behavioral analysis"
        )
    )

    parser.add_argument(
        "pcap",
        help=(
            "Path to a PCAP or PCAPNG file"
        ),
    )

    args = parser.parse_args()

    pcap_path = Path(
        args.pcap
    ).expanduser()

    if not pcap_path.is_file():

        raise SystemExit(
            f"[ERROR] Capture not found: "
            f"{pcap_path}"
        )

    try:

        results = analyze_pcap(
            pcap_path
        )

    except Exception as error:

        raise SystemExit(
            f"[ERROR] Could not analyze capture: "
            f"{error}"
        )

    print_report(
        pcap_path,
        results,
    )


if __name__ == "__main__":
    main()
