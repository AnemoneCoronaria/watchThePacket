import time as _time

from scapy.all import Ether, Dot3, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Padding, NoPayload
from scapy.layers.inet import IPerror, UDPerror, TCPerror, ICMPerror

from core.packet_parser import (
    build_detail, payload_bytes, tcp_flag_names, parse_http, http_header, tls_records,
    icmpv6_layer, dns_records, dns_name, dns_rdata,
    DNS_TYPES, DNS_RCODES, ICMP_TYPES, ICMP_CODES, TLS_RECORDS, TLS_HANDSHAKES, TLS_VERSIONS,
)

# 상세 트리(왼쪽 아래)를 Wireshark처럼 만드는 파일
# Qt는 몰라도 됨. Node 들의 나무 모양만 만들어서 돌려주고, 화면에 그리는 건 main_window가 함
#
# build_tree(pkt, no, meta, t0) -> [Node, Node, ...]
#   Frame / Ethernet II / Internet Protocol / TCP or UDP / DNS, HTTP ... 순서
#   맨 아래에는 scapy 원본 필드도 붙여둠 (build_detail 결과)


class Node:
    # 트리 한 줄. children 이 있으면 접었다 펼 수 있음
    def __init__(self, text, expanded=False):
        self.text = text
        self.children = []
        self.expanded = expanded

    def add(self, text, expanded=False):
        child = Node(text, expanded)
        self.children.append(child)
        return child


# ---- 이름표 ----
ETHER_TYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP"}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
DNS_TYPE_DESC = {"A": "Host Address", "AAAA": "IPv6 Address", "CNAME": "Canonical NAME for an alias",
                 "NS": "authoritative Name Server", "PTR": "domain name PoinTeR", "MX": "Mail eXchange",
                 "TXT": "Text strings", "SOA": "Start Of a zone of Authority", "SRV": "Server Selection",
                 "OPT": "EDNS0 option", "HTTPS": "HTTPS specific Resource Record", "SVCB": "General Purpose Service Binding"}


def bitline(value, mask, width, label):
    # Wireshark 식 비트 그림: ".... ..1. = Syn: Set"
    chars = []
    for pos in range(width - 1, -1, -1):
        bit = 1 << pos
        chars.append(("1" if value & bit else "0") if mask & bit else ".")
        if pos % 4 == 0 and pos:
            chars.append(" ")
    return f"{''.join(chars)} = {label}"


def human_seconds(sec):
    # 3600 -> "1 hour", 90061 -> "1 day, 1 hour, 1 minute, 1 second"
    parts = []
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        n, sec = divmod(sec, size)
        if n:
            parts.append(f"{n} {unit}{'s' if n > 1 else ''}")
    return ", ".join(parts) or "0 seconds"


def _ms(seconds):
    return f"{seconds * 1000:.3f} ms"


# ---- 층별로 만들기 ----
def _frame(pkt, no, meta, t0):
    caplen = len(pkt)
    wirelen = getattr(pkt, "wirelen", None) or caplen
    head = f"Frame {no}: {wirelen} bytes on wire ({wirelen * 8} bits), {caplen} bytes captured ({caplen * 8} bits)"
    iface = getattr(pkt, "sniffed_on", None)
    if iface:
        head += f" on interface {iface}"
    node = Node(head)
    t = float(pkt.time)
    node.add("Arrival Time: " + _time.strftime("%b %d, %Y %H:%M:%S", _time.localtime(t)) + f".{int((t % 1) * 1e6):06d}")
    node.add(f"[Time since reference or first frame: {t - float(t0):.9f} seconds]")
    node.add(f"Frame Number: {no}")
    node.add(f"Frame Length: {wirelen} bytes ({wirelen * 8} bits)")
    node.add(f"Capture Length: {caplen} bytes ({caplen * 8} bits)")
    names = [cls.__name__.lower().replace("ether", "eth") for cls in pkt.layers() if cls not in (Raw, Padding)]
    node.add(f"[Protocols in frame: {':'.join(names)}]")
    return node


def _ethernet(layer):
    node = Node(f"Ethernet II, Src: {layer.src}, Dst: {layer.dst}")
    node.add(f"Destination: {layer.dst}")
    node.add(f"Source: {layer.src}")
    node.add(f"Type: {ETHER_TYPES.get(layer.type, 'Unknown')} (0x{layer.type:04x})")
    return node


def _dot3(layer):
    node = Node(f"IEEE 802.3 Ethernet, Src: {layer.src}, Dst: {layer.dst}")
    node.add(f"Destination: {layer.dst}")
    node.add(f"Source: {layer.src}")
    node.add(f"Length: {layer.len}")
    return node


def _ipv4(layer):
    node = Node(f"Internet Protocol Version 4, Src: {layer.src}, Dst: {layer.dst}")
    node.add(bitline(layer.version << 4, 0xF0, 8, f"Version: {layer.version}"))
    node.add(bitline(layer.ihl, 0x0F, 8, f"Header Length: {layer.ihl * 4} bytes ({layer.ihl})"))
    node.add(f"Differentiated Services Field: 0x{layer.tos:02x} (DSCP: {layer.tos >> 2}, ECN: {layer.tos & 3})")
    node.add(f"Total Length: {layer.len}")
    node.add(f"Identification: 0x{layer.id:04x} ({layer.id})")
    flags = int(layer.flags)
    text = f"Flags: 0x{flags:x}"
    if flags & 2:
        text += ", Don't fragment"
    if flags & 1:
        text += ", More fragments"
    fnode = node.add(text)
    fnode.add(bitline(flags << 5, 0x80, 8, f"Reserved bit: {'Set' if flags & 4 else 'Not set'}"))
    fnode.add(bitline(flags << 5, 0x40, 8, f"Don't fragment: {'Set' if flags & 2 else 'Not set'}"))
    fnode.add(bitline(flags << 5, 0x20, 8, f"More fragments: {'Set' if flags & 1 else 'Not set'}"))
    node.add(f"Fragment Offset: {layer.frag * 8}")
    node.add(f"Time to Live: {layer.ttl}")
    node.add(f"Protocol: {IP_PROTOCOLS.get(layer.proto, 'Unknown')} ({layer.proto})")
    node.add(f"Header Checksum: 0x{layer.chksum:04x} [validation disabled]")
    node.add(f"Source Address: {layer.src}")
    node.add(f"Destination Address: {layer.dst}")
    return node


def _ipv6(layer):
    node = Node(f"Internet Protocol Version 6, Src: {layer.src}, Dst: {layer.dst}")
    node.add(f"0110 .... = Version: {layer.version}")
    node.add(f"Traffic Class: 0x{layer.tc:02x}")
    node.add(f"Flow Label: 0x{layer.fl:05x}")
    node.add(f"Payload Length: {layer.plen}")
    node.add(f"Next Header: {IP_PROTOCOLS.get(layer.nh, 'Unknown')} ({layer.nh})")
    node.add(f"Hop Limit: {layer.hlim}")
    node.add(f"Source Address: {layer.src}")
    node.add(f"Destination Address: {layer.dst}")
    return node


TCP_BITS = [  # (마스크, Wireshark 이름, 짧은 글자)
    (0x800, "Reserved", None), (0x400, "Reserved", None), (0x200, "Reserved", None),
    (0x100, "Accurate ECN", None), (0x80, "Congestion Window Reduced", "C"), (0x40, "ECN-Echo", "E"),
    (0x20, "Urgent", "U"), (0x10, "Acknowledgment", "A"), (0x08, "Push", "P"),
    (0x04, "Reset", "R"), (0x02, "Syn", "S"), (0x01, "Fin", "F"),
]


def _tcp(layer, meta):
    names = tcp_flag_names(layer)
    seg_len = len(payload_bytes(layer))
    rel_seq = meta.rel_seq if meta and meta.rel_seq is not None else None
    rel_ack = meta.rel_ack if meta and meta.rel_ack is not None else None

    head = f"Transmission Control Protocol, Src Port: {layer.sport}, Dst Port: {layer.dport}, Seq: {rel_seq if rel_seq is not None else layer.seq}"
    if "ACK" in names:
        head += f", Ack: {rel_ack if rel_ack is not None else layer.ack}"
    head += f", Len: {seg_len}"
    node = Node(head)

    node.add(f"Source Port: {layer.sport}")
    node.add(f"Destination Port: {layer.dport}")
    if meta and meta.stream is not None:
        node.add(f"[Stream index: {meta.stream}]")
    if meta and meta.phase_label:
        node.add(f"[연결 단계: {meta.phase_label}]")
    node.add(f"[TCP Segment Len: {seg_len}]")
    if rel_seq is not None:
        node.add(f"Sequence Number: {rel_seq}    (relative sequence number)")
    node.add(f"Sequence Number (raw): {layer.seq}")
    if meta and meta.next_seq is not None:
        node.add(f"[Next Sequence Number: {meta.next_seq}    (relative sequence number)]")
    if "ACK" in names and rel_ack is not None:
        node.add(f"Acknowledgment Number: {rel_ack}    (relative ack number)")
    elif "ACK" not in names:
        node.add("Acknowledgment Number: 0")
    node.add(f"Acknowledgment number (raw): {layer.ack}")
    node.add(bitline(layer.dataofs << 4, 0xF0, 8, f"Header Length: {layer.dataofs * 4} bytes ({layer.dataofs})"))

    flags = int(layer.flags)
    fnode = node.add(f"Flags: 0x{flags:03x} ({', '.join(names) or '<None>'})")
    for mask, label, _ in TCP_BITS:
        fnode.add(bitline(flags, mask, 12, f"{label}: {'Set' if flags & mask else 'Not set'}"))
    short = "".join((ch if flags & mask else "·") for mask, _, ch in TCP_BITS if ch)
    fnode.add(f"[TCP Flags: ····{short}]")

    node.add(f"Window: {layer.window}")
    node.add(f"Checksum: 0x{layer.chksum:04x} [unverified]")
    node.add(f"Urgent Pointer: {layer.urgptr}")

    options = [opt for opt in layer.options if opt[0] not in ("EOL",)]
    if options:
        opt_len = layer.dataofs * 4 - 20
        onode = node.add(f"Options: ({opt_len} bytes), " + ", ".join(_tcp_option_name(o) for o in options))
        for opt in options:
            onode.add(_tcp_option_detail(opt))
    return node


def _tcp_option_name(opt):
    return {"MSS": "Maximum segment size", "SAckOK": "SACK permitted", "Timestamp": "Timestamps",
            "NOP": "No-Operation (NOP)", "WScale": "Window scale", "SAck": "SACK"}.get(opt[0], opt[0])


def _tcp_option_detail(opt):
    name, value = opt
    if name == "MSS":
        return f"TCP Option - Maximum segment size: {value} bytes"
    if name == "SAckOK":
        return "TCP Option - SACK permitted"
    if name == "Timestamp":
        return f"TCP Option - Timestamps: TSval {value[0]}, TSecr {value[1]}"
    if name == "WScale":
        return f"TCP Option - Window scale: {value} (multiply by {2 ** value})"
    if name == "NOP":
        return "TCP Option - No-Operation (NOP)"
    return f"TCP Option - {name}: {value}"


def _udp(layer, meta):
    node = Node(f"User Datagram Protocol, Src Port: {layer.sport}, Dst Port: {layer.dport}")
    node.add(f"Source Port: {layer.sport}")
    node.add(f"Destination Port: {layer.dport}")
    node.add(f"Length: {layer.len}")
    node.add(f"Checksum: 0x{layer.chksum:04x} [unverified]")
    if meta and meta.stream is not None:
        node.add(f"[Stream index: {meta.stream}]")
    node.add(f"UDP payload ({len(payload_bytes(layer))} bytes)")
    return node


def _dns(layer, meta):
    qr = layer.qr
    node = Node(f"Domain Name System ({'response' if qr else 'query'})", expanded=True)
    node.add(f"Transaction ID: 0x{layer.id:04x}")

    # 플래그 16비트 다시 조립
    flags = (qr << 15) | (layer.opcode << 11) | (layer.aa << 10) | (layer.tc << 9) | (layer.rd << 8) \
        | (layer.ra << 7) | (layer.z << 6) | (layer.ad << 5) | (layer.cd << 4) | layer.rcode
    desc = "Standard query" if not qr else f"Standard query response, {DNS_RCODES.get(layer.rcode, 'Error')}"
    fnode = node.add(f"Flags: 0x{flags:04x} {desc}")
    fnode.add(bitline(flags, 0x8000, 16, f"Response: Message is a {'response' if qr else 'query'}"))
    fnode.add(bitline(flags, 0x7800, 16, f"Opcode: Standard query ({layer.opcode})"))
    if qr:
        fnode.add(bitline(flags, 0x0400, 16, f"Authoritative: Server is {'' if layer.aa else 'not '}an authority for domain"))
    fnode.add(bitline(flags, 0x0200, 16, f"Truncated: Message is {'' if layer.tc else 'not '}truncated"))
    fnode.add(bitline(flags, 0x0100, 16, f"Recursion desired: {'Do' if layer.rd else 'Do not'} query recursively"))
    if qr:
        fnode.add(bitline(flags, 0x0080, 16, f"Recursion available: Server {'can' if layer.ra else 'cannot'} do recursive queries"))
    fnode.add(bitline(flags, 0x0040, 16, f"Z: reserved ({layer.z})"))
    if qr:
        fnode.add(bitline(flags, 0x0020, 16, f"Answer authenticated: Answer/authority portion was {'' if layer.ad else 'not '}authenticated by the server"))
    fnode.add(bitline(flags, 0x0010, 16, f"Non-authenticated data: {'Acceptable' if layer.cd else 'Unacceptable'}"))
    if qr:
        fnode.add(bitline(flags, 0x000F, 16, f"Reply code: {DNS_RCODES.get(layer.rcode, 'Error')} ({layer.rcode})"))

    node.add(f"Questions: {layer.qdcount}")
    node.add(f"Answer RRs: {layer.ancount}")
    node.add(f"Authority RRs: {layer.nscount}")
    node.add(f"Additional RRs: {layer.arcount}")

    questions = dns_records(layer.qd, layer.qdcount)
    if questions:
        qnode = node.add("Queries", expanded=True)
        for q in questions:
            name, qtype = dns_name(q.qname), DNS_TYPES.get(q.qtype, str(q.qtype))
            one = qnode.add(f"{name}: type {qtype}, class IN", expanded=True)
            one.add(f"Name: {name}")
            one.add(f"[Name Length: {len(name)}]")
            one.add(f"[Label Count: {len(name.split('.'))}]")
            one.add(f"Type: {qtype} ({DNS_TYPE_DESC.get(qtype, qtype)}) ({q.qtype})")
            one.add(f"Class: IN (0x{q.qclass:04x})")

    for title, section, count in (("Answers", layer.an, layer.ancount),
                                  ("Authoritative nameservers", layer.ns, layer.nscount),
                                  ("Additional records", layer.ar, layer.arcount)):
        records = dns_records(section, count)
        if records:
            snode = node.add(title, expanded=(title == "Answers"))
            for rr in records:
                _dns_rr(snode, rr)

    if meta and meta.link_kind == "dns":
        if not qr and meta.response_in is not None:
            node.add(f"[Response In: {meta.response_in + 1}]")
        if qr and meta.request_in is not None:
            node.add(f"[Request In: {meta.request_in + 1}]")
            node.add(f"[Time: {meta.rtt:.9f} seconds]")
    return node


def _dns_rr(parent, rr):
    rtype = DNS_TYPES.get(rr.type, str(rr.type))
    name = dns_name(getattr(rr, "rrname", b""))
    value = dns_rdata(rr)
    kind = {"A": "addr", "AAAA": "addr", "CNAME": "cname", "NS": "ns", "PTR": "domain name"}.get(rtype)
    head = f"{name}: type {rtype}, class IN"
    if kind:
        head += f", {kind} {value}"
    elif rtype == "SOA":
        head += f", mname {value}"
    one = parent.add(head, expanded=True)
    one.add(f"Name: {name}")
    one.add(f"Type: {rtype} ({DNS_TYPE_DESC.get(rtype, rtype)}) ({rr.type})")
    if rtype == "OPT":
        one.add(f"UDP payload size: {rr.rclass}")
        return
    one.add(f"Class: IN (0x{rr.rclass:04x})")
    ttl = rr.ttl
    one.add(f"Time to live: {ttl} ({human_seconds(ttl)})")
    rdlen = rr.rdlen
    if rdlen is None:                           # scapy가 안 채워줄 때가 있어서 직접 계산
        rdlen = {"A": 4, "AAAA": 16}.get(rtype, "?")
    one.add(f"Data length: {rdlen}")
    if rtype == "A" or rtype == "AAAA":
        one.add(f"Address: {value}")
    elif rtype == "CNAME":
        one.add(f"CNAME: {value}")
    elif rtype == "SOA":
        one.add(f"Primary name server: {dns_name(rr.mname)}")
        one.add(f"Responsible authority's mailbox: {dns_name(rr.rname)}")
        one.add(f"Serial Number: {rr.serial}")
        one.add(f"Refresh Interval: {rr.refresh} ({human_seconds(rr.refresh)})")
        one.add(f"Retry Interval: {rr.retry} ({human_seconds(rr.retry)})")
        one.add(f"Expire limit: {rr.expire} ({human_seconds(rr.expire)})")
        one.add(f"Minimum TTL: {rr.minimum} ({human_seconds(rr.minimum)})")
    else:
        one.add(f"Data: {value}")


def _http(data, meta, nodes):
    http = parse_http(data)
    node = Node("Hypertext Transfer Protocol", expanded=True)
    first = node.add(f"{http['first_line']}\\r\\n")
    if http["kind"] == "request":
        first.add(f"Request Method: {http['method']}")
        first.add(f"Request URI: {http['uri']}")
        first.add(f"Request Version: {http['version']}")
    else:
        first.add(f"Response Version: {http['version']}")
        first.add(f"Status Code: {http['status']}")
        first.add(f"Response Phrase: {http['phrase']}")
    for name, value in http["headers"]:
        node.add(f"{name}: {value}\\r\\n")
    if http["complete_head"]:
        node.add("\\r\\n")

    host = http_header(http, "Host")
    if http["kind"] == "request" and host:
        node.add(f"[Full request URI: http://{host}{http['uri']}]")
    if meta and meta.link_kind == "http":
        if http["kind"] == "request" and meta.response_in is not None:
            node.add(f"[Response in frame: {meta.response_in + 1}]")
        if http["kind"] == "response" and meta.request_in is not None:
            node.add(f"[Time since request: {meta.rtt:.9f} seconds]")
            node.add(f"[Request in frame: {meta.request_in + 1}]")
    body = http["body"]
    if body:
        node.add(f"File Data: {len(body)} bytes")
    nodes.append(node)

    if body:                                    # 본문은 Wireshark처럼 따로 한 덩어리
        ctype = (http_header(http, "Content-Type") or "data").split(";")[0]
        lines = body.decode("utf-8", errors="replace").split("\n")
        text_node = Node(f"Line-based text data: {ctype} ({len(lines)} lines)", expanded=True)
        for line in lines[:200]:
            text_node.add(f"{line.rstrip(chr(13))}\\n")
        if len(lines) > 200:
            text_node.add(f"... ({len(lines) - 200} lines more)")
        nodes.append(text_node)


def _tls(data):
    node = Node("Transport Layer Security", expanded=True)
    for rec in tls_records(data):
        version = TLS_VERSIONS.get(rec["version"], f"0x{rec['version']:04x}")
        ctype = TLS_RECORDS[rec["type"]]
        title = f"{version} Record Layer: {ctype}"
        if "handshake" in rec:
            title += f" Protocol: {TLS_HANDSHAKES.get(rec['handshake'], 'Handshake')}"
        rnode = node.add(title, expanded=True)
        rnode.add(f"Content Type: {ctype} ({rec['type']})")
        rnode.add(f"Version: {version} (0x{rec['version']:04x})")
        rnode.add(f"Length: {rec['length']}")
        if "handshake" in rec:
            rnode.add(f"Handshake Type: {TLS_HANDSHAKES.get(rec['handshake'], 'Unknown')} ({rec['handshake']})")
        if rec.get("sni"):
            rnode.add(f"Server Name Indication: {rec['sni']}")
    if not node.children:
        node.add("Continuation Data (앞 패킷에서 이어지는 내용)")
    return node


def _data(data):
    node = Node(f"Data ({len(data)} bytes)")
    shown = data[:64].hex()
    node.add(f"Data: {shown}{'…' if len(data) > 64 else ''}")
    node.add(f"[Length: {len(data)}]")
    return node


def _icmp(pkt, layer, meta, packets):
    node = Node("Internet Control Message Protocol", expanded=True)
    node.add(f"Type: {layer.type} ({ICMP_TYPES.get(layer.type, 'Unknown')})")
    code = ICMP_CODES.get(layer.type, {}).get(layer.code)
    node.add(f"Code: {layer.code}" + (f" ({code})" if code else ""))
    node.add(f"Checksum: 0x{layer.chksum:04x} [unverified]")

    if layer.type in (0, 8):                    # ping
        node.add(f"Identifier (BE): {layer.id} (0x{layer.id:04x})")
        node.add(f"Sequence Number (BE): {layer.seq} (0x{layer.seq:04x})")
        if meta and meta.link_kind in ("icmp", "traceroute"):
            if layer.type == 8 and meta.response_in is not None:
                label = "Response frame" if meta.link_kind == "icmp" else "[traceroute] 이 요청에 대한 ICMP 에러"
                node.add(f"[{label}: {meta.response_in + 1}]")
            if layer.type == 0 and meta.request_in is not None:
                node.add(f"[Request frame: {meta.request_in + 1}]")
                node.add(f"[Response time: {_ms(meta.rtt)}]")
        data = payload_bytes(layer)
        if data:
            node.add(f"Data ({len(data)} bytes)")

    elif layer.type in (3, 11) and pkt.haslayer(IPerror):
        # 에러 안에 들어있는 "원래 보냈던 패킷" 보여주기 (traceroute 분석 핵심)
        inner = pkt[IPerror]
        inode = node.add(f"Internet Protocol Version 4, Src: {inner.src}, Dst: {inner.dst}", expanded=True)
        inode.add(f"Time to Live: {inner.ttl}")
        inode.add(f"Protocol: {IP_PROTOCOLS.get(inner.proto, 'Unknown')} ({inner.proto})")
        if pkt.haslayer(UDPerror):
            u = pkt[UDPerror]
            node.add(f"User Datagram Protocol, Src Port: {u.sport}, Dst Port: {u.dport}")
        elif pkt.haslayer(TCPerror):
            t = pkt[TCPerror]
            node.add(f"Transmission Control Protocol, Src Port: {t.sport}, Dst Port: {t.dport}")
        elif pkt.haslayer(ICMPerror):
            e = pkt[ICMPerror]
            node.add(f"Internet Control Message Protocol (Echo request), id={e.id}, seq={e.seq}")

        if meta and meta.request_in is not None:
            probe = packets[meta.request_in] if packets else None
            ttl = probe[IP].ttl if probe is not None and probe.haslayer(IP) else "?"
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            node.add(f"[원래 요청(probe): {meta.request_in + 1}번 패킷, TTL={ttl}]")
            node.add(f"[응답까지 걸린 시간: {_ms(meta.rtt)}]")
            if layer.type == 11:
                node.add(f"[traceroute 해석: TTL={ttl}로 보낸 요청이 라우터 {src}에서 TTL 만료 -> {ttl}번째 홉 = {src}]")
            else:
                node.add(f"[traceroute 해석: 목적지 {src}가 직접 응답 (포트 닫힘) -> 도착 완료]")
    return node


def _icmpv6(layer, meta):
    name = layer.name
    node = Node("Internet Control Message Protocol v6", expanded=True)
    node.add(f"Type: {name.replace('ICMPv6 ', '', 1)} ({layer.type})")
    node.add(f"Code: {getattr(layer, 'code', 0)}")
    if hasattr(layer, "id") and hasattr(layer, "seq"):
        node.add(f"Identifier: 0x{layer.id:04x}")
        node.add(f"Sequence: {layer.seq}")
        if meta and meta.response_in is not None:
            node.add(f"[Response In: {meta.response_in + 1}]")
        if meta and meta.request_in is not None:
            node.add(f"[Request In: {meta.request_in + 1}]")
            node.add(f"[Response Time: {_ms(meta.rtt)}]")
    if hasattr(layer, "tgt"):
        node.add(f"Target Address: {layer.tgt}")
    return node


def _arp(layer):
    op = {1: "request", 2: "reply"}.get(layer.op, str(layer.op))
    node = Node(f"Address Resolution Protocol ({op})", expanded=True)
    node.add(f"Hardware type: {'Ethernet' if layer.hwtype == 1 else layer.hwtype} ({layer.hwtype})")
    node.add(f"Protocol type: {ETHER_TYPES.get(layer.ptype, 'Unknown')} (0x{layer.ptype:04x})")
    node.add(f"Hardware size: {layer.hwlen}")
    node.add(f"Protocol size: {layer.plen}")
    node.add(f"Opcode: {op} ({layer.op})")
    node.add(f"Sender MAC address: {layer.hwsrc}")
    node.add(f"Sender IP address: {layer.psrc}")
    node.add(f"Target MAC address: {layer.hwdst}")
    node.add(f"Target IP address: {layer.pdst}")
    return node


def _generic(layer):
    # 따로 안 만든 층은 필드 이름: 값 으로
    node = Node(layer.name)
    for f in layer.fields_desc:
        node.add(f"{f.name}: {layer.getfieldval(f.name)}")
    return node


def build_tree(pkt, no, meta=None, t0=None, packets=None):
    nodes = [_frame(pkt, no, meta, t0 if t0 is not None else pkt.time)]

    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        if isinstance(layer, Padding):
            break
        if layer.__class__.__name__ == "Loopback":      # 맥 lo0 는 Ethernet 대신 이게 붙음
            node = Node("Null/Loopback")
            node.add(f"Family: {'IPv4' if layer.type == 2 else 'IPv6' if layer.type in (24, 28, 30) else layer.type} ({layer.type})")
            nodes.append(node)
        elif isinstance(layer, Ether):
            nodes.append(_ethernet(layer))
        elif isinstance(layer, Dot3):
            nodes.append(_dot3(layer))
        elif isinstance(layer, IP):
            nodes.append(_ipv4(layer))
        elif isinstance(layer, IPv6):
            nodes.append(_ipv6(layer))
        elif isinstance(layer, ARP):
            nodes.append(_arp(layer))
            break
        elif isinstance(layer, TCP):
            nodes.append(_tcp(layer, meta))
            data = payload_bytes(layer)         # TCP 위 내용은 바이트 보고 직접 판단
            if parse_http(data):
                _http(data, meta, nodes)
            elif data and data[0] in TLS_RECORDS and len(data) > 2 and data[1] == 3:
                nodes.append(_tls(data))
            elif data:
                nodes.append(_data(data))
            break
        elif isinstance(layer, UDP):
            nodes.append(_udp(layer, meta))
            if isinstance(layer.payload, DNS):
                nodes.append(_dns(layer.payload, meta))
            elif payload_bytes(layer):
                nodes.append(_data(payload_bytes(layer)))
            break
        elif isinstance(layer, ICMP):
            nodes.append(_icmp(pkt, layer, meta, packets))
            break
        elif layer.__class__.__name__.startswith("ICMPv6"):
            nodes.append(_icmpv6(icmpv6_layer(pkt), meta))
            break
        elif isinstance(layer, Raw):
            nodes.append(_data(bytes(layer.load)))
            break
        else:
            nodes.append(_generic(layer))
        layer = layer.payload

    # 맨 마지막 진짜 프로토콜은 펼쳐서 보여주기 (Data 같은 건 빼고)
    for node in reversed(nodes[1:]):
        if not node.text.startswith(("Data (", "Line-based")):
            node.expanded = True
            break

    # 원래 쓰던 scapy 필드 보기도 남겨둠 (접힌 채로)
    raw = Node("[scapy 원본 필드]")
    for layer_name, fields in build_detail(pkt):
        lnode = raw.add(layer_name)
        for name, value in fields:
            lnode.add(f"{name}: {value}")
    nodes.append(raw)
    return nodes
