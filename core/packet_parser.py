from scapy.all import Packet, Ether, Dot3, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, STP, Padding

# scapy 패킷을 화면에 보여줄 글자로 바꿔주는 파일
# Qt는 몰라도 되는 애들이라 터미널에서도 테스트 가능
#
# get_protocol : Protocol 칸에 쓸 이름 정하기 (TCP, DNS, HTTP, TLS ...)
# make_info    : Info 칸에 쓸 한 줄 설명 만들기 (Wireshark 느낌)
# summarize    : 표 한 줄 만들기
# hex_dump     : 오른쪽 hex 뷰용 글자 만들기 (완성)
# build_detail : scapy 원본 필드 그대로 (완성. 상세 트리 맨 아래 "[scapy 원본 필드]"에 씀)
#
# meta = core/analyzer.py 가 만들어 주는 "패킷 사이 관계" 정보 (상대 Seq, 짝꿍 패킷 번호 등)
#        없으면(None) 그냥 패킷 하나만 보고 만듦


# ---- 이름표들 ----
HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")

# TCP 플래그 한 글자 -> 이름 (scapy는 "SA" 처럼 글자로 줌). Wireshark랑 같은 순서로 보여주려고 순서도 정해둠
TCP_FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
TCP_FLAG_ORDER = "FSRPAUEC"

# TLS 레코드 종류 (첫 바이트) / 핸드셰이크 종류
TLS_RECORDS = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}
TLS_HANDSHAKES = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions",
                  11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request",
                  14: "Server Hello Done", 15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished"}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 41: "OPT", 64: "SVCB", 65: "HTTPS"}
DNS_RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented", 5: "Refused"}

ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo (ping) request", 11: "Time-to-live exceeded"}
ICMP_CODES = {
    3: {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable", 3: "Port unreachable",
        4: "Fragmentation needed", 9: "Network administratively prohibited",
        10: "Host administratively prohibited", 13: "Communication administratively filtered"},
    11: {0: "Time to live exceeded in transit", 1: "Fragment reassembly time exceeded"},
}


# ---- 공통 도우미 ----
def payload_bytes(layer):
    # 이 층이 실어 나르는 진짜 내용 (바이트). 짧은 프레임에 붙는 Padding(0으로 채운 것)은 뺌
    # 이거 안 빼면 60바이트 프레임에서 Len이 6처럼 엉뚱하게 나옴
    data = bytes(layer.payload)
    if layer.payload.haslayer(Padding):
        data = data[: len(data) - len(bytes(layer.payload[Padding]))]
    return data


def tcp_flag_names(tcp):
    # "SA" -> ["SYN", "ACK"] (Wireshark 순서: FIN SYN RST PSH ACK ...)
    letters = str(tcp.flags)
    return [TCP_FLAGS[ch] for ch in TCP_FLAG_ORDER if ch in letters]


def is_http(data):
    return data.startswith(HTTP_STARTS)


def is_tls(data):
    # TLS는 첫 3바이트가 (종류 20~23, 3, 버전 0~4) 모양
    return len(data) >= 3 and data[0] in TLS_RECORDS and data[1] == 3 and data[2] <= 4


def parse_http(data):
    # HTTP 메시지를 쪼개서 dict로. HTTP 아니면 None
    #   kind: "request" / "response", first_line, method, uri, version, status, phrase
    #   headers: [(이름, 값), ...]   body: 바이트
    if not is_http(data):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    first = lines[0]
    info = {"first_line": first, "headers": [], "body": body, "complete_head": b"\r\n\r\n" in data}

    parts = first.split(" ", 2)
    if first.startswith("HTTP/"):
        info["kind"] = "response"
        info["version"] = parts[0]
        info["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        info["phrase"] = parts[2] if len(parts) > 2 else ""
    else:
        info["kind"] = "request"
        info["method"] = parts[0]
        info["uri"] = parts[1] if len(parts) > 1 else ""
        info["version"] = parts[2] if len(parts) > 2 else ""

    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            info["headers"].append((name.strip(), value.strip()))
    return info


def http_header(info, name):
    # 헤더 값 하나 찾기 (대소문자 무시). 없으면 None
    for key, value in info["headers"]:
        if key.lower() == name.lower():
            return value
    return None


def tls_records(data, limit=10):
    # TCP 내용에 들어있는 TLS 레코드들을 쪼갬 (한 패킷에 여러 개 들어있을 수 있음)
    # [{"type", "version", "length", "handshake"(있으면), "sni"(Client Hello면)}, ...]
    records = []
    pos = 0
    while pos + 5 <= len(data) and len(records) < limit:
        ctype, version, length = data[pos], int.from_bytes(data[pos + 1:pos + 3], "big"), int.from_bytes(data[pos + 3:pos + 5], "big")
        if ctype not in TLS_RECORDS or data[pos + 1] != 3:
            break
        rec = {"type": ctype, "version": version, "length": length}
        body = data[pos + 5:pos + 5 + length]
        if ctype == 22 and body:
            rec["handshake"] = body[0]
            if body[0] == 1:
                rec["sni"] = _client_hello_sni(body)
        records.append(rec)
        pos += 5 + length
    return records


def _client_hello_sni(hs):
    # Client Hello 안에서 접속하려는 서버 이름(SNI) 꺼내기. 못 찾으면 None
    try:
        pos = 4 + 2 + 32                        # 핸드셰이크 헤더(4) + 버전(2) + 랜덤(32)
        pos += 1 + hs[pos]                      # 세션 ID
        pos += 2 + int.from_bytes(hs[pos:pos + 2], "big")   # 암호 목록
        pos += 1 + hs[pos]                      # 압축 방식
        end = pos + 2 + int.from_bytes(hs[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= end:                   # 확장(extension)들 하나씩
            etype = int.from_bytes(hs[pos:pos + 2], "big")
            elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
            if etype == 0:                      # 0번이 server_name
                name_len = int.from_bytes(hs[pos + 7:pos + 9], "big")
                return hs[pos + 9:pos + 9 + name_len].decode("ascii", errors="replace")
            pos += 4 + elen
    except (IndexError, ValueError):
        pass
    return None


def icmpv6_layer(pkt):
    # ICMPv6 계열 층이 있으면 그 층을 돌려줌 (종류가 엄청 많아서 이름으로 찾음)
    for cls in reversed(pkt.layers()):
        if cls.__name__.startswith("ICMPv6") and "Option" not in cls.__name__:
            return pkt.getlayer(cls)
    return None


def dns_records(section, count):
    # DNS 질문/답 부분을 리스트로 (scapy 버전에 따라 모양이 달라서 하나씩 꺼냄)
    out = []
    for i in range(count or 0):
        try:
            out.append(section[i])
        except (IndexError, TypeError):
            break
    return out


def dns_name(value):
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    value = str(value).rstrip(".")
    return value or "<Root>"


def dns_rdata(rr):
    # 답 레코드 내용을 글자로 (주소, 이름 등)
    if DNS_TYPES.get(getattr(rr, "type", None)) == "SOA":
        return dns_name(rr.mname)
    rdata = getattr(rr, "rdata", "")
    if isinstance(rdata, list):
        rdata = " ".join(dns_name(x) if isinstance(x, bytes) else str(x) for x in rdata)
    if isinstance(rdata, bytes):
        return dns_name(rdata)
    return str(rdata).rstrip(".") if isinstance(rdata, str) else str(rdata)


def get_protocol(pkt):
    # Protocol 칸에 쓸 이름. 위쪽 층(앱)부터 확인해야 함
    if pkt.haslayer(TCP):
        data = payload_bytes(pkt[TCP])
        if is_http(data):
            return "HTTP"
        if is_tls(data):
            return "TLS"
        return "TCP"
    if pkt.haslayer(UDP):
        return "DNS" if pkt.haslayer(DNS) else "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if icmpv6_layer(pkt) is not None:
        return "ICMPv6"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    if pkt.haslayer(STP):
        return "STP"
    return "Other"


# ---- Info 칸 ----
def tcp_option_text(tcp):
    # SYN 같은 데 붙는 옵션들 (MSS=1460 SACK_PERM TSval=.. TSecr=.. WS=128)
    parts = []
    for name, value in tcp.options:
        if name == "MSS":
            parts.append(f"MSS={value}")
        elif name == "SAckOK":
            parts.append("SACK_PERM")
        elif name == "Timestamp":
            parts.append(f"TSval={value[0]} TSecr={value[1]}")
        elif name == "WScale":
            parts.append(f"WS={2 ** value}")
    return " ".join(parts)


def _info_tcp(pkt, meta):
    tcp = pkt[TCP]
    names = tcp_flag_names(tcp)
    seq = meta.rel_seq if meta and meta.rel_seq is not None else tcp.seq
    info = f"{tcp.sport} → {tcp.dport} [{', '.join(names) or '<None>'}] Seq={seq}"
    if "ACK" in names:                      # Ack은 ACK 플래그 있을 때만 의미 있음
        ack = meta.rel_ack if meta and meta.rel_ack is not None else tcp.ack
        info += f" Ack={ack}"
    info += f" Win={tcp.window} Len={len(payload_bytes(tcp))}"
    options = tcp_option_text(tcp)
    return f"{info} {options}" if options else info


def _info_http(pkt):
    http = parse_http(payload_bytes(pkt[TCP]))
    text = http["first_line"][:120]
    if http["kind"] == "response":          # 응답이면 내용 종류도 (Wireshark 처럼)
        ctype = http_header(http, "Content-Type")
        if ctype:
            text += f"  ({ctype.split(';')[0]})"
    return text


def _info_tls(pkt):
    names = []
    for rec in tls_records(payload_bytes(pkt[TCP])):
        if rec["type"] == 22 and "handshake" in rec:
            name = TLS_HANDSHAKES.get(rec["handshake"], "Handshake")
            if rec.get("sni"):
                name += f" (SNI={rec['sni']})"
            names.append(name)
        else:
            names.append(TLS_RECORDS[rec["type"]])
    return ", ".join(dict.fromkeys(names)) or "Continuation Data"     # 같은 이름 겹치면 한 번만


def _info_dns(pkt):
    dns = pkt[DNS]
    questions = dns_records(dns.qd, dns.qdcount)
    qname, qtype = "", ""
    if questions:
        qname = dns_name(questions[0].qname)
        qtype = DNS_TYPES.get(questions[0].qtype, str(questions[0].qtype))

    if dns.qr == 0:
        return f"Standard query 0x{dns.id:04x} {qtype} {qname}"

    text = f"Standard query response 0x{dns.id:04x}"
    if dns.rcode:
        text += f" {DNS_RCODES.get(dns.rcode, 'Error')}"
    text += f" {qtype} {qname}"
    for rr in dns_records(dns.an, dns.ancount)[:4] + dns_records(dns.ns, dns.nscount)[:1]:
        text += f" {DNS_TYPES.get(rr.type, rr.type)} {dns_rdata(rr)}"
    return text


def _info_icmp(pkt, meta):
    icmp = pkt[ICMP]
    name = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
    if icmp.type in (0, 8):                     # ping이면 id, seq, ttl, 짝꿍 번호도
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else "?"
        name += f" id=0x{icmp.id:04x}, seq={icmp.seq}, ttl={ttl}"
        if meta and icmp.type == 8 and meta.response_in is not None:
            name += f" (reply in {meta.response_in + 1})"
        if meta and icmp.type == 0 and meta.request_in is not None:
            name += f" (request in {meta.request_in + 1})"
        return name
    code = ICMP_CODES.get(icmp.type, {}).get(icmp.code)
    return f"{name} ({code})" if code else name


def _info_icmpv6(pkt, meta):
    layer = icmpv6_layer(pkt)
    name = layer.name.replace("ICMPv6 ", "", 1)         # "ICMPv6 Echo Request" -> "Echo Request"
    name = name.split(" - ")[-1]                        # "Neighbor Discovery - Neighbor Solicitation" -> 뒤쪽만
    if hasattr(layer, "seq") and hasattr(layer, "id"):  # ping6
        name += f" id=0x{layer.id:04x}, seq={layer.seq}"
        if meta and meta.response_in is not None:
            name += f" (reply in {meta.response_in + 1})"
        if meta and meta.request_in is not None:
            name += f" (request in {meta.request_in + 1})"
    target = getattr(layer, "tgt", None)                # NS/NA는 대상 주소도
    return f"{name} for {target}" if target else name


def _info_arp(pkt):
    arp = pkt[ARP]
    if arp.op == 1:
        return f"Who has {arp.pdst}? Tell {arp.psrc}"
    if arp.op == 2:
        return f"{arp.psrc} is at {arp.hwsrc}"
    return pkt.summary()


def make_info(pkt, proto, meta=None):
    # Info 칸에 쓸 한 줄. 프로토콜별로 필요한 값만 꺼내서 문장으로 만듦
    # 하다가 에러 나면 (이상하게 생긴 패킷) 그냥 scapy 요약으로 대신함
    try:
        if proto == "HTTP":
            return _info_http(pkt)
        if proto == "TLS":
            return _info_tls(pkt)
        if proto == "TCP":
            return _info_tcp(pkt, meta)
        if proto == "DNS":
            return _info_dns(pkt)
        if proto == "UDP":
            udp = pkt[UDP]
            return f"{udp.sport} → {udp.dport} Len={len(payload_bytes(udp))}"
        if proto == "ICMP":
            return _info_icmp(pkt, meta)
        if proto == "ICMPv6":
            return _info_icmpv6(pkt, meta)
        if proto == "ARP":
            return _info_arp(pkt)
        if proto == "STP":
            return "Spanning Tree Protocol"
    except Exception:
        pass

    summary = pkt.summary()                     # 나머지는 scapy 요약에서 앞의 "Ether / " 만 떼기
    return summary.replace("Ether / ", "", 1)


def endpoints(pkt):
    # (출발 주소, 도착 주소). IP > IPv6 > ARP > MAC 순으로 먼저 있는 걸 씀
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst   # 얘는 MAC 주소
    if pkt.haslayer(Dot3):
        return pkt[Dot3].src, pkt[Dot3].dst     # 802.3 (STP 같은 것) 도 MAC 주소
    return "", ""


def summarize(pkt, no, t0, meta=None):
    # 패킷 하나 받아서 표 한 줄(글자 7개)로 만들어줌
    # no = 몇 번째 패킷, t0 = 맨 처음 패킷의 시간, meta = 관계 정보 (없어도 됨)

    # Time: 첫 패킷부터 몇 초 지났는지
    time_str = f"{float(pkt.time - t0):.6f}"

    # Source / Destination
    # haslayer(X) = 이 패킷에 X가 들어있나?
    # pkt[X] = 그 부분만 꺼내기 (없는데 꺼내면 에러남)
    src, dst = endpoints(pkt)

    proto = get_protocol(pkt)            # Protocol 칸
    length = len(pkt)                    # 전체 바이트 수
    info = make_info(pkt, proto, meta)   # Info 칸

    # 표 열 순서랑 똑같이 맞춰야 함
    return [str(no), time_str, src, dst, proto, str(length), info]


def build_detail(pkt):
    # 패킷을 층별로 쪼개서 상세 트리에 넣을 데이터를 만든다
    # 결과 모양:
    #   [
    #     ("Ethernet", [("dst", "aa:bb:..."), ("src", "cc:dd:..."), ...]),
    #     ("IP",       [("src", "1.1.1.1"), ("dst", "2.2.2.2"), ...]),
    #     ("TCP",      [("sport", "443"), ("dport", "80"), ...]),
    #   ]
    result = []

    for layer_cls in pkt.layers():
        layer = pkt.getlayer(layer_cls)     # 층 하나 꺼내기

        fields = []                         # 이 층의 (필드이름, 값) 모음

        for f in layer.fields_desc:         # 필드 하나씩
            fields.append((f.name, str(layer.getfieldval(f.name))))

        result.append((layer.name, fields))

    return result



def hex_dump(pkt):
    # 패킷을 hex 뷰에 넣을 글자(여러 줄)로 만든다
    # 한 줄 모양: 0000  45 00 00 28 ...   E..(....
    #            (주소)  (hex 16개)       (글자)
    data = bytes(pkt)

    lines = []

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]       # 16바이트 씩 자르기
        address = f"{i:04x}"       # 앞에 주소 부분 4자리 16진수
        hex_part = " ".join(f"{b:02x}" for b in chunk)   # hex 부분

        text = ""   # 오른쪽 글자 부분

        for b in chunk:
            if 32 <= b <= 126:      # 읽을 수 있는 문자면?
                text += chr(b)
            else:                   # 아니면 그냥 .(점))
                text += "."

        # 한 줄로 합쳐서 리스트에 쌓기
        lines.append(f"{address}  {hex_part.ljust(47)}  {text}")

    return "\n".join(lines)



if __name__ == "__main__":
    # 캡처 없이 가짜 패킷으로 테스트하는 곳 (sudo 필요 없음)
    # 실행: .venv/bin/python -m core.packet_parser
    from scapy.all import Raw, DNSQR, DNSRR

    def rebuild(p):
        return Ether(bytes(p))      # 바이트로 만들었다 다시 읽으면 진짜 캡처 패킷이랑 같아짐

    samples = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=443, dport=52341, flags="SA", seq=1, ack=2,
                                                          options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)]),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=80, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n"),
        Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, flags="PA") / Raw(b"HTTP/1.1 307 Temporary Redirect\r\nContent-Type: text/html\r\n\r\n<html>"),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443) / Raw(bytes([0x16, 3, 1, 0, 5, 1, 0, 0, 0, 0])),
        Ether() / IP(src="3.3.3.3", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(id=0x5c, qd=DNSQR(qname="google.com")),
        Ether() / IP(src="8.8.8.8", dst="3.3.3.3") / UDP(sport=53, dport=5353)
        / DNS(id=0x5c, qr=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="1.2.3.4"), ancount=1),
        Ether() / IP(src="3.3.3.3", dst="8.8.8.8") / UDP(sport=1000, dport=2000) / Raw(b"hi"),
        Ether() / IP(src="3.3.3.3", dst="8.8.8.8") / ICMP(type=8, id=1, seq=7),
        Ether() / IP(src="10.0.0.1", dst="3.3.3.3") / ICMP(type=11, code=0),
        Ether() / ARP(op=1, psrc="192.168.0.1", pdst="192.168.0.2"),
    ]

    t0 = None
    for i, p in enumerate(samples, start=1):
        p = rebuild(p)
        t0 = t0 or p.time
        row = summarize(p, i, t0)
        print(f"{row[4]:6} {row[6]}")

    p1 = samples[0]
    print(hex_dump(p1))
    print(build_detail(p1))
