import ipaddress
import re

from scapy.all import Ether, Dot3, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
from scapy.layers.inet import IPerror, UDPerror, TCPerror, ICMPerror

from core.packet_parser import get_protocol, payload_bytes, parse_http, http_data, http_header, dns_records, dns_name, dns_rdata

# 표시 필터: 이미 잡은 패킷 중에 "보여줄 것만" 고르는 글자 해석기
# Qt는 몰라도 됨 (터미널에서 테스트 가능)
#
# parse_filter("tcp and port 80") -> 함수(pkt, meta) -> True/False
#   True면 보여주고, False면 숨김
#   글자가 비어 있으면 None (= 필터 없음, 다 보여줌)
#   문법이 틀리면 ValueError (메시지는 그대로 사용자에게 보여줘도 됨)
#   meta = analyzer가 만든 관계 정보 (tcp.stream, 상대 tcp.seq 같은 데 씀. 없어도 됨)
#
# 쓸 수 있는 것
#   프로토콜 : tcp udp icmp icmpv6 arp ip ipv6 eth dns http tls stp
#   비교     : 필드 == 값   != > < >= <=   (eq ne gt lt ge le 도 됨),  필드 contains "글자"
#              필드만 쓰면 "그 필드가 있는 패킷"
#   BPF 느낌 : port 80   host 1.1.1.1   src 1.1.1.1   dst 1.1.1.1
#   조합     : and  or  not  ( )     (&&  ||  !  도 됨)
#   필드 목록은 아래 FIELDS 참고 (ip.addr, tcp.flags.syn, icmp.type, dns.qry.name ...)

# 레이어가 들어있는지로 판단하는 단어들
LAYER_WORDS = {
    "tcp": TCP, "udp": UDP, "icmp": ICMP, "arp": ARP,
    "ip": IP, "ipv6": IPv6, "eth": Ether,
}

# 표의 Protocol 칸 글자랑 똑같은지로 판단하는 단어들
APP_WORDS = {"dns", "http", "tls", "icmpv6", "stp"}

WORD_OPS = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=", "contains": "contains"}
OPS = {"==", "!=", ">", "<", ">=", "<=", "contains"}

# 글자 쪼개기용: "따옴표", 괄호, 비교기호, &&, ||, !, 단어, (그 외 이상한 글자 1개)
TOKEN_RE = re.compile(r'"[^"]*"|\(|\)|==|!=|>=|<=|>|<|&&|\|\||!|[^\s()=!&|<>"]+|\S')


# ICMP 에러(traceroute 응답 등) 안에 들어있는 "원래 보낸 패킷"의 헤더도 같이 봄 (Wireshark랑 같음)
#   예) 라우터가 보낸 Time-to-live exceeded 안에는 내가 보낸 IP(목적지 주소)와 UDP(포트)가 들어있어서
#       ip.addr==목적지, udp.port==33434 필터에 같이 걸림 (2차/3차 설명서 화면이 이렇게 나옴)
INNER = {IP: IPerror, UDP: UDPerror, TCP: TCPerror, ICMP: ICMPerror}


def _layers(pkt, cls):
    found = [pkt[cls]] if pkt.haslayer(cls) else []
    inner = INNER.get(cls)
    if inner is not None and pkt.haslayer(inner):
        found.append(pkt[inner])
    return found


# ---- 필드 값 꺼내는 함수들: (pkt, meta) -> 값 리스트 (없으면 빈 리스트) ----
def _layer_vals(cls, *attrs):
    def get(pkt, meta):
        return [getattr(layer, a) for layer in _layers(pkt, cls) for a in attrs]
    return get


def _eth(*attrs):
    def get(pkt, meta):
        for cls in (Ether, Dot3):
            if pkt.haslayer(cls):
                return [getattr(pkt[cls], a) for a in attrs]
        return []
    return get


def _tcp_flag(letter):
    return lambda pkt, meta: [int(letter in str(pkt[TCP].flags))] if pkt.haslayer(TCP) else []


def _tcp_rel(name):
    # 상대 Seq/Ack (analyzer가 계산한 것). 없으면 원래 값
    def get(pkt, meta):
        if not pkt.haslayer(TCP):
            return []
        rel = getattr(meta, "rel_" + name, None) if meta else None
        return [rel if rel is not None else getattr(pkt[TCP], name)]
    return get


def _stream(proto):
    return lambda pkt, meta: [meta.stream] if meta and meta.stream_proto == proto else []


def _http(fn):
    def get(pkt, meta):
        if not pkt.haslayer(TCP):
            return []
        if meta is not None and (meta.http_partial or meta.repeat_data):
            return []
        info = parse_http(http_data(pkt, meta))
        value = fn(info) if info else None
        return [value] if value is not None else []
    return get


def _dns_questions(attr, conv):
    def get(pkt, meta):
        if not pkt.haslayer(DNS):
            return []
        return [conv(getattr(q, attr)) for q in dns_records(pkt[DNS].qd, pkt[DNS].qdcount)]
    return get


def _dns_answers(rtype):
    def get(pkt, meta):
        if not pkt.haslayer(DNS):
            return []
        return [dns_rdata(rr) for rr in dns_records(pkt[DNS].an, pkt[DNS].ancount) if rr.type == rtype]
    return get


# 이름 -> (값 꺼내는 함수, 값 종류)   종류: ip / mac / int / str
FIELDS = {
    "ip.addr": (_layer_vals(IP, "src", "dst"), "ip"),
    "ip.src": (_layer_vals(IP, "src"), "ip"),
    "ip.dst": (_layer_vals(IP, "dst"), "ip"),
    "ip.ttl": (_layer_vals(IP, "ttl"), "int"),
    "ip.proto": (_layer_vals(IP, "proto"), "int"),
    "ip.len": (_layer_vals(IP, "len"), "int"),
    "ip.id": (_layer_vals(IP, "id"), "int"),
    "ipv6.addr": (_layer_vals(IPv6, "src", "dst"), "ip"),
    "ipv6.src": (_layer_vals(IPv6, "src"), "ip"),
    "ipv6.dst": (_layer_vals(IPv6, "dst"), "ip"),
    "ipv6.hlim": (_layer_vals(IPv6, "hlim"), "int"),
    "eth.addr": (_eth("src", "dst"), "mac"),
    "eth.src": (_eth("src"), "mac"),
    "eth.dst": (_eth("dst"), "mac"),
    "tcp.port": (_layer_vals(TCP, "sport", "dport"), "int"),
    "tcp.srcport": (_layer_vals(TCP, "sport"), "int"),
    "tcp.dstport": (_layer_vals(TCP, "dport"), "int"),
    "tcp.len": (lambda pkt, meta: [len(payload_bytes(pkt[TCP]))] if pkt.haslayer(TCP) else [], "int"),
    "tcp.seq": (_tcp_rel("seq"), "int"),
    "tcp.ack": (_tcp_rel("ack"), "int"),
    "tcp.seq_raw": (_layer_vals(TCP, "seq"), "int"),
    "tcp.ack_raw": (_layer_vals(TCP, "ack"), "int"),
    "tcp.window_size": (_layer_vals(TCP, "window"), "int"),
    "tcp.stream": (_stream("tcp"), "int"),
    # 우리 프로그램 전용: 연결 단계 (handshake / data / teardown) -> tcp.phase==handshake
    # Wireshark 전문가 분석 필드들 (재전송 종류)
    "tcp.analysis.retransmission": (lambda pkt, meta: [1] if meta is not None and (meta.retransmission or meta.fast_retransmission or meta.spurious) else [], "int"),
    "tcp.analysis.fast_retransmission": (lambda pkt, meta: [1] if meta is not None and meta.fast_retransmission else [], "int"),
    "tcp.analysis.spurious_retransmission": (lambda pkt, meta: [1] if meta is not None and meta.spurious else [], "int"),
    "tcp.analysis.out_of_order": (lambda pkt, meta: [1] if meta is not None and meta.out_of_order else [], "int"),
    "tcp.analysis.keep_alive": (lambda pkt, meta: [1] if meta is not None and meta.keepalive else [], "int"),
    "tcp.phase": (lambda pkt, meta: [meta.phase] if meta and meta.phase else [], "str"),
    "tcp.flags.syn": (_tcp_flag("S"), "int"),
    "tcp.flags.ack": (_tcp_flag("A"), "int"),
    "tcp.flags.fin": (_tcp_flag("F"), "int"),
    "tcp.flags.reset": (_tcp_flag("R"), "int"),
    "tcp.flags.rst": (_tcp_flag("R"), "int"),
    "tcp.flags.push": (_tcp_flag("P"), "int"),
    "tcp.flags.urg": (_tcp_flag("U"), "int"),
    "udp.port": (_layer_vals(UDP, "sport", "dport"), "int"),
    "udp.srcport": (_layer_vals(UDP, "sport"), "int"),
    "udp.dstport": (_layer_vals(UDP, "dport"), "int"),
    "udp.length": (_layer_vals(UDP, "len"), "int"),
    "udp.stream": (_stream("udp"), "int"),
    "icmp.type": (_layer_vals(ICMP, "type"), "int"),
    "icmp.code": (_layer_vals(ICMP, "code"), "int"),
    "icmp.ident": (lambda pkt, meta: [pkt[ICMP].id] if pkt.haslayer(ICMP) and pkt[ICMP].type in (0, 8) else [], "int"),
    "icmp.seq": (lambda pkt, meta: [pkt[ICMP].seq] if pkt.haslayer(ICMP) and pkt[ICMP].type in (0, 8) else [], "int"),
    "dns.id": (_layer_vals(DNS, "id"), "int"),
    "dns.flags.response": (_layer_vals(DNS, "qr"), "int"),
    "dns.flags.rcode": (_layer_vals(DNS, "rcode"), "int"),
    "dns.qry.name": (_dns_questions("qname", dns_name), "str"),
    "dns.qry.type": (_dns_questions("qtype", int), "int"),
    "dns.a": (_dns_answers(1), "ip"),
    "dns.aaaa": (_dns_answers(28), "ip"),
    "http.request.method": (_http(lambda h: h.get("method")), "str"),
    "http.request.uri": (_http(lambda h: h.get("uri")), "str"),
    "http.host": (_http(lambda h: http_header(h, "Host")), "str"),
    "http.response.code": (_http(lambda h: h.get("status")), "int"),
    "frame.len": (lambda pkt, meta: [len(pkt)], "int"),
    "frame.number": (lambda pkt, meta: [meta.index + 1] if meta else [], "int"),
}


# ---- 값 비교 ----
def _make_test(op, value, kind):
    # (실제값 -> True/False) 함수 만들기. 값이 이상하면 여기서 ValueError

    if kind == "int":
        if op == "contains":
            raise ValueError("숫자 필드에는 contains를 못 써요")
        low = value.lower()
        if low in ("true", "false"):
            target = int(low == "true")
        else:
            try:
                target = int(value, 0)          # 80, 0x50 둘 다 됨
            except ValueError:
                raise ValueError(f"숫자여야 해요: {value}")
        return {
            "==": lambda a: a == target, "!=": lambda a: a == target,     # != 는 밖에서 뒤집음
            ">": lambda a: a > target, "<": lambda a: a < target,
            ">=": lambda a: a >= target, "<=": lambda a: a <= target,
        }[op]

    if op not in ("==", "!=", "contains"):
        raise ValueError(f"{'주소' if kind != 'str' else '글자'}는 크기 비교(> <)를 못 해요. == 나 != 를 써 주세요")

    if kind == "str" or op == "contains":
        low = value.lower()                     # 대소문자 구분 안 함 (편하게)
        if op == "contains":
            return lambda a: low in str(a).lower()
        return lambda a: str(a).lower() == low

    if kind == "mac":
        low = value.lower()
        return lambda a: str(a).lower() == low

    # 여기부터 IP 주소 (한 개 or 192.168.0.0/24 같은 대역)
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"주소 모양이 이상해요: {value}")

        def in_net(actual):
            try:
                return ipaddress.ip_address(actual) in net
            except ValueError:
                return False
        return in_net

    try:
        target = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"IP 주소 모양이 이상해요: {value}")

    def same(actual):
        try:
            return ipaddress.ip_address(actual) == target     # 압축 표기가 달라도 같은 주소로 봄
        except ValueError:
            return False
    return same


def _field_pred(getter, op, test):
    # 값이 여러 개(ip.addr = 출발+도착)면 하나라도 맞으면 True
    # 단, != 는 "전부 아니어야" True (Wireshark랑 같음)
    if op == "!=":
        return lambda pkt, meta: bool(getter(pkt, meta)) and not any(test(v) for v in getter(pkt, meta))
    return lambda pkt, meta: any(test(v) for v in getter(pkt, meta))


def _host_pair(pkt):                            # host/src/dst 용: IPv4, IPv6, ARP 중 먼저 보이는 것
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None


# ---- 해석기 (and/or/not/괄호) ----
# 우선순위: not > and > or
class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):                     # 다음 글자 (소문자로). 없으면 None
        return self.tokens[self.i].lower() if self.i < len(self.tokens) else None

    def take(self):                     # 다음 글자 꺼내기 (원래 대소문자 그대로)
        if self.i >= len(self.tokens):
            raise ValueError("필터가 중간에 끝났어요")
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def take_value(self):               # 값 꺼내기 ("따옴표" 벗기기)
        tok = self.take()
        if tok.lower() in ("and", "or", "not", "&&", "||", "!", "(", ")"):
            raise ValueError(f"값이 와야 하는데 {tok} 가 왔어요")
        return tok[1:-1] if tok.startswith('"') and tok.endswith('"') else tok

    def parse_or(self):
        left = self.parse_and()
        while self.peek() in ("or", "||"):
            self.take()
            right = self.parse_and()
            left = (lambda a, b: lambda pkt, meta: a(pkt, meta) or b(pkt, meta))(left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() in ("and", "&&"):
            self.take()
            right = self.parse_not()
            left = (lambda a, b: lambda pkt, meta: a(pkt, meta) and b(pkt, meta))(left, right)
        return left

    def parse_not(self):
        if self.peek() in ("not", "!"):
            self.take()
            inner = self.parse_not()
            return lambda pkt, meta: not inner(pkt, meta)
        return self.parse_atom()

    def parse_atom(self):
        if self.peek() == "(":
            self.take()
            inner = self.parse_or()
            if self.peek() != ")":
                raise ValueError("괄호가 안 닫혔어요")
            self.take()
            return inner
        return self.parse_term()

    def parse_term(self):
        tok = self.take()
        word = tok.lower()

        if word in FIELDS:              # ip.addr == 1.1.1.1 / tcp.flags.syn == 1 / dns.qry.name contains "a"
            getter, kind = FIELDS[word]
            op = WORD_OPS.get(self.peek(), self.peek())
            if op not in OPS:           # 필드만 쓰면 "그 필드가 있는 패킷"
                return lambda pkt, meta: bool(getter(pkt, meta))
            self.take()
            test = _make_test(op, self.take_value(), kind)
            return _field_pred(getter, op, test)

        if word in LAYER_WORDS:         # tcp, udp, ip ... (ICMP 에러 안에 들어있는 것도 포함, Wireshark랑 같음)
            layer = LAYER_WORDS[word]
            return lambda pkt, meta: bool(_layers(pkt, layer))

        if word in APP_WORDS:           # dns, http, tls ...
            return lambda pkt, meta: get_protocol(pkt, meta).lower() == word

        if word == "port":              # port 80 (tcp든 udp든)
            test = _make_test("==", self.take_value(), "int")
            return lambda pkt, meta: any(test(v) for v in FIELDS["tcp.port"][0](pkt, meta) + FIELDS["udp.port"][0](pkt, meta))

        if word in ("host", "src", "dst"):      # host 1.1.1.1
            test = _make_test("==", self.take_value(), "ip")
            pick = {"host": slice(0, 2), "src": slice(0, 1), "dst": slice(1, 2)}[word]

            def host_pred(pkt, meta):
                pair = _host_pair(pkt)
                return bool(pair) and any(test(v) for v in pair[pick])
            return host_pred

        if word in OPS or word in WORD_OPS:
            raise ValueError(f"{tok} 앞에 필드 이름이 와야 해요 (예: ip.addr {tok} 1.1.1.1)")
        raise ValueError(f"모르는 단어예요: {tok}")


def parse_filter(text):
    text = text.strip()
    if not text:
        return None                     # 필터 없음

    parser = _Parser(TOKEN_RE.findall(text))
    pred = parser.parse_or()

    if parser.i != len(parser.tokens):  # 다 읽었는데 남은 글자가 있으면 이상한 것
        raise ValueError(f"뜻을 모르겠어요: {parser.tokens[parser.i]}")
    return pred


if __name__ == "__main__":
    # 가짜 패킷으로 테스트 (sudo 필요 없음)
    # 실행: .venv/bin/python -m core.display_filter
    from scapy.all import DNSQR

    pkts = {
        "syn80": Ether() / IP(src="1.1.1.1", dst="2.2.2.2", ttl=64) / TCP(dport=80, flags="S"),
        "dns":   Ether() / IP(src="3.3.3.3", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="www.tukorea.ac.kr")),
        "trace": Ether() / IP(src="3.3.3.3", dst="8.8.8.8", ttl=1) / UDP(dport=33434),
        "ttlx":  Ether() / IP(src="10.0.0.1", dst="3.3.3.3") / ICMP(type=11),
        "arp":   Ether() / ARP(psrc="192.168.0.1", pdst="192.168.0.2"),
    }
    pkts = {k: Ether(bytes(v)) for k, v in pkts.items()}
    for text in ["tcp", "udp or arp", "ip.addr == 8.8.8.8", "port 80 and not udp", "tcp.flags.syn==1 && tcp.flags.ack==0",
                 "udp.dstport>=33434", "icmp.type==11", "ip.ttl==1", "ip.addr!=8.8.8.8", 'dns.qry.name contains "tukorea"',
                 "tcp.port eq 80", "tcpp", "ip.addr ==", "ip.addr > 1.1.1.1"]:
        try:
            pred = parse_filter(text)
            print(f"{text!r:42}", [name for name, p in pkts.items() if pred(p, None)])
        except ValueError as e:
            print(f"{text!r:42} 에러: {e}")
