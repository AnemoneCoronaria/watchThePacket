from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS
from scapy.layers.inet import IPerror, UDPerror, TCPerror, ICMPerror

from core.packet_parser import payload_bytes, parse_http, tcp_flag_names, icmpv6_layer

# 패킷 "사이"의 관계를 정리하는 파일 (패킷 하나만 봐서는 모르는 것들)
# Qt는 몰라도 됨
#
#  - TCP/UDP 스트림 번호 (같은 연결끼리 묶기)
#  - 상대 Seq/Ack (Wireshark처럼 SYN이 Seq=0 으로 보이게)
#  - TCP 연결 단계 (3-way handshake / 데이터 송수신 / 연결 해제)
#  - 요청-응답 짝꿍 + 걸린 시간 (DNS, ping, HTTP, traceroute)
#
# 쓰는 법: 패킷 들어올 때마다 순서대로 add(pkt) -> PacketMeta 하나 돌려줌
#          analyzer.metas[i] 가 i번째 패킷의 정보 (행 번호랑 같음)


class PacketMeta:
    # 패킷 하나에 붙는 정보. 모르는 건 None
    def __init__(self, index, time):
        self.index = index          # 몇 번째 패킷인지 (0부터)
        self.time = time            # 캡처 시각 (초)
        self.stream = None          # 스트림 번호 (tcp/udp 따로 셈)
        self.stream_proto = None    # "tcp" / "udp"
        self.rel_seq = None         # 상대 Seq
        self.rel_ack = None         # 상대 Ack
        self.next_seq = None        # 다음에 올 Seq (상대)
        self.seg_len = None         # TCP가 실은 데이터 길이
        self.phase = None           # "handshake" / "data" / "teardown"
        self.phase_label = None     # 화면에 보여줄 단계 이름
        self.request_in = None      # (응답이면) 요청 패킷 번호
        self.response_in = None     # (요청이면) 응답 패킷 번호
        self.rtt = None             # 요청 -> 응답 걸린 시간 (초, 응답 쪽에 저장)
        self.link_kind = None       # 짝꿍 종류 ("dns", "icmp", "http", "traceroute")


class _TcpStream:
    def __init__(self, index, client):
        self.index = index
        self.client = client        # 처음 보낸 쪽 (주소, 포트)
        self.base = [None, None]    # 방향별 처음 Seq (0: client->server, 1: 반대)
        self.synack_seen = False
        self.established = False
        self.fin_seen = False
        self.teardown_step = 0
        self.http_requests = []     # 아직 응답 못 받은 HTTP 요청 번호들


def _ip_pair(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


class Analyzer:
    def __init__(self):
        self.reset()

    def reset(self):
        self.metas = []
        self._tcp = {}              # 연결 키 -> _TcpStream
        self._udp = {}              # 연결 키 -> 스트림 번호
        self._dns_wait = {}         # (클라이언트 주소, 포트, DNS id) -> 요청 번호
        self._echo_wait = {}        # (보낸 쪽, 받는 쪽, id, seq) -> ping 요청 번호
        self._probes = {}           # (보낸 쪽, 받는 쪽, 출발포트, 도착포트) -> UDP 패킷 번호 (traceroute용)

    def stream_count(self, proto):
        # 지금까지 나온 스트림 개수 ("tcp" / "udp")
        return len(self._tcp) if proto == "tcp" else len(self._udp)

    # ---- 짝꿍 연결 ----
    def _link(self, req_index, meta, kind):
        req = self.metas[req_index]
        req.response_in = meta.index
        meta.request_in = req_index
        meta.rtt = meta.time - req.time
        meta.link_kind = req.link_kind = kind

    def add(self, pkt):
        meta = PacketMeta(len(self.metas), float(pkt.time))
        self.metas.append(meta)
        pair = _ip_pair(pkt)

        if pair and pkt.haslayer(TCP):
            self._add_tcp(pkt, meta, pair)
        elif pair and pkt.haslayer(UDP):
            self._add_udp(pkt, meta, pair)

        if pair and pkt.haslayer(ICMP):
            self._add_icmp(pkt, meta, pair)
        elif pair and pkt.haslayer(IPv6):
            self._add_icmpv6(pkt, meta, pair)
        return meta

    # ---- TCP: 스트림, 상대 Seq/Ack, 연결 단계, HTTP 짝꿍 ----
    def _add_tcp(self, pkt, meta, pair):
        tcp = pkt[TCP]
        me, other = (pair[0], tcp.sport), (pair[1], tcp.dport)
        key = tuple(sorted([me, other]))
        stream = self._tcp.get(key)
        if stream is None:
            stream = self._tcp[key] = _TcpStream(len(self._tcp), me)

        d = 0 if me == stream.client else 1          # 이 패킷의 방향
        names = set(tcp_flag_names(tcp))
        seg_len = len(payload_bytes(tcp))

        if stream.base[d] is None:                   # 이 방향 첫 패킷의 Seq가 기준(0)
            stream.base[d] = tcp.seq
        meta.stream, meta.stream_proto = stream.index, "tcp"
        meta.seg_len = seg_len
        meta.rel_seq = (tcp.seq - stream.base[d]) % 2 ** 32
        if "ACK" in names and stream.base[1 - d] is not None:
            meta.rel_ack = (tcp.ack - stream.base[1 - d]) % 2 ** 32
        meta.next_seq = meta.rel_seq + seg_len + ("SYN" in names) + ("FIN" in names)

        # 연결 단계 정하기
        if "SYN" in names and "ACK" not in names:
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 1/3: SYN"
        elif "SYN" in names:
            stream.synack_seen = True
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 2/3: SYN, ACK"
        elif stream.synack_seen and not stream.established and names == {"ACK"} and seg_len == 0 and d == 0:
            stream.established = True
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 3/3: ACK"
        elif "RST" in names:
            meta.phase, meta.phase_label = "teardown", "연결 강제 종료 (RST)"
        elif "FIN" in names or (stream.fin_seen and seg_len == 0):
            stream.fin_seen = True
            stream.teardown_step += 1
            meta.phase, meta.phase_label = "teardown", f"연결 해제 {stream.teardown_step}단계: {', '.join(tcp_flag_names(tcp))}"
        else:
            stream.established = True
            meta.phase, meta.phase_label = "data", "데이터 송수신"

        # HTTP 요청 -> 응답 짝꿍 (같은 연결 안에서 순서대로)
        http = parse_http(payload_bytes(tcp)) if seg_len else None
        if http and http["kind"] == "request":
            stream.http_requests.append(meta.index)
        elif http and http["kind"] == "response" and stream.http_requests:
            self._link(stream.http_requests.pop(0), meta, "http")

    # ---- UDP: 스트림, DNS 짝꿍, traceroute 요청 기억 ----
    def _add_udp(self, pkt, meta, pair):
        udp = pkt[UDP]
        me, other = (pair[0], udp.sport), (pair[1], udp.dport)
        key = tuple(sorted([me, other]))
        if key not in self._udp:
            self._udp[key] = len(self._udp)
        meta.stream, meta.stream_proto = self._udp[key], "udp"

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0:
                self._dns_wait[(pair[0], udp.sport, dns.id)] = meta.index
            else:
                req = self._dns_wait.pop((pair[1], udp.dport, dns.id), None)
                if req is not None:
                    self._link(req, meta, "dns")
        else:
            # traceroute는 UDP를 보내고 ICMP 에러로 답이 옴. 나중에 짝 지으려고 기억해둠
            self._probes[(pair[0], pair[1], udp.sport, udp.dport)] = meta.index

    # ---- ICMP: ping 짝꿍, traceroute(시간초과/도달불가) 짝꿍 ----
    def _add_icmp(self, pkt, meta, pair):
        icmp = pkt[ICMP]
        if icmp.type == 8:
            self._echo_wait[(pair[0], pair[1], icmp.id, icmp.seq)] = meta.index
        elif icmp.type == 0:
            req = self._echo_wait.pop((pair[1], pair[0], icmp.id, icmp.seq), None)
            if req is not None:
                self._link(req, meta, "icmp")
        elif icmp.type in (3, 11) and pkt.haslayer(IPerror):
            # 에러 안에 "원래 보냈던 패킷 앞부분"이 들어있음 -> 그걸로 원래 요청 찾기
            inner = pkt[IPerror]
            req = None
            if pkt.haslayer(UDPerror):
                req = self._probes.get((inner.src, inner.dst, pkt[UDPerror].sport, pkt[UDPerror].dport))
            elif pkt.haslayer(ICMPerror):
                req = self._echo_wait.get((inner.src, inner.dst, pkt[ICMPerror].id, pkt[ICMPerror].seq))
            elif pkt.haslayer(TCPerror):
                req = None
            if req is not None:
                self._link(req, meta, "traceroute")

    def _add_icmpv6(self, pkt, meta, pair):
        layer = icmpv6_layer(pkt)
        if layer is None or not hasattr(layer, "seq"):
            return
        if layer.type == 128:                       # ping6 요청
            self._echo_wait[(pair[0], pair[1], layer.id, layer.seq)] = meta.index
        elif layer.type == 129:                     # ping6 응답
            req = self._echo_wait.pop((pair[1], pair[0], layer.id, layer.seq), None)
            if req is not None:
                self._link(req, meta, "icmp")
