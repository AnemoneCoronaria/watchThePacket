from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS
from scapy.layers.inet import IPerror, UDPerror, TCPerror, ICMPerror

from core.packet_parser import payload_bytes, parse_http, tcp_flag_names, icmpv6_layer, is_http, http_complete

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
        self.retransmission = False # 이미 보낸 데이터를 다시 보낸 패킷인지 ([TCP Retransmission])
        self.repeat_data = False    # 전에 본 데이터를 그대로 또 보냄 (이러면 Protocol도 TCP로)
        self.port_reused = False    # 끝난 연결과 같은 포트로 새 연결 ([TCP Port numbers reused])
        self.keepalive = False      # 연결 살아있나 확인용 1바이트 ([TCP Keep-Alive])
        self.fast_retransmission = False    # 중복 ACK 받고 바로 다시 보냄 ([TCP Fast Retransmission])
        self.spurious = False       # 상대가 이미 받았다고 한 데이터를 또 보냄 ([TCP Spurious Retransmission])
        self.out_of_order = False   # 순서가 바뀌어 도착 ([TCP Out-Of-Order])
        self.dup_ack = None         # 중복 ACK면 (원래 ACK 패킷 번호, 몇 번째) ([TCP Dup ACK 341#1])
        self.sack = []              # SACK 구간들 (상대 Seq 기준) [(시작, 끝), ...]
        self.http_data = None       # HTTP 메시지 전체 바이트 (여러 조각을 이어 붙였으면 그 결과)
        self.http_parts = None      # 이어 붙인 조각들 [(패킷 번호, 길이), ...] (2개 이상일 때)
        self.http_partial = False   # HTTP 중간 조각 (아직 덜 옴)
        self.reassembled_in = None  # 이 조각이 이어 붙여진 패킷 번호
        self.win_calc = None        # 창 크기 x 배율 (Wireshark의 Calculated window size)
        self.win_scale = None       # 창 크기 배율 (예: 128). 모르면 None
        self.link_kind = None       # 짝꿍 종류 ("dns", "icmp", "http", "traceroute")


class _TcpStream:
    def __init__(self, index, client):
        self.index = index
        self.client = client        # 처음 보낸 쪽 (주소, 포트)
        self.base = [None, None]    # 방향별 처음 Seq (0: client->server, 1: 반대)
        self.synack_seen = False
        # 아래는 Wireshark(packet-tcp.c)가 방향별로 기억하는 것들 (재전송 / 순서 바뀜 판정용)
        self.nextseq = [None, None]     # 지금까지 보낸 데이터의 끝 (상대 Seq)
        self.segments = [[], []]        # 보낸 구간들 [(시작, 끝), ...] -> 이미 본 데이터인지 확인
        self.lastack = [None, None]     # 이 방향이 마지막으로 보낸 ACK (상대 Seq 기준)
        self.lastacktime = [None, None] # 이 방향 마지막 패킷 시각
        self.lastacklen = [0, 0]        # 마지막으로 새 데이터 보냈을 때의 길이
        self.window = [None, None]      # 마지막 창 크기 (중복 ACK 판단용)
        self.dupack = [0, 0]            # 중복 ACK 개수 (Fast Retransmission 판단용)
        self.lastnondupack = [None, None]   # 중복 아닌 마지막 ACK 패킷 번호
        self.syn_time = None        # 첫 SYN 시각
        self.first_rtt = None       # 3-way handshake 왕복 시간 (Wireshark가 순서 바뀜 판단 기준으로 씀)
        self.syn_seq = [None, None] # 방향별 SYN의 Seq (다른 Seq로 SYN 오면 포트 재사용 = 새 연결)
        self.closed = False         # FIN이나 RST가 오갔는지
        self.wscale = [None, None]  # 방향별 창 크기 배율(SYN에 붙은 WS 옵션). 양쪽 다 있어야 씀
        self.established = False
        self.fin_seen = False
        self.teardown_step = 0
        self.http_requests = []     # 아직 응답 못 받은 HTTP 요청 번호들
        self.http_buf = [None, None]    # 방향별 이어 붙이는 중인 HTTP {"data", "parts", "next"}


def _ip_pair(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def ping_stats(packets, metas, src, dst, ident):
    # 터미널 ping 맨 끝 통계랑 같은 것: 보낸 수, 받은 수, 손실률, rtt min/avg/max/mdev (ms)
    # (src -> dst, 같은 id 인 ping 묶음 기준)
    from scapy.all import IP, ICMP
    sent, rtts = 0, []
    for pkt, meta in zip(packets, metas):
        if pkt.haslayer(ICMP) and pkt.haslayer(IP) and pkt[ICMP].type == 8 and pkt[ICMP].id == ident \
                and pkt[IP].src == src and pkt[IP].dst == dst:
            sent += 1
            if meta.response_in is not None and metas[meta.response_in].link_kind == "icmp":
                rtts.append(metas[meta.response_in].rtt * 1000)
    if not sent:
        return None
    result = {"sent": sent, "received": len(rtts), "loss": round(100 * (sent - len(rtts)) / sent)}
    if rtts:
        avg = sum(rtts) / len(rtts)
        mdev = max(sum(r * r for r in rtts) / len(rtts) - avg * avg, 0) ** 0.5    # 리눅스 ping이랑 같은 식
        result.update(min=min(rtts), avg=avg, max=max(rtts), mdev=mdev)
    return result


class Analyzer:
    def __init__(self):
        self.reset()

    def reset(self):
        self.metas = []
        self.reassembled_now = []
        self._tcp = {}              # 연결 키 -> 지금 그 포트 쌍의 _TcpStream
        self._tcp_count = 0         # 지금까지 나온 TCP 스트림 수 (포트 재사용하면 늘어남)
        self._udp = {}              # 연결 키 -> 스트림 번호
        self._dns_wait = {}         # (클라이언트 주소, 포트, DNS id) -> 요청 번호
        self._echo_wait = {}        # (보낸 쪽, 받는 쪽, id, seq) -> ping 요청 번호
        self._probes = {}           # (보낸 쪽, 받는 쪽, 출발포트, 도착포트) -> UDP 패킷 번호 (traceroute용)

    def stream_count(self, proto):
        # 지금까지 나온 스트림 개수 ("tcp" / "udp")
        return self._tcp_count if proto == "tcp" else len(self._udp)

    # ---- 짝꿍 연결 ----
    def _link(self, req_index, meta, kind):
        req = self.metas[req_index]
        req.response_in = meta.index
        meta.request_in = req_index
        meta.rtt = meta.time - req.time
        meta.link_kind = req.link_kind = kind

    def add(self, pkt):
        self.reassembled_now = []    # 이번 패킷 덕분에 Info가 바뀌는 앞 패킷들 (화면 갱신용)
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
        names = set(tcp_flag_names(tcp))
        seg_len = len(payload_bytes(tcp))
        stream = self._tcp.get(key)
        if stream is not None and "SYN" in names:
            d0 = 0 if me == stream.client else 1
            # 끝난 연결에 SYN이 오거나, 다른 시작 번호로 SYN이 오면 = 같은 포트로 새 연결 (Wireshark랑 같음)
            if stream.closed or (stream.syn_seq[d0] is not None and stream.syn_seq[d0] != tcp.seq):
                stream = None
                meta.port_reused = True
        if stream is None:
            stream = self._tcp[key] = _TcpStream(self._tcp_count, me)
            self._tcp_count += 1

        d = 0 if me == stream.client else 1          # 이 패킷의 방향
        if "SYN" in names:
            stream.syn_seq[d] = tcp.seq
            if "ACK" not in names and stream.syn_time is None:
                stream.syn_time = meta.time

        # 상대 Seq 기준 정하기 (Wireshark 규칙이랑 같게)
        #   SYN이면 그 Seq가 기준 -> SYN은 Seq=0
        #   SYN을 못 보고 중간부터 잡힌 연결이면 "첫 Seq - 1"이 기준 -> 첫 패킷이 Seq=1
        #   상대 방향을 아직 못 봤는데 ACK가 있으면 "ACK - 1"을 상대 기준으로 -> Ack=1
        if "SYN" in names:
            stream.base[d] = tcp.seq
        elif stream.base[d] is None:
            stream.base[d] = (tcp.seq - 1) % 2 ** 32
        if "ACK" in names and stream.base[1 - d] is None:
            stream.base[1 - d] = (tcp.ack - 1) % 2 ** 32
        meta.stream, meta.stream_proto = stream.index, "tcp"
        meta.seg_len = seg_len
        meta.rel_seq = (tcp.seq - stream.base[d]) % 2 ** 32
        if "ACK" in names:
            meta.rel_ack = (tcp.ack - stream.base[1 - d]) % 2 ** 32
        for name, value in tcp.options:              # SACK: "여기부터 여기까지는 받았어" (상대 Seq로)
            if name == "SAck" and value:
                edges = [(v - stream.base[1 - d]) % 2 ** 32 for v in value]
                meta.sack = list(zip(edges[0::2], edges[1::2]))
        meta.next_seq = meta.rel_seq + seg_len + ("SYN" in names) + ("FIN" in names)

        self._seq_analysis(stream, d, meta, names, seg_len, tcp)

        # 창 크기 배율: SYN 때 서로 알려준 WS 값. 양쪽 다 보냈을 때만 적용 (Wireshark랑 같음)
        # SYN 패킷 자체의 창 크기는 배율 안 곱함
        if "SYN" in names:
            shift = dict((k, v) for k, v in tcp.options if k == "WScale").get("WScale")
            stream.wscale[d] = shift if shift is not None else -1     # -1 = 이 쪽은 배율 안 씀
            meta.win_calc = tcp.window
        elif -1 in stream.wscale:          # 한쪽이라도 배율 안 쓴다고 했으면 배율 없음
            meta.win_scale = 1
            meta.win_calc = tcp.window
        elif stream.wscale[d] is not None:  # 이 방향 배율을 알면 적용 (상대 SYN을 못 봤어도. Wireshark랑 같음)
            meta.win_scale = 2 ** stream.wscale[d]
            meta.win_calc = tcp.window * meta.win_scale
        else:                               # 모르면 원래 값 그대로
            meta.win_calc = tcp.window

        # 연결 단계 정하기
        if "SYN" in names and "ACK" not in names:
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 1/3: SYN"
        elif "SYN" in names:
            stream.synack_seen = True
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 2/3: SYN, ACK"
        elif stream.synack_seen and not stream.established and names == {"ACK"} and seg_len == 0 and d == 0:
            stream.established = True
            if stream.syn_time is not None:
                stream.first_rtt = meta.time - stream.syn_time
            meta.phase, meta.phase_label = "handshake", "연결 설정 (3-way handshake) 3/3: ACK"
        elif "RST" in names:
            stream.closed = True
            meta.phase, meta.phase_label = "teardown", "연결 강제 종료 (RST)"
        elif "FIN" in names or (stream.fin_seen and seg_len == 0):
            stream.fin_seen = True
            stream.closed = True
            stream.teardown_step += 1
            meta.phase, meta.phase_label = "teardown", f"연결 해제 {stream.teardown_step}단계: {', '.join(tcp_flag_names(tcp))}"
        else:
            stream.established = True
            meta.phase, meta.phase_label = "data", "데이터 송수신"

        # HTTP 조각 이어 붙이기 (Wireshark 재조립처럼: 중간 조각은 TCP, 마지막 조각에서 HTTP로)
        data = payload_bytes(tcp) if seg_len and not meta.repeat_data else b""
        buf = stream.http_buf[d]
        if data and buf is not None and meta.rel_seq == buf["next"]:
            buf["data"] += data
            buf["parts"].append((meta.index, seg_len))
            buf["next"] += seg_len
            if http_complete(buf["data"]):
                meta.http_data, meta.http_parts = buf["data"], buf["parts"]
                for index, _ in buf["parts"][:-1]:
                    self.metas[index].reassembled_in = meta.index
                    self.reassembled_now.append(index)
                stream.http_buf[d] = None
            else:
                meta.http_partial = True
        elif data and is_http(data):
            if http_complete(data):
                meta.http_data = data
            else:
                stream.http_buf[d] = {"data": data, "parts": [(meta.index, seg_len)], "next": meta.rel_seq + seg_len}
                meta.http_partial = True

        # HTTP 요청 -> 응답 짝꿍 (같은 연결 안에서 순서대로)
        http = parse_http(meta.http_data) if meta.http_data else None
        if http and http["kind"] == "request":
            stream.http_requests.append(meta.index)
        elif http and http["kind"] == "response" and stream.http_requests:
            self._link(stream.http_requests.pop(0), meta, "http")

    # ---- TCP 재전송 / 순서 바뀜 판정 (Wireshark packet-tcp.c 의 tcp_analyze_sequence_number 규칙 그대로) ----
    def _seq_analysis(self, stream, d, meta, names, seg_len, tcp):
        r = 1 - d                                   # 반대 방향
        seq, ctrl = meta.rel_seq, ("SYN" in names or "FIN" in names)
        end = seq + seg_len + (1 if ctrl else 0)    # 이 패킷이 차지하는 Seq의 끝
        nextseq = stream.nextseq[d]
        not_advanced = nextseq is not None and seq < nextseq      # 시작이 지금까지 보낸 끝보다 앞쪽

        # Keep-Alive: 끝 바로 앞 0~1바이트, 제어 플래그 없음 -> 재전송 판정 안 함
        if nextseq is not None and seg_len <= 1 and seq == nextseq - 1 and not ({"SYN", "FIN", "RST"} & names):
            meta.keepalive = True
        elif seg_len or ctrl:
            if seg_len > 1 and nextseq is not None and nextseq - 1 == seq:
                not_advanced = False
            r_ack = stream.lastack[r]
            already = any(a <= seq and seq + seg_len <= b for a, b in stream.segments[d])
            meta.repeat_data = already and seg_len > 0
            if seg_len > 0 and r_ack and seq + seg_len <= r_ack:
                meta.spurious = True                # 상대가 이미 받았다고 ACK한 데이터
            elif not_advanced:
                t = meta.time - stream.lastacktime[r] if stream.lastacktime[r] is not None else 0
                if t < 0.020 and stream.dupack[r] >= 2 and r_ack == seq:
                    meta.fast_retransmission = True     # 중복 ACK 2번 이상 받고 바로 다시 보냄
                elif t < (stream.first_rtt or 0.003) and not already and \
                        (nextseq != end or stream.lastacklen[d] == 0):
                    meta.out_of_order = True            # 처음 보는 데이터가 금방 도착 = 순서만 바뀜
                else:
                    meta.retransmission = True

        # 기억해 두기
        if seg_len or ctrl:
            stream.segments[d].append((seq, end))
            if len(stream.segments[d]) > 400:          # 너무 쌓이면 오래된 것부터 버림
                del stream.segments[d][:100]
        if nextseq is None or end > nextseq + (1 if ctrl else 0):
            stream.lastacklen[d] = seg_len
        if nextseq is None or end > nextseq:
            stream.nextseq[d] = end

        # 중복 ACK 세기 (데이터 없고, 창 크기/ACK 그대로)
        if "ACK" in names:
            if meta.rel_ack != stream.lastack[d]:
                stream.dupack[d] = 0
                stream.lastnondupack[d] = meta.index
            elif seg_len == 0 and tcp.window and seq == stream.nextseq[d] and not ({"SYN", "FIN", "RST"} & names) \
                    and (tcp.window == stream.window[d] or any(o[0] == "SAck" for o in tcp.options)):
                # (SACK이 붙은 중복 ACK는 창 크기가 바뀌어도 중복 ACK로 셈 - 실제 Wireshark 결과에 맞춤)
                stream.dupack[d] += 1
                meta.dup_ack = (stream.lastnondupack[d], stream.dupack[d])
            stream.lastack[d] = meta.rel_ack
        else:
            stream.lastack[d] = None
        stream.window[d] = tcp.window
        stream.lastacktime[d] = meta.time

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
                self._dns_wait.setdefault((pair[0], udp.sport, dns.id), meta.index)   # 다시 보낸 질의는 첫 질의 기준
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
