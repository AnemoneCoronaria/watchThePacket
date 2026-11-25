from scapy.all import TCP, UDP

from core.packet_parser import endpoints, get_protocol, make_info, tcp_flag_names

# 흐름도(Flow Graph)에 그릴 줄들을 만드는 파일 (Qt 몰라도 됨)
# 실제 그림은 gui/flow_graph.py 가 그림
#
# build_flow_rows(indices, packets, metas, t0) -> (호스트 목록, 줄 목록)
#   줄 하나 = dict(index, time, src, dst, sport, dport, label, comment, phase, phase_label, stream)

MAX_ROWS = 1000     # 너무 많으면 그림이 엄청 길어져서 앞에서부터 이만큼만


def _tcp_label(tcp, seg_len):
    # 화살표 위 글자: "SYN" / "SYN, ACK" / "PSH, ACK - Len: 81" (Wireshark TCP 흐름이랑 같은 모양)
    label = ", ".join(tcp_flag_names(tcp)) or "<None>"
    return f"{label} - Len: {seg_len}" if seg_len else label


def build_flow_rows(indices, packets, metas, t0):
    hosts, rows = [], []
    for i in indices[:MAX_ROWS]:
        pkt, meta = packets[i], metas[i]
        src, dst = endpoints(pkt)
        if not src or not dst:
            continue
        for host in (src, dst):                 # 처음 나온 순서대로 세로줄 만들기
            if host not in hosts:
                hosts.append(host)

        sport = dport = ""
        proto = get_protocol(pkt, meta)
        info = make_info(pkt, proto, meta)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            label = _tcp_label(tcp, meta.seg_len or 0)      # 설명서 22쪽처럼 화살표엔 플래그 + 길이
            seq = meta.rel_seq if meta.rel_seq is not None else tcp.seq
            comment = f"Seq = {seq}"
            if "ACK" in tcp_flag_names(tcp):
                ack = meta.rel_ack if meta.rel_ack is not None else tcp.ack
                comment += f" Ack = {ack}"
            if proto != "TCP":                              # HTTP/TLS 내용은 오른쪽 설명에
                comment += f"   [{proto}] {info}"
        else:
            if pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            label = info
            comment = f"{proto}: {info}"

        rows.append({
            "index": i, "time": float(pkt.time - t0), "src": src, "dst": dst, "sport": sport, "dport": dport,
            "label": label, "comment": comment, "phase": meta.phase, "phase_label": meta.phase_label,
            "stream": (meta.stream_proto, meta.stream),
        })
    return hosts, rows


def phase_groups(rows):
    # 연달아 같은 단계인 줄들을 한 덩어리로: [(시작줄, 끝줄, 단계), ...]  (TCP만)
    groups = []
    for r, row in enumerate(rows):
        phase = row["phase"]
        # 연결(스트림)이 달라도 같은 단계면 한 덩어리로 묶음
        # (브라우저처럼 연결 여러 개가 섞여 오면, 스트림별로 끊을 때 색 띠가 한 줄씩 조각나서 못 알아봄)
        if phase and groups and groups[-1][2] == phase and groups[-1][1] == r - 1:
            groups[-1][1] = r
        elif phase:
            groups.append([r, r, phase])
    return [tuple(g) for g in groups]
