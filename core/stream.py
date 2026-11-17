from scapy.all import TCP, UDP

from core.packet_parser import payload_bytes, endpoints

# 스트림 따라가기 (Follow TCP/UDP Stream) 내용 만드는 파일 (Qt 몰라도 됨)
# 같은 연결(스트림)의 패킷들이 실어 나른 내용을 순서대로 이어 붙임
#   클라이언트(처음 보낸 쪽) -> 서버 : 방향 0 (화면에서 빨강)
#   서버 -> 클라이언트            : 방향 1 (화면에서 파랑)
#
# collect_stream(...) -> {"client", "server", "chunks": [(방향, 바이트, 패킷번호)], "packets", "bytes": [0방향, 1방향]}
# render(chunks, mode) -> [(방향, 글자), ...]   mode = "ascii" / "utf8" / "hex"


def collect_stream(proto, stream_id, packets, metas):
    layer_cls = TCP if proto == "tcp" else UDP
    client = server = None
    chunks, count, seen = [], 0, set()
    total = [0, 0]

    for i, meta in enumerate(metas):
        if meta.stream_proto != proto or meta.stream != stream_id:
            continue
        pkt = packets[i]
        layer = pkt[layer_cls]
        src, dst = endpoints(pkt)
        count += 1
        me = (src, layer.sport)
        if client is None:                      # 처음 보낸 쪽이 클라이언트
            client, server = me, (dst, layer.dport)
        direction = 0 if me == client else 1

        data = payload_bytes(layer)
        if not data:
            continue
        if proto == "tcp":                      # 재전송(같은 내용 또 보냄)은 한 번만
            key = (direction, layer.seq, len(data))
            if key in seen:
                continue
            seen.add(key)
        chunks.append((direction, data, i))
        total[direction] += len(data)

    return {"client": client, "server": server, "chunks": chunks, "packets": count, "bytes": total}


def _ascii(data, utf8=False):
    # 읽을 수 있는 글자는 그대로, 나머지는 "." (Wireshark랑 같음). \r 은 지우고 \n, 탭은 살림
    if utf8:
        text = data.decode("utf-8", errors="replace")
        return "".join(ch if ch.isprintable() or ch in "\n\t" else ("" if ch == "\r" else ".") for ch in text)
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10) else ("" if b == 13 else ".") for b in data)


def _hex_lines(data, offset, indent):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{offset + i:08X}  {hex_part.ljust(47)}  {text}")
    return "\n".join(lines) + "\n"


def render(chunks, mode="ascii", only=None):
    # only = None(전부) / 0(클라이언트->서버만) / 1(서버->클라이언트만)
    segments = []
    offsets = [0, 0]
    for direction, data, _ in chunks:
        if only is not None and direction != only:
            continue
        if mode == "hex":
            # 서버 쪽은 들여쓰기 (Wireshark Hex Dump 모양)
            text = _hex_lines(data, offsets[direction], "    " if direction else "")
            offsets[direction] += len(data)
        else:
            text = _ascii(data, utf8=(mode == "utf8"))
            if not text.endswith("\n"):         # 덩어리(패킷/방향)마다 줄 바꿈
                text += "\n"
        if segments and segments[-1][0] == direction:
            segments[-1] = (direction, segments[-1][1] + text)      # 같은 방향 연달아 오면 합치기
        else:
            segments.append((direction, text))
    return segments


if __name__ == "__main__":
    # 실행: .venv/bin/python -m core.stream  (가짜 HTTP 대화로 시험)
    from scapy.all import Ether, IP, Raw
    from core.analyzer import Analyzer

    pk = [
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="S", seq=100),
        Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, dport=5000, flags="SA", seq=900, ack=101),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="PA", seq=101) / Raw(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
        Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="PA", seq=101) / Raw(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
        Ether() / IP(src="2.2.2.2", dst="1.1.1.1") / TCP(sport=80, dport=5000, flags="PA", seq=901) / Raw(b"HTTP/1.1 200 OK\r\n\r\nhello"),
    ]
    pk = [Ether(bytes(p)) for p in pk]
    an = Analyzer()
    metas = [an.add(p) for p in pk]
    s = collect_stream("tcp", 0, pk, metas)
    print("client", s["client"], "server", s["server"], "packets", s["packets"], "bytes", s["bytes"], "(재전송 1개는 빠져야 함)")
    for mode in ("ascii", "hex"):
        print(f"--- {mode}")
        for d, text in render(s["chunks"], mode):
            print(("[빨강] " if d == 0 else "[파랑] ") + text.rstrip("\n").replace("\n", "\n       "))
