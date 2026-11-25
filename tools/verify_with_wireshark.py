"""우리 프로그램 결과를 Wireshark(tshark)랑 비교하는 검증 도구

과제 설명서: "개발 프로그램의 정상 동작 여부는 wireshark를 통해 검증 필수"
-> 같은 pcap 파일을 우리 프로그램과 tshark로 각각 해석해서, 패킷마다 결과가 같은지 비교함

사용법 (프로젝트 폴더에서)
    1. 우리 프로그램으로 캡처하고 💾 저장 -> capture.pcap
    2. .venv/bin/python tools/verify_with_wireshark.py capture.pcap
       (필터도 비교하려면)  ... capture.pcap --filter "ip.addr==210.93.48.59 && icmp" --filter "dns"

필요한 것: tshark (Ubuntu: sudo apt install -y tshark / macOS: Wireshark 앱 설치하면 같이 들어있음)

비교하는 것
    1. 패킷마다 Protocol 칸, Info 칸
    2. ping(ICMP): id, seq(BE/LE), 짝꿍 패킷 번호, 응답 시간, 체크섬 검증, 데이터 속 보낸 시각, Data 길이
    3. DNS: Transaction ID, 짝꿍 패킷 번호, 응답 시간
    4. TCP: 스트림 번호, 상대 Seq/Ack, 창 크기(배율 계산), 데이터 길이
    5. 표시 필터: 같은 필터에 걸리는 패킷 번호가 같은지
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scapy.all import IP, TCP, UDP, ICMP, DNS                                # noqa: E402

from core.analyzer import Analyzer                                          # noqa: E402
from core.display_filter import parse_filter                                # noqa: E402
from core.packet_parser import summarize, swap16, payload_bytes             # noqa: E402
from core.pcap_io import load_pcap                                          # noqa: E402

# Wireshark 이름 -> 우리 이름 (같은 걸 다르게 부르는 것만)
PROTO_SAME = {"TLSv1": "TLS", "TLSv1.1": "TLS", "TLSv1.2": "TLS", "TLSv1.3": "TLS", "SSL": "TLS", "MDNS": "DNS"}


def find_tshark():
    for path in (shutil.which("tshark"), "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        if path and os.path.exists(path):
            return path
    sys.exit("tshark를 못 찾았어요. Ubuntu: sudo apt install -y tshark / macOS: Wireshark 앱 설치")


def tshark_fields(tshark, pcap, fields, display_filter=None):
    # tshark 결과를 {패킷번호: {필드: 값}} 으로
    # -2: Wireshark 화면처럼 두 번 훑음 (응답이 나중에 와도 요청 쪽 [Response In]이 채워짐)
    cmd = [tshark, "-r", pcap, "-2", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f", "-e", "frame.number"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        cols = line.split("\t")
        rows[int(cols[0])] = dict(zip(fields, cols[1:] + [""] * (len(fields) - len(cols) + 1)))
    return rows


def clean_info(text):
    # Wireshark만 붙이는 분석 꼬리표([TCP Retransmission] 등)와 여러 칸 띄어쓰기 정리
    text = text.strip()
    while text.startswith("["):
        end = text.find("]")
        if end < 0:
            break
        text = text[end + 1:].strip()
    return " ".join(text.split())


def main():
    ap = argparse.ArgumentParser(description="우리 프로그램 vs Wireshark(tshark) 비교")
    ap.add_argument("pcap")
    ap.add_argument("--filter", action="append", default=[], help="같이 비교할 표시 필터 (여러 번 가능)")
    ap.add_argument("--show", type=int, default=8, help="다른 점 몇 개까지 보여줄지")
    args = ap.parse_args()

    tshark = find_tshark()
    packets = load_pcap(args.pcap)
    an = Analyzer()
    metas = [an.add(p) for p in packets]
    t0 = packets[0].time if packets else 0
    ours = [summarize(p, i + 1, t0, m) for i, (p, m) in enumerate(zip(packets, metas))]
    print(f"파일: {args.pcap}  |  패킷 {len(packets)}개  |  {subprocess.run([tshark, '-v'], capture_output=True, text=True).stdout.splitlines()[0]}")

    ws = tshark_fields(tshark, args.pcap, ["_ws.col.Protocol", "_ws.col.Info"])
    report = []

    # ---- 1. Protocol / Info ----
    # 443번(HTTPS/QUIC 암호화)은 Wireshark가 여러 패킷을 재조립해서 해석하는데, 우리는 재조립을 안 함
    # -> 전체 결과와 "443 빼고" 결과를 따로 보여줌 (과제 명령어 nslookup/curl(HTTP)/ping/traceroute는 443 안 씀)
    def is_443(pkt):
        for cls in (TCP, UDP):
            if pkt.haslayer(cls) and 443 in (pkt[cls].sport, pkt[cls].dport):
                return True
        return False

    plain = [i for i in range(len(ours)) if not is_443(packets[i])]
    proto_ok, info_ok, info_total, proto_diff, info_diff = 0, 0, 0, [], []
    for i, row in enumerate(ours):
        w = ws.get(i + 1, {})
        w_proto = PROTO_SAME.get(w.get("_ws.col.Protocol", ""), w.get("_ws.col.Protocol", ""))
        if w_proto == row[4]:
            proto_ok += 1
        else:
            proto_diff.append((i + 1, row[4], w_proto))
        if row[4] in ("TCP", "HTTP", "DNS", "ICMP", "UDP", "ARP") and w_proto == row[4]:
            info_total += 1
            if clean_info(row[6]) == clean_info(w.get("_ws.col.Info", "")):
                info_ok += 1
            else:
                info_diff.append((i + 1, row[6], w.get("_ws.col.Info", "")))
    plain_set = set(n + 1 for n in plain)
    p_proto_diff = [d for d in proto_diff if d[0] in plain_set]
    p_info_diff = [d for d in info_diff if d[0] in plain_set]
    p_info_total = info_total - (len(info_diff) - len(p_info_diff)) - sum(
        1 for i in range(len(ours)) if i not in set(plain) and ours[i][4] in ("TCP", "HTTP", "DNS", "ICMP", "UDP", "ARP")
        and PROTO_SAME.get(ws.get(i + 1, {}).get("_ws.col.Protocol", ""), ws.get(i + 1, {}).get("_ws.col.Protocol", "")) == ours[i][4]
        and clean_info(ours[i][6]) == clean_info(ws.get(i + 1, {}).get("_ws.col.Info", "")))
    fmt_p = lambda diffs: [f"#{n}: 우리 {a} / Wireshark {b}" for n, a, b in diffs]
    fmt_i = lambda diffs: [f"#{n}\n      우리      : {a}\n      Wireshark : {b}" for n, a, b in diffs]
    report.append(("Protocol 칸 (443 암호화 트래픽 제외)", len(plain) - len(p_proto_diff), len(plain), fmt_p(p_proto_diff)))
    report.append(("Info 칸 (443 암호화 트래픽 제외)", p_info_total - len(p_info_diff), p_info_total, fmt_i(p_info_diff)))
    report.append(("(참고) Protocol 칸 전체", proto_ok, len(ours), fmt_p(proto_diff)))
    report.append(("(참고) Info 칸 전체", info_ok, info_total, fmt_i(info_diff)))

    # ---- 2. ping ----
    icmp = tshark_fields(tshark, args.pcap, ["icmp.ident", "icmp.seq", "icmp.seq_le", "icmp.resp_in", "icmp.resp_to",
                                             "icmp.resptime", "icmp.checksum.status", "icmp.data_time_relative", "data.len"],
                         "icmp.type==0 || icmp.type==8")
    ok, total, diff = 0, 0, []
    for n, w in icmp.items():
        pkt, meta = packets[n - 1], metas[n - 1]
        if not pkt.haslayer(ICMP):
            continue
        layer = pkt[ICMP]
        from core.dissector import _icmp_checksum_ok, _icmp_timestamp      # 상세 트리에서 쓰는 것과 같은 함수
        data = payload_bytes(layer)
        found = _icmp_timestamp(data, float(pkt.time))
        rel = f"{round(float(pkt.time) - found[0] - found[1] / 1e6, 6):.9f}" if found else ""
        rest = len(data) - (found[2] if found else 0)
        mine = {
            "icmp.ident": str(layer.id), "icmp.seq": str(layer.seq), "icmp.seq_le": str(swap16(layer.seq)),
            "icmp.resp_in": str(meta.response_in + 1) if meta.response_in is not None and layer.type == 8 else "",
            "icmp.resp_to": str(meta.request_in + 1) if meta.request_in is not None and layer.type == 0 else "",
            "icmp.checksum.status": "1" if _icmp_checksum_ok(layer) else "0",
            "icmp.data_time_relative": rel, "data.len": str(rest) if rest else "",
        }
        total += 1
        bad = [f"{k}: 우리 {mine[k]!r} / Wireshark {w[k]!r}" for k in mine if mine[k] != w[k]]
        if w["icmp.resptime"] and meta.rtt is not None and abs(float(w["icmp.resptime"]) - meta.rtt * 1000) > 0.001:
            bad.append(f"응답 시간: 우리 {meta.rtt * 1000:.3f} / Wireshark {w['icmp.resptime']} ms")
        if bad:
            diff.append(f"#{n}: " + ", ".join(bad))
        else:
            ok += 1
    report.append(("ping 필드 (id, seq, 짝꿍, 응답 시간, 체크섬, 보낸 시각, Data 길이)", ok, total, diff))

    # ---- 3. DNS ----
    dns = tshark_fields(tshark, args.pcap, ["dns.id", "dns.response_in", "dns.response_to", "dns.time"], "dns")
    ok, total, diff = 0, 0, []
    for n, w in dns.items():
        pkt, meta = packets[n - 1], metas[n - 1]
        if not pkt.haslayer(DNS):
            continue
        total += 1
        mine = {"dns.id": f"0x{pkt[DNS].id:04x}",
                "dns.response_in": str(meta.response_in + 1) if meta.response_in is not None and meta.link_kind == "dns" else "",
                "dns.response_to": str(meta.request_in + 1) if meta.request_in is not None and meta.link_kind == "dns" else ""}
        bad = [f"{k}: 우리 {mine[k]!r} / Wireshark {w[k]!r}" for k in mine if mine[k] != w[k]]
        if w["dns.time"] and meta.rtt is not None and abs(float(w["dns.time"]) - meta.rtt) > 1e-6:
            bad.append(f"응답 시간: 우리 {meta.rtt:.9f} / Wireshark {w['dns.time']}")
        if bad:
            diff.append(f"#{n}: " + ", ".join(bad))
        else:
            ok += 1
    report.append(("DNS 필드 (ID, 짝꿍, 응답 시간)", ok, total, diff))

    # ---- 4. TCP ----
    tcp = tshark_fields(tshark, args.pcap, ["tcp.stream", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.len", "tcp.flags.ack"], "tcp")
    ok, total, diff = 0, 0, []
    for n, w in tcp.items():
        pkt, meta = packets[n - 1], metas[n - 1]
        if not pkt.haslayer(TCP) or meta.stream is None:
            continue
        total += 1
        layer = pkt[TCP]
        mine = {"tcp.seq": str(meta.rel_seq if meta.rel_seq is not None else layer.seq),
                "tcp.ack": str(meta.rel_ack if meta.rel_ack is not None else layer.ack) if "A" in str(layer.flags) else w["tcp.ack"],
                "tcp.window_size": str(meta.win_calc if meta.win_calc is not None else layer.window),
                "tcp.len": str(len(payload_bytes(layer))),
                "tcp.stream": str(meta.stream)}
        bad = [f"{k}: 우리 {mine[k]} / Wireshark {w[k]}" for k in mine if mine[k] != w[k]]
        if bad:
            diff.append(f"#{n}: " + ", ".join(bad))
        else:
            ok += 1
    report.append(("TCP 필드 (스트림, 상대 Seq/Ack, 창 크기, 길이)", ok, total, diff))

    # ---- 5. 표시 필터 ----
    for text in args.filter:
        w_frames = sorted(tshark_fields(tshark, args.pcap, [], text).keys())
        pred = parse_filter(text)
        o_frames = [i + 1 for i, (p, m) in enumerate(zip(packets, metas)) if pred is None or pred(p, m)]
        same = w_frames == o_frames
        detail = [] if same else [f"우리만: {sorted(set(o_frames) - set(w_frames))[:20]}",
                                  f"Wireshark만: {sorted(set(w_frames) - set(o_frames))[:20]}"]
        report.append((f"필터 {text!r} (걸린 패킷 {len(w_frames)}개)", int(same), 1, detail))

    # ---- 결과 ----
    print()
    all_ok = True
    for title, ok, total, diff in report:
        mark = "✅" if ok == total else "⚠️ "
        if not title.startswith("(참고)"):
            all_ok &= ok == total
        print(f"{mark} {title}: {ok}/{total} 같음")
        for line in diff[: args.show]:
            print("    " + line)
        if len(diff) > args.show:
            print(f"    ... 외 {len(diff) - args.show}개")
    print("\n결론:", "전부 Wireshark와 같아요 ((참고) 항목은 443 암호화 트래픽 재조립 차이)" if all_ok
          else "다른 부분이 있어요 (위 ⚠️ 참고)")


if __name__ == "__main__":
    main()
