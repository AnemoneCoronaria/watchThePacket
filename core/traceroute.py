from scapy.all import IP, UDP, ICMP

# traceroute 경로 뽑아내는 파일 (Qt 몰라도 됨). 그림은 gui/route_view.py 가 그림
#
# traceroute 원리
#   TTL=1 로 보내면 첫 번째 라우터가 "시간 초과(ICMP 11)"로 답함 -> 1번째 홉
#   TTL=2 로 보내면 두 번째 라우터가 답함 -> 2번째 홉 ... 이렇게 TTL을 하나씩 늘림
#   목적지에 닿으면 목적지가 "포트 닫힘(ICMP 3)" (UDP 방식) 이나 "ping 응답(ICMP 0)" (ICMP 방식)으로 답함
#
# build_routes(packets, metas) -> [경로, ...]   목적지마다 하나
#   경로 = {"src": 내 주소, "dst": 목적지, "reached": 도착했는지,
#           "hops": [{"ttl", "responders": [주소...], "rtts": [초...], "sent", "answered", "reached", "packets": [응답 패킷 번호...]}]}

TRACE_PORTS = range(33434, 33535)       # UDP traceroute가 쓰는 포트 (맥/리눅스 기본)


def _probe_kind(pkt):
    # traceroute 요청처럼 생겼으면 "udp" / "icmp", 아니면 None
    if not pkt.haslayer(IP):
        return None
    if pkt.haslayer(UDP) and pkt[UDP].dport in TRACE_PORTS:
        return "udp"
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt[IP].ttl <= 32:   # ping은 보통 TTL 64라 빠짐
        return "icmp"
    return None


def build_routes(packets, metas):
    probes = {}                         # 요청 패킷 번호 -> (내 주소, 목적지, TTL)
    for i, pkt in enumerate(packets):
        if _probe_kind(pkt):
            probes[i] = (pkt[IP].src, pkt[IP].dst, pkt[IP].ttl)

    # 목적지별로 "TTL -> 홉 정보" 모으기
    routes = {}
    for i, (src, dst, ttl) in probes.items():
        route = routes.setdefault((src, dst), {})
        hop = route.setdefault(ttl, {"ttl": ttl, "responders": [], "rtts": [], "sent": 0, "answered": 0,
                                     "reached": False, "packets": []})
        hop["sent"] += 1

        resp = metas[i].response_in
        if resp is None or metas[resp].link_kind not in ("traceroute", "icmp"):
            continue                    # 응답 없음 -> 화면에서 * 로
        rpkt = packets[resp]
        responder = rpkt[IP].src if rpkt.haslayer(IP) else "?"
        hop["answered"] += 1
        hop["rtts"].append(metas[resp].rtt)
        hop["packets"].append(resp)
        if responder not in hop["responders"]:
            hop["responders"].append(responder)
        # 목적지가 직접 답했으면 도착 (포트 닫힘 or ping 응답)
        if responder == dst or (rpkt.haslayer(ICMP) and rpkt[ICMP].type in (0, 3)):
            hop["reached"] = True

    result = []
    for (src, dst), hops in routes.items():
        # 응답이 하나도 없는 목적지(그냥 UDP 몇 개)는 traceroute가 아님
        if not any(h["answered"] for h in hops.values()):
            continue
        ordered = [hops[t] for t in sorted(hops)]
        # 도착한 다음 홉들은 traceroute가 이미 끝난 뒤라 잘라냄
        for n, hop in enumerate(ordered):
            if hop["reached"]:
                ordered = ordered[: n + 1]
                break
        result.append({"src": src, "dst": dst, "hops": ordered, "reached": ordered[-1]["reached"]})
    return result


def hop_text(hop):
    # 터미널 traceroute 출력이랑 비교하기 좋은 한 줄: "2  10.20.30.1  4.012 ms  3.998 ms  *"
    times = [f"{r * 1000:.3f} ms" for r in hop["rtts"]] + ["*"] * (hop["sent"] - hop["answered"])
    who = ", ".join(hop["responders"]) or "*"
    return f"{hop['ttl']:>2}  {who}  {'  '.join(times)}"


if __name__ == "__main__":
    # 실행: .venv/bin/python -m core.traceroute  (가짜 traceroute로 시험)
    from scapy.all import Ether, Raw
    from core.analyzer import Analyzer

    ME, DST = "192.168.0.123", "8.8.8.8"
    routers = {1: "192.168.0.1", 2: None, 3: "10.0.0.1"}    # 2번째 홉은 응답 안 함
    pk = []
    t = 0.0
    port = 33434
    for ttl in (1, 2, 3, 4):
        for _ in range(3):                                  # 홉마다 3번씩 (맥/리눅스 기본)
            probe = IP(src=ME, dst=DST, ttl=ttl) / UDP(sport=50000, dport=port) / Raw(b"\0" * 12)
            port += 1
            p = Ether(bytes(Ether() / probe)); t += 0.01; p.time = t; pk.append(p)
            if ttl == 4:
                reply = IP(src=DST, dst=ME) / ICMP(type=3, code=3) / bytes(probe)[:28]
            elif routers[ttl]:
                reply = IP(src=routers[ttl], dst=ME) / ICMP(type=11) / bytes(probe)[:28]
            else:
                continue
            r = Ether(bytes(Ether() / reply)); t += 0.002 * ttl; r.time = t; pk.append(r)

    an = Analyzer()
    metas = [an.add(p) for p in pk]
    for route in build_routes(pk, metas):
        print(f"{route['src']} -> {route['dst']}  도착: {route['reached']}")
        for hop in route["hops"]:
            print("  ", hop_text(hop))
