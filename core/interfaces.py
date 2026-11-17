from scapy.all import conf, get_if_list

# 캡처할 네트워크 인터페이스 목록 만드는 파일 (Qt 몰라도 됨)
#
# list_interfaces() -> [{"label": 화면 글자, "value": sniffer에 넘길 값}, ...]
#   value = "en0" 같은 이름 하나, 또는 ["en0", "lo0"] 같은 이름 리스트(여러 개 동시에)
#   순서: 기본 인터페이스(무조건 맨 위) -> IP 있는 것 -> "IP 있는 것 전부" -> IP 없는 것(켜져 있는 것만)
#   맥은 utun, awdl 같은 안 쓰는 애들이 많아서 IP 없는 건 맨 뒤로 보냄
#
# 주의: 기본 인터페이스는 IP를 못 읽어도 맨 위에 둠
#       (sudo로 켜면 IP를 못 읽는 경우가 있는데, 그러면 anpi0 같은 엉뚱한 게 맨 위로 와서 아무것도 안 잡혔음)


def _is_up(iface):
    flags = getattr(iface, "flags", None)
    if flags is None:                           # flags 정보 자체가 없는 환경이면 그냥 켜진 걸로
        return True
    return "UP" in str(flags)


def _is_loopback(iface):
    return "LOOPBACK" in str(getattr(iface, "flags", "")) or iface.name in ("lo", "lo0")


def default_iface():
    # scapy가 정한 기본 인터페이스 이름 (인터넷 나가는 쪽, 보통 en0 / enp0s3)
    return conf.iface.name if hasattr(conf.iface, "name") else str(conf.iface)


def list_interfaces():
    default = default_iface()
    try:
        ifaces = [i for i in conf.ifaces.values() if _is_up(i) or i.name == default]
    except Exception:
        # 혹시 위가 안 되는 환경이면 이름만이라도 (기본 먼저)
        names = get_if_list()
        names.sort(key=lambda n: n != default)
        return [{"label": n + ("  (기본)" if n == default else ""), "value": n} for n in names]

    items = []
    first = next((i for i in ifaces if i.name == default), None)
    label = f"{default} · {first.ip}" if first is not None and first.ip else default
    items.append({"label": f"{label}  (기본)", "value": default})

    others = [i for i in ifaces if i.name != default]
    with_ip = sorted([i for i in others if i.ip], key=lambda i: (_is_loopback(i), i.name))
    without_ip = sorted([i for i in others if not i.ip], key=lambda i: i.name)

    for i in with_ip:
        items.append({"label": f"{i.name} · {i.ip}" + ("  (루프백)" if _is_loopback(i) else ""), "value": i.name})

    if with_ip:
        names = [default] + [i.name for i in with_ip]
        items.append({"label": f"IP 있는 것 전부 ({', '.join(names)})", "value": names})

    for i in without_ip:
        items.append({"label": f"{i.name}  (IP 없음)", "value": i.name})
    return items


if __name__ == "__main__":
    # 실행: .venv/bin/python -m core.interfaces   (sudo 붙여서도 한 번 해보기)
    print("기본 인터페이스:", default_iface())
    for item in list_interfaces():
        print(f"{item['label']:45} -> {item['value']}")
