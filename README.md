# 🦈 watchThePacket

**패킷을 직접 잡아서 보는 Wireshark 스타일 패킷 분석기** (앱 이름: MiniWireShark)

scapy로 패킷을 캡처하고 PySide6(Qt)로 보여준다.
`nslookup`, `curl`, `netstat`, `ping`, `traceroute`를 실행했을 때 **어떤 패킷이 오가는지**를
Wireshark처럼 목록 · 상세 트리 · 흐름도 · 경로 그림으로 확인할 수 있다.

> 2026-2학기 컴퓨터네트워크 팀 프로젝트 (주요 네트워크 명령어 ↔ 프로토콜 연계 분석)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-Qt%206-41CD52?logo=qt&logoColor=white)
![scapy](https://img.shields.io/badge/scapy-2.5%2B-orange)
![Platform](https://img.shields.io/badge/Ubuntu%2022.04%20%7C%2024.04%20%7C%20macOS-supported-lightgrey)

![메인 화면](docs/images/main.png)

---

## 목차

1. [빠른 시작](#빠른-시작)
2. [주요 기능](#주요-기능)
3. [화면 사용법](#화면-사용법)
4. [과제 실습 가이드 (명령어별)](#과제-실습-가이드-명령어별)
5. [표시 필터 문법](#표시-필터-문법)
6. [문제 해결](#문제-해결)
7. [확인한 환경](#확인한-환경)
8. [폴더 구조](#폴더-구조)
9. [개발자용](#개발자용)

---

## 빠른 시작

### Ubuntu (실습 환경, 22.04 / 24.04)

터미널(`Ctrl + Alt + T`)을 열고 한 줄씩 실행한다.

```bash
sudo apt update && sudo apt install -y git
```
```bash
git clone https://github.com/AnemoneCoronaria/watchThePacket.git
```
```bash
cd watchThePacket
```
```bash
./install.sh
```
```bash
./run.sh
```

- `install.sh`, `run.sh` 둘 다 sudo 비밀번호를 물어본다 (패키지 설치 / 패킷 캡처에 관리자 권한 필요)
- 설치는 처음 한 번만. 그다음부터는 `cd watchThePacket` 후 `./run.sh`만 하면 된다
- 최신 코드로 바꾸려면 `git pull`

### macOS

```bash
git clone https://github.com/AnemoneCoronaria/watchThePacket.git && cd watchThePacket
```
```bash
./install.sh
```
```bash
./run.sh
```

### 스크립트가 하는 일

| 스크립트 | 하는 일 |
|---|---|
| `install.sh` | (Ubuntu) Qt 창에 필요한 패키지 설치 → `.venv` 가상환경 만들고 `requirements.txt` 설치 |
| `run.sh` | (Ubuntu) root가 화면에 창을 띄울 수 있게 잠깐 허락(`xhost`) → `sudo -E`로 실행 → 끝나면 허락 취소 |

직접 하고 싶으면 [개발자용](#개발자용) 참고.

---

## 주요 기능

| 기능 | 설명 |
|---|---|
| 캡처 | 인터페이스 선택(기본 / 루프백 / IP 있는 것 전부), 시작 · 정지 · 재시작, pcap 저장 · 열기 |
| 패킷 목록 | No, Time, Source, Destination, Protocol, Length, Info + 프로토콜별 색 |
| Info 칸 | Wireshark처럼: 상대 Seq/Ack (`Seq=0`), TCP 플래그/옵션, DNS `Standard query 0x005c A ...`, HTTP 첫 줄, TLS 단계(SNI), ping `(reply in N)` |
| 상세 트리 | Frame / Ethernet II / IP / TCP·UDP / DNS·HTTP·TLS·ICMP·ARP. 플래그 비트 분해, DNS Queries/Answers(TTL), HTTP 헤더·본문 |
| 요청 ↔ 응답 | DNS `[Response In]` `[Time]`, HTTP `[Request in frame]`, ping `[Response time]` |
| TCP 연결 단계 | `[연결 단계: 연결 설정 (3-way handshake) 1/3: SYN]` / 데이터 송수신 / 연결 해제 |
| 흐름도 | 호스트별 세로선 + 화살표. TCP 연결 단계를 색칠. 필터 결과를 따라 바뀜 |
| 스트림 따라가기 | 표에서 우클릭 → Follow TCP/UDP Stream. 요청은 빨강, 응답은 파랑 (ASCII / UTF-8 / Hex) |
| traceroute 경로 | 내 PC → 라우터들 → 목적지를 그림으로. 응답 없는 홉, 여러 갈래 경로, 도착 여부 표시 |
| 표시 필터 | `udp && ip.addr==210.93.48.196`, `tcp.flags.syn==1`, `dns.qry.name contains "tukorea"` 등 |

| 흐름도 (3-way handshake → 데이터 → 연결 해제) | 스트림 따라가기 (HTTP) |
|---|---|
| ![흐름도](docs/images/flow.png) | ![스트림 따라가기](docs/images/follow.png) |

![traceroute 경로](docs/images/route.png)

---

## 화면 사용법

### 툴바 (왼쪽부터)

| 항목 | 설명 |
|---|---|
| 인터페이스 | 캡처할 네트워크. 처음엔 기본 인터페이스(Ubuntu VM은 보통 `enp0s3`)가 골라져 있음. 캡처 중엔 못 바꿈 |
| ▶ 시작 / ■ 정지 | 캡처 시작 / 멈춤. 창 제목에 `enp0s3에서 캡처 중 · 패킷 N개`가 나옴 |
| ↻ 재시작 | 표를 비우고 처음부터 |
| 💾 저장 / 📂 열기 | `.pcap` 파일 저장 / 불러오기 (Wireshark 파일도 열림) |
| 흐름도 | 지금 보이는 패킷(필터 결과)의 흐름도. 줄을 누르면 그 패킷이 선택됨 |
| 경로 | traceroute 경로 그림. 동그라미나 아래 표를 누르면 그 응답 패킷이 선택됨 |

### 그 밖에

- **필터 칸**: 쓰고 **Enter**. 지우면 필터 해제. 문법이 틀리면 빨개지고, 마우스를 올리면 이유가 나옴
- **표에서 우클릭**: TCP/UDP 스트림 따라가기, 이 연결만 흐름도, 필터 지우기
- **화살표 키**로 행을 옮겨도 상세 트리 / hex가 바뀜

---

## 과제 실습 가이드 (명령어별)

`./run.sh`로 켜고 **▶ 시작**을 누른 다음, 다른 터미널에서 명령어를 실행한다.

| 명령어 | 실행 예 | 필터 | 볼 것 |
|---|---|---|---|
| nslookup | `nslookup www.tukorea.ac.kr 210.93.48.196` | `udp && ip.addr==210.93.48.196` | 질의/응답 2개, 응답 상세의 Answers와 `[Request In]` `[Time]` |
| curl | `curl -v http://www.tukorea.ac.kr` | `tcp && ip.addr==210.93.48.59` | 흐름도: 3-way handshake → GET/307 → 연결 해제. 우클릭 → 스트림 따라가기 |
| netstat | curl 직후 `netstat -an \| grep 210.93.48.59` | `tcp.phase==teardown` | `TIME_WAIT` ↔ 흐름도에서 내 쪽이 마지막 ACK를 보낸 것 |
| ping | `ping -c 4 210.93.48.59` | `icmp` | request `(reply in N)`, reply 상세의 `[Response time]` |
| traceroute | `traceroute -q 2 8.8.8.8` | `(udp.dstport>=33434 && udp.dstport<=33534) \|\| icmp.type==11 \|\| icmp.type==3` | **경로** 버튼 그림, `Time-to-live exceeded` 상세의 `[traceroute 해석]` |

- curl의 IP는 출력 맨 위 `Trying 210.93.48.59:80...`에서 확인 (바뀔 수 있음)
- Ubuntu `nslookup`의 기본 서버 `127.0.0.53`은 루프백이라, 위처럼 서버를 지정하거나 인터페이스를 "IP 있는 것 전부"로 고른다
- traceroute를 `-m 8`처럼 홉 수를 제한하면 목적지 전에 끝나서 경로 그림이 "아직 안 닿음"으로 나온다 (정상)
- Ubuntu에 traceroute가 없으면: `sudo apt install -y traceroute`

---

## 표시 필터 문법

필터 칸에 쓰고 **Enter**.

| 종류 | 예시 |
|---|---|
| 프로토콜 | `tcp` `udp` `icmp` `icmpv6` `arp` `ip` `ipv6` `dns` `http` `tls` `stp` |
| 비교 | `==` `!=` `>` `<` `>=` `<=` (`eq` `ne` `gt` `lt` `ge` `le`도 됨), 글자는 `contains "..."` |
| 주소 | `ip.addr==210.93.48.196` `ip.src` `ip.dst` (`192.168.0.0/24` 대역 가능) `ipv6.addr` `eth.addr` |
| 포트 | `port 80` `tcp.port==443` `tcp.srcport` `tcp.dstport` `udp.port` `udp.dstport>=33434` |
| TCP | `tcp.flags.syn==1` `tcp.flags.ack` `tcp.flags.fin` `tcp.flags.reset` `tcp.flags.push` `tcp.len>0` `tcp.seq` `tcp.stream==0` |
| TCP 연결 단계 (전용) | `tcp.phase==handshake` `tcp.phase==data` `tcp.phase==teardown` |
| IP / ICMP | `ip.ttl==1` `ip.proto` `icmp.type==11` `icmp.code==3` `icmp.seq` |
| DNS / HTTP | `dns.qry.name contains "tukorea"` `dns.qry.type==28` `dns.a` `dns.flags.response==1` `http.request.method=="GET"` `http.host` `http.response.code==307` |
| 기타 | `frame.len>100` `frame.number<=50` `udp.stream` |
| BPF 느낌 | `host 1.1.1.1` `src 1.1.1.1` `dst 1.1.1.1` |
| 조합 | `and` `or` `not` `( )` 또는 `&&` `\|\|` `!` |

- 필드 이름만 쓰면 "그 필드가 있는 패킷" (`tcp.flags.syn` = TCP 전부). 값을 보려면 `==1`까지
- `!=`는 Wireshark처럼 "전부 아니어야" 참 (`ip.addr!=1.1.1.1` = 출발·도착 둘 다 1.1.1.1이 아님)
- 글자 비교는 대소문자 구분 안 함
- `http`, `tls`는 내용을 보고 판단해서, 연결 중간 조각은 `tcp`로만 보일 수 있음

---

## 문제 해결

| 증상 | 해결 |
|---|---|
| 시작하면 "관리자 권한이 필요해요" | `./run.sh`로 실행했는지 확인 (그냥 `python main.py`는 캡처 권한이 없음) |
| 창 제목에 "5초 넘게 패킷이 안 들어와요" | 인터페이스가 맞는지 확인. VM은 보통 `enp0s3`. 모르겠으면 "IP 있는 것 전부" |
| `could not connect to display` / `cannot open display` | 데스크톱 화면 안의 터미널에서 실행했는지 확인 (SSH 접속 터미널에서는 창이 안 뜸) |
| `Could not load the Qt platform plugin "xcb"` | `./install.sh`를 다시 실행 (Qt 창 패키지 설치) |
| `./run.sh: Permission denied` | `chmod +x install.sh run.sh` 후 다시 |
| `pip install` 중 `No matching distribution` | Python 3.10 미만 (Ubuntu 20.04 등). Ubuntu 22.04 이상 사용 |
| 끌 때 `Fatal Python error: none_dealloc` | 예전 `requirements.txt`로 설치함. `rm -rf .venv && ./install.sh` |

### sudo 없이 실행하고 싶을 때 (선택)

이 프로젝트 가상환경의 파이썬에만 캡처 권한을 주는 방법. 한 번 해두면 `sudo` 없이 실행된다.

```bash
rm -rf .venv && python3 -m venv --copies .venv && .venv/bin/pip install -r requirements.txt
```
```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
```
```bash
.venv/bin/python main.py
```

- `--copies`로 만들어야 시스템 파이썬이 아니라 이 폴더의 파이썬에만 권한이 붙는다
- `.venv`를 다시 만들면 `setcap`도 다시 해야 한다

---

## 확인한 환경

Docker 컨테이너 안에서 **Ubuntu 데스크톱(GNOME)과 같은 화면 관리자 mutter(Wayland + XWayland)** 를 띄우고, 일반 사용자 계정으로 이 README 순서대로 설치 → 실행 → 실제 캡처(ping, nslookup, curl, traceroute) → 흐름도 / 스트림 따라가기 / 경로 창까지 확인했다.

| 환경 | 설치된 PySide6 | `./install.sh` | `./run.sh` (Wayland) | `./run.sh` (X11) | sudo 없이 setcap |
|---|---|---|---|---|---|
| Ubuntu 22.04 ARM64 (맥북 VirtualBox와 같은 CPU) | 6.8.0.2 | ✅ | ✅ | ✅ | ✅ |
| Ubuntu 24.04 ARM64 | 6.12.0 | ✅ | ✅ | - | ✅ |
| Ubuntu 24.04 x86_64 (윈도우 PC VirtualBox와 같은 CPU) | 6.12.0 | ✅ | ✅ | - | ✅ |
| macOS (Apple Silicon) | 6.12.0 | ✅ | ✅ (`sudo`) | - | - |

✅ = 창이 화면에 뜨고, 실제 캡처(ICMP · DNS · TCP · HTTP · UDP)와 흐름도 · 스트림 따라가기 · 경로 그림까지 정상

- X11 = Wayland 없이 X 화면만 있는 경우 (VirtualBox에서 Ubuntu가 Xorg 세션으로 켜질 때와 같음)
- `run.sh`가 끝나면 root 화면 허락(`xhost`)이 다시 취소되고, root가 만든 파일이 프로젝트에 남지 않는 것도 확인
- sudo 없이 그냥 `python main.py`로 켜면 창은 뜨고, 캡처를 누르면 "관리자 권한이 필요해요" 안내가 나오는 것도 확인
- 실제 VirtualBox VM 화면에서 손으로 해 본 결과는 아님

---

## 폴더 구조

```
watchThePacket/
├── install.sh / run.sh   # 설치 / 실행 스크립트
├── main.py               # 진입점
├── main.ui / res.qrc     # Qt Designer 원본
├── ui_main.py, res_rc.py # 자동 생성 (직접 고치지 않음)
├── icons/                # 툴바 아이콘 (SVG)
├── docs/images/          # README 스크린샷
├── gui/
│   ├── main_window.py    # 창: 버튼, 표, 트리, hex 연결
│   ├── flow_graph.py     # 흐름도 창
│   ├── follow_stream.py  # 스트림 따라가기 창
│   └── route_view.py     # traceroute 경로 그림 창
└── core/                 # 화면을 모르는 로직 (터미널에서 테스트 가능)
    ├── sniffer.py        # scapy 캡처 + 시그널
    ├── interfaces.py     # 캡처할 인터페이스 목록
    ├── packet_parser.py  # 패킷 -> 표 한 줄 / Info / hex
    ├── analyzer.py       # 패킷 사이 관계: 스트림, 상대 Seq/Ack, 연결 단계, 요청-응답 짝꿍
    ├── dissector.py      # Wireshark식 상세 트리
    ├── flow.py           # 흐름도에 그릴 줄
    ├── stream.py         # 스트림 내용 모으기 / ASCII·Hex
    ├── traceroute.py     # traceroute 경로(홉) 뽑기
    ├── display_filter.py # 표시 필터 해석기
    └── pcap_io.py        # pcap 저장, 열기
```

---

## 개발자용

### 스크립트 없이 직접 설치 / 실행

```bash
# Ubuntu만: Qt 창에 필요한 패키지
sudo apt install -y python3-venv libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
    libxcb-render-util0 libxcb-shape0 libxcb-xkb1 libxkbcommon-x11-0 x11-xserver-utils

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 실행 (macOS)
sudo .venv/bin/python main.py
# 실행 (Ubuntu)
xhost +SI:localuser:root && sudo -E .venv/bin/python main.py
```

### 요구 사항

- Python 3.10 이상, PySide6-Essentials 6.5 이상, scapy 2.5 이상 ([requirements.txt](requirements.txt))
- 버전을 고정하지 않은 이유: 맥북(Apple Silicon) VirtualBox의 Ubuntu 22.04는 ARM64라 PySide6 6.8까지만 설치됨
- Python 3.10~3.11 + PySide6 6.12는 종료할 때 크래시가 나서 6.12 미만으로 설치되게 해 둠

### 화면(.ui) / 아이콘 수정 후

```bash
.venv/bin/pyside6-rcc res.qrc -o res_rc.py
.venv/bin/pyside6-uic main.ui -o ui_main.py
```

### 창 없이 로직만 테스트

```bash
.venv/bin/python -m core.packet_parser
.venv/bin/python -m core.display_filter
.venv/bin/python -m core.stream
.venv/bin/python -m core.traceroute
.venv/bin/python -m core.interfaces
```

---

## 주의

내가 관리하는 네트워크, 또는 허락받은 네트워크에서만 캡처한다.
