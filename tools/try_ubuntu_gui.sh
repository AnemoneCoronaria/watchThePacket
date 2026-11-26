#!/usr/bin/env bash
# 맥(OrbStack / Docker Desktop)에서 우분투 데스크톱을 띄워서 GUI로 직접 시험하기
#
#   tools/try_ubuntu_gui.sh          # Ubuntu 22.04 (실습 환경과 같음)
#   tools/try_ubuntu_gui.sh 24.04    # Ubuntu 24.04
#   tools/try_ubuntu_gui.sh stop     # 컨테이너 지우기
#
# 접속: Finder -> 이동 -> 서버에 연결 (⌘K) -> vnc://localhost:5901   비밀번호: watch123
#       (맥 기본 "화면 공유" 앱이 열림)
# 그 안에서: 아래쪽 독의 터미널 아이콘 -> cd ~/watchThePacket -> ./install.sh -> ./run.sh
#
# 하는 일
#   1. ubuntu 컨테이너 하나 만들기 (이름: watchthepacket-gui)
#   2. 가벼운 데스크톱(Xfce) + VNC 서버 + 한글 글꼴 + ping/traceroute/curl/nslookup 설치
#   3. 지금 프로젝트 폴더를 컨테이너 안 ~/watchThePacket 으로 복사 (맥의 .venv 는 빼고)
#      -> 코드를 고쳤으면 이 스크립트를 다시 실행하면 새로 복사됨
set -e
cd "$(dirname "$0")/.."
NAME=watchthepacket-gui
PORT=5901
PASS=watch123

if [ "$1" = "stop" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "지웠어요: $NAME" || echo "없어요: $NAME"
    exit 0
fi
VER="${1:-22.04}"

echo "==> [1/4] Ubuntu $VER 컨테이너 만들기"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname ubuntu-$VER -p 127.0.0.1:$PORT:5900 \
    -e DEBIAN_FRONTEND=noninteractive -e TZ=Asia/Seoul ubuntu:$VER sleep infinity >/dev/null

echo "==> [2/4] 데스크톱 · VNC · 명령어 설치 (처음엔 몇 분 걸려요)"
docker exec "$NAME" bash -c '
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends \
    xvfb x11vnc xfce4 xfce4-terminal dbus-x11 fonts-noto-cjk fonts-dejavu \
    sudo git ca-certificates python3-venv \
    iputils-ping traceroute curl dnsutils net-tools >/dev/null 2>&1
'

echo "==> [3/4] 프로젝트 복사 (~/watchThePacket)"
COPYFILE_DISABLE=1 tar --no-xattrs --no-fflags --exclude=.venv --exclude='.venv-*' --exclude=__pycache__ --exclude=ui_main.py --exclude=res_rc.py -cf - . \
    | docker exec -i "$NAME" bash -c 'mkdir -p /root/watchThePacket && tar -C /root/watchThePacket -xf -'

echo "==> [4/4] 데스크톱 + VNC 서버 켜기"
docker exec -d "$NAME" bash -c "
  Xvfb :1 -screen 0 1600x1000x24 >/tmp/xvfb.log 2>&1 &
  sleep 1
  DISPLAY=:1 dbus-launch startxfce4 >/tmp/xfce.log 2>&1 &
  x11vnc -display :1 -forever -shared -passwd $PASS -rfbport 5900 >/tmp/vnc.log 2>&1
"
sleep 3

echo
echo "준비 끝! 맥에서 접속:  Finder -> 이동 -> 서버에 연결(⌘K) -> vnc://localhost:$PORT   (비밀번호 $PASS)"
echo "우분투 화면 안의 터미널에서:  cd ~/watchThePacket && ./install.sh && ./run.sh"
echo "다 쓰면:  tools/try_ubuntu_gui.sh stop"
