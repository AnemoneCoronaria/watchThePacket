#!/usr/bin/env bash
# MiniWireShark 설치 스크립트 (Ubuntu / macOS)
#   ./install.sh
# 하는 일
#   1. (Ubuntu만) Qt 창 띄우는 데 필요한 패키지 설치  <- sudo 비밀번호 물어봄
#   2. .venv 가상환경 만들고 requirements.txt 설치
set -e
cd "$(dirname "$0")"

if [ "$(uname)" = "Linux" ]; then
    echo "==> [1/2] 우분투 패키지 설치 (sudo 비밀번호를 물어볼 수 있어요)"
    sudo apt-get update
    sudo apt-get install -y python3-venv \
        libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 \
        libxcb-shape0 libxcb-xkb1 libxkbcommon-x11-0 x11-xserver-utils
else
    echo "==> [1/2] macOS: 따로 설치할 패키지 없음"
fi

echo "==> [2/2] 파이썬 가상환경(.venv) + 패키지 설치"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo
echo "설치 끝! 실행은:  ./run.sh"
