#!/usr/bin/env bash
# MiniWireShark 실행 스크립트 (Ubuntu / macOS)
#   ./run.sh
# 패킷 캡처는 관리자 권한이 필요해서 sudo로 실행함 (비밀번호 물어봄)
#
# Ubuntu 데스크톱은 root 프로그램이 내 화면에 창 띄우는 걸 막아둠
#   -> xhost 로 root한테 잠깐 허락해주고, 앱이 끝나면 다시 막음
cd "$(dirname "$0")"
PY="$PWD/.venv/bin/python"

if [ ! -x "$PY" ]; then
    echo "먼저 ./install.sh 를 실행하세요"
    exit 1
fi

# 화면 파일(ui_main.py, res_rc.py)이 없거나 main.ui / res.qrc 가 더 새 거면 다시 만들기 (sudo 전에, 내 권한으로)
if [ ! -f ui_main.py ] || [ main.ui -nt ui_main.py ]; then
    .venv/bin/pyside6-uic main.ui -o ui_main.py || exit 1
fi
if [ ! -f res_rc.py ] || [ res.qrc -nt res_rc.py ] || [ -n "$(find icons -newer res_rc.py 2>/dev/null)" ]; then
    .venv/bin/pyside6-rcc res.qrc -o res_rc.py || exit 1
fi

if [ "$(uname)" = "Linux" ]; then
    if [ -n "$DISPLAY" ] && command -v xhost >/dev/null 2>&1; then
        xhost +SI:localuser:root >/dev/null 2>&1
        trap 'xhost -SI:localuser:root >/dev/null 2>&1' EXIT
    fi
    # -E: 화면 정보(DISPLAY, WAYLAND_DISPLAY 등)를 root한테도 넘김
    #     (Wayland/X 중 뭘 쓸지는 Qt가 알아서 고름. 하나를 강제하면 그게 없는 환경에서 앱이 죽음)
    # PYTHONDONTWRITEBYTECODE: root가 프로젝트 폴더에 캐시 파일 안 만들게
    sudo -E env PYTHONDONTWRITEBYTECODE=1 "$PY" main.py "$@"
else
    sudo env PYTHONDONTWRITEBYTECODE=1 "$PY" main.py "$@"
fi
