import signal
import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

try:
    from gui.main_window import MainWindow
except ModuleNotFoundError as e:
    # ui_main.py / res_rc.py 는 main.ui, res.qrc 에서 만드는 파일이라 저장소에 없음
    if e.name in ("ui_main", "res_rc"):
        sys.exit("화면 파일이 아직 없어요. ./install.sh (또는 ./run.sh) 로 실행해 주세요.")
    raise


def main():
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    # 터미널에서 Ctrl+C 눌러도 안 꺼지던 문제
    #   Qt가 돌고 있는 동안엔 파이썬이 Ctrl+C를 확인할 틈이 없어서 그냥 무시됨
    #   -> Ctrl+C(또는 kill) 오면 창 X 누른 거랑 똑같이 닫기
    #   -> 0.2초마다 타이머로 파이썬한테 잠깐씩 차례를 줘야 이걸 알아챔
    signal.signal(signal.SIGINT, lambda *_: window.close())
    signal.signal(signal.SIGTERM, lambda *_: window.close())
    wake = QTimer()
    wake.timeout.connect(lambda: None)
    wake.start(200)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
