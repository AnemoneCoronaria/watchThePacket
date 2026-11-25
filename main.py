import sys
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

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
