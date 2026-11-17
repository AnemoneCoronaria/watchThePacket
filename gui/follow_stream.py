from PySide6.QtGui import QTextCursor, QTextCharFormat, QColor, QFontDatabase
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QSpinBox,
                               QTextEdit, QPushButton)

from core.stream import collect_stream, render

# 스트림 따라가기 창 (Wireshark의 Follow TCP/UDP Stream)
# 같은 연결의 내용을 이어서 보여줌. 클라이언트 -> 서버는 빨강, 서버 -> 클라이언트는 파랑
# 열면 메인 창 필터도 tcp.stream==N 으로 바뀜 (Wireshark처럼)

COLORS = {0: ("#a40000", "#fbeded"), 1: ("#00007f", "#ededfb")}    # (글자색, 배경색)
MAX_CHARS = 1_000_000                                                # 너무 길면 앞부분만


class FollowStreamDialog(QDialog):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main = main_window
        self.proto = "tcp"
        self.resize(900, 620)

        self.who = QLabel()
        self.direction = QComboBox()
        self.mode = QComboBox()
        self.mode.addItems(["ASCII", "UTF-8", "Hex Dump"])
        self.stream_box = QSpinBox()
        self.stream_box.setPrefix("스트림 ")

        top = QHBoxLayout()
        top.addWidget(self.who)
        top.addStretch()
        top.addWidget(QLabel("보기:"))
        top.addWidget(self.direction)
        top.addWidget(self.mode)
        top.addWidget(self.stream_box)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QTextEdit.NoWrap)
        mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        mono.setPointSize(12)
        self.text.setFont(mono)
        self.text.setStyleSheet("QTextEdit { background: white; color: black; }")   # 다크모드여도 흰 바탕

        self.status = QLabel()
        close = QPushButton("닫기")
        bottom = QHBoxLayout()
        bottom.addWidget(self.status)
        bottom.addStretch()
        bottom.addWidget(close)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.text)
        layout.addLayout(bottom)

        self.direction.currentIndexChanged.connect(self.redraw)
        self.mode.currentIndexChanged.connect(self.redraw)
        self.stream_box.valueChanged.connect(self.on_stream_changed)
        close.clicked.connect(self.close)

    # 메인 창에서 부름: 이 스트림 보여줘
    def show_stream(self, proto, stream_id):
        self.proto = proto
        self.stream_box.blockSignals(True)      # 숫자 바꾸는 중에 on_stream_changed 안 불리게
        self.stream_box.setRange(0, max(self.main.analyzer.stream_count(proto) - 1, 0))
        self.stream_box.setValue(stream_id)
        self.stream_box.blockSignals(False)
        self.load()

    def on_stream_changed(self, value):
        self.load()

    def load(self):
        stream_id = self.stream_box.value()
        self.setWindowTitle(f"Follow {self.proto.upper()} Stream ({self.proto}.stream eq {stream_id})")
        self.main.set_filter(f"{self.proto}.stream=={stream_id}")      # 표에서도 이 스트림만

        self.data = collect_stream(self.proto, stream_id, self.main.packets, self.main.analyzer.metas)
        c, s = self.data["client"], self.data["server"]
        if c is None:
            self.who.setText("이 스트림에 패킷이 없어요")
            self.text.clear()
            self.status.clear()
            return

        a, b = f"{c[0]}:{c[1]}", f"{s[0]}:{s[1]}"
        self.who.setText(f"{a}  ⇄  {b}")
        keep = self.direction.currentIndex()
        self.direction.blockSignals(True)
        self.direction.clear()
        self.direction.addItems([f"전체 대화 ({sum(self.data['bytes'])} bytes)",
                                 f"{a} → {b} ({self.data['bytes'][0]} bytes)",
                                 f"{b} → {a} ({self.data['bytes'][1]} bytes)"])
        self.direction.setCurrentIndex(max(keep, 0))
        self.direction.blockSignals(False)
        self.status.setText(f"패킷 {self.data['packets']}개 · 클라이언트(빨강) {self.data['bytes'][0]} bytes · "
                            f"서버(파랑) {self.data['bytes'][1]} bytes")
        self.redraw()

    def redraw(self):
        if not getattr(self, "data", None) or self.data["client"] is None:
            return
        mode = {0: "ascii", 1: "utf8", 2: "hex"}[self.mode.currentIndex()]
        only = {0: None, 1: 0, 2: 1}[max(self.direction.currentIndex(), 0)]

        self.text.clear()
        cursor = self.text.textCursor()
        written = 0
        for direction, text in render(self.data["chunks"], mode, only):
            if written + len(text) > MAX_CHARS:
                text = text[: MAX_CHARS - written] + "\n... (너무 길어서 여기까지만)\n"
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(COLORS[direction][0]))
            fmt.setBackground(QColor(COLORS[direction][1]))
            cursor.insertText(text, fmt)
            written += len(text)
            if written >= MAX_CHARS:
                break
        if not self.data["chunks"]:
            cursor.insertText("(실어 나른 내용이 없어요. SYN/ACK 같은 제어 패킷만 있는 스트림)")
        self.text.moveCursor(QTextCursor.Start)
