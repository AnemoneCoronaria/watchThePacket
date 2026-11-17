from PySide6.QtCore import Qt, Signal, QPointF, QRectF
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QFontMetrics, QPolygonF
from PySide6.QtWidgets import (QDialog, QWidget, QScrollArea, QVBoxLayout, QHBoxLayout, QComboBox,
                               QCheckBox, QPushButton, QLabel)

from core.flow import build_flow_rows, phase_groups, MAX_ROWS

# 흐름도 창 (Wireshark의 Statistics > Flow Graph 같은 것)
# 호스트마다 세로 점선, 패킷마다 화살표. TCP는 연결 단계(3-way handshake / 데이터 / 해제)를 색칠함
# 화살표 줄을 누르면 메인 창에서 그 패킷이 선택됨

PHASE_COLORS = {"handshake": "#ffd8c2", "data": "#dbeafe", "teardown": "#eadcff"}
PHASE_NAMES = {"handshake": "연결 설정\n(3-way\nhandshake)", "data": "데이터\n송수신", "teardown": "연결 해제"}


class FlowCanvas(QWidget):
    packetClicked = Signal(int)     # 누른 줄의 패킷 번호 (0부터)

    TIME_W, PHASE_W, SIDE, COL_W, COMMENT_W = 100, 90, 70, 240, 320
    ROW_H, HEAD_H = 30, 56

    def __init__(self):
        super().__init__()
        self.hosts, self.rows, self.groups = [], [], []
        self.show_phase = True
        self.selected = None
        self.font_main = QFont(self.font())
        self.font_main.setPointSize(11)
        self.font_small = QFont(self.font_main)
        self.font_small.setPointSize(9)
        self.font_bold = QFont(self.font_main)
        self.font_bold.setBold(True)

    def set_data(self, hosts, rows, groups):
        self.hosts, self.rows, self.groups = hosts, rows, groups
        self.selected = None
        width = self.host_x(max(len(hosts), 2) - 1) + self.SIDE + self.COMMENT_W
        height = self.HEAD_H + max(len(rows), 1) * self.ROW_H + 20
        self.setFixedSize(int(width), int(height))
        self.update()

    def host_x(self, i):
        return self.TIME_W + self.PHASE_W + self.SIDE + i * self.COL_W

    def comment_x(self):
        return self.host_x(max(len(self.hosts), 2) - 1) + self.SIDE

    # ---- 그리기 ----
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor("white"))        # 다크모드여도 그림은 흰 바탕 (보고서용)
        black, gray = QColor("#111827"), QColor("#6b7280")

        # 맨 위 제목줄
        p.setFont(self.font_bold)
        p.setPen(black)
        p.drawText(8, self.HEAD_H - 12, "Time")
        p.drawText(int(self.comment_x()) + 8, self.HEAD_H - 12, "Comment")
        fm = QFontMetrics(self.font_bold)
        for i, host in enumerate(self.hosts):
            text = fm.elidedText(str(host), Qt.ElideMiddle, self.COL_W - 12)
            p.drawText(QRectF(self.host_x(i) - self.COL_W / 2, 8, self.COL_W, 22), Qt.AlignCenter, text)

        if not self.rows:
            p.setFont(self.font_main)
            p.setPen(gray)
            p.drawText(QRectF(0, self.HEAD_H, self.width(), 40), Qt.AlignCenter, "그릴 패킷이 없어요")
            return

        # 연결 단계 색칠 (TCP)
        if self.show_phase:
            p.setFont(self.font_small)
            for first, last, phase in self.groups:
                top = self.HEAD_H + first * self.ROW_H
                rect = QRectF(self.TIME_W, top, self.comment_x() - self.TIME_W, (last - first + 1) * self.ROW_H)
                p.fillRect(rect, QColor(PHASE_COLORS[phase]))
                p.setPen(QColor("#9a3412") if phase == "handshake" else QColor("#1e3a8a") if phase == "data" else QColor("#5b21b6"))
                p.drawText(QRectF(self.TIME_W + 2, top, self.PHASE_W - 4, rect.height()), Qt.AlignCenter, PHASE_NAMES[phase])

        # 선택한 줄
        if self.selected is not None:
            p.fillRect(QRectF(0, self.HEAD_H + self.selected * self.ROW_H, self.width(), self.ROW_H), QColor("#fde68a"))

        # 호스트 세로 점선
        bottom = self.HEAD_H + len(self.rows) * self.ROW_H
        p.setPen(QPen(gray, 1, Qt.DashLine))
        for i in range(len(self.hosts)):
            x = self.host_x(i)
            p.drawLine(QPointF(x, self.HEAD_H - 4), QPointF(x, bottom))

        # 패킷 화살표
        fm_main, fm_small = QFontMetrics(self.font_main), QFontMetrics(self.font_small)
        for r, row in enumerate(self.rows):
            top = self.HEAD_H + r * self.ROW_H
            line_y = top + self.ROW_H - 9
            xs, xd = self.host_x(self.hosts.index(row["src"])), self.host_x(self.hosts.index(row["dst"]))

            p.setFont(self.font_small)
            p.setPen(black)
            p.drawText(QRectF(6, top, self.TIME_W - 8, self.ROW_H), Qt.AlignVCenter | Qt.AlignLeft, f"{row['time']:.6f}")

            # 화살표 몸통 + 머리
            p.setPen(QPen(black, 1.4))
            p.drawLine(QPointF(xs, line_y), QPointF(xd, line_y))
            direction = 1 if xd > xs else -1
            head = QPolygonF([QPointF(xd, line_y), QPointF(xd - 9 * direction, line_y - 4), QPointF(xd - 9 * direction, line_y + 4)])
            p.setBrush(black)
            p.drawPolygon(head)

            # 화살표 위 글자
            p.setFont(self.font_main)
            span = abs(xd - xs) - 16
            label = fm_main.elidedText(row["label"], Qt.ElideRight, int(max(span, 40)))
            p.drawText(QRectF(min(xs, xd) + 8, top + 1, abs(xd - xs) - 16, line_y - top - 2), Qt.AlignHCenter | Qt.AlignBottom, label)

            # 포트 번호 (각자 세로줄 바깥쪽에)
            p.setFont(self.font_small)
            p.setPen(gray)
            for x, port, outward in ((xs, row["sport"], -direction), (xd, row["dport"], direction)):
                if port == "":
                    continue
                text = str(port)
                w = fm_small.horizontalAdvance(text)
                tx = x + 5 if outward > 0 else x - 5 - w
                p.drawText(QPointF(tx, line_y + 4), text)

            # 오른쪽 설명
            p.setFont(self.font_small)
            p.setPen(black)
            comment = fm_small.elidedText(row["comment"], Qt.ElideRight, self.COMMENT_W - 12)
            p.drawText(QRectF(self.comment_x() + 8, top, self.COMMENT_W - 12, self.ROW_H), Qt.AlignVCenter | Qt.AlignLeft, comment)

    def mousePressEvent(self, event):
        r = int((event.position().y() - self.HEAD_H) // self.ROW_H)
        if 0 <= r < len(self.rows):
            self.selected = r
            self.update()
            self.packetClicked.emit(self.rows[r]["index"])


class FlowGraphDialog(QDialog):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main = main_window
        self.setWindowTitle("흐름도 (Flow Graph)")
        self.resize(1150, 620)

        # 위쪽 버튼 줄
        self.scope = QComboBox()
        self.scope.addItems(["표시된 패킷 (필터 결과)", "선택한 패킷의 연결(스트림)만"])
        self.phase_box = QCheckBox("TCP 연결 단계 색칠")
        self.phase_box.setChecked(True)
        refresh = QPushButton("새로고침")
        self.status = QLabel()

        bar = QHBoxLayout()
        bar.addWidget(QLabel("범위:"))
        bar.addWidget(self.scope)
        bar.addWidget(self.phase_box)
        bar.addWidget(refresh)
        bar.addStretch()
        bar.addWidget(self.status)

        self.canvas = FlowCanvas()
        scroll = QScrollArea()
        scroll.setWidget(self.canvas)
        scroll.setStyleSheet("QScrollArea { background: white; }")

        layout = QVBoxLayout(self)
        layout.addLayout(bar)
        layout.addWidget(scroll)

        self.scope.currentIndexChanged.connect(self.refresh)
        self.phase_box.toggled.connect(self.toggle_phase)
        refresh.clicked.connect(self.refresh)
        self.canvas.packetClicked.connect(self.main.select_packet)

    def refresh(self):
        indices, problem = self.main.flow_indices(stream_only=self.scope.currentIndex() == 1)
        hosts, rows = build_flow_rows(indices, self.main.packets, self.main.analyzer.metas, self.main.t0 or 0)
        self.canvas.set_data(hosts, rows, phase_groups(rows))
        text = problem or f"패킷 {len(rows)}개, 호스트 {len(hosts)}개"
        if len(indices) > MAX_ROWS:
            text += f" (앞 {MAX_ROWS}개만 그림)"
        self.status.setText(text)

    def toggle_phase(self, on):
        self.canvas.show_phase = on
        self.canvas.update()
