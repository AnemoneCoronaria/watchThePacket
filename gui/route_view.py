from PySide6.QtCore import Qt, Signal, QPointF, QRectF
from PySide6.QtGui import QPainter, QPen, QColor, QFont, QFontMetrics, QPolygonF, QBrush
from PySide6.QtWidgets import (QDialog, QWidget, QScrollArea, QVBoxLayout, QHBoxLayout, QComboBox,
                               QPushButton, QLabel, QTableWidget, QTableWidgetItem, QSplitter, QAbstractItemView)

from core.traceroute import build_routes

# traceroute 경로 그림 창
# 내 PC -> 1번째 라우터 -> 2번째 라우터 -> ... -> 목적지 를 동그라미 + 화살표로 그림
#   파랑 = 내 PC, 청록 = 응답한 라우터, 회색 점선 = 응답 없음(*), 초록 = 목적지 도착 / 주황 = 아직 도착 못함
# 동그라미를 누르면 메인 창에서 그 홉의 응답 패킷이 선택됨
# 홉이 많으면 한 줄에 PER_ROW개씩 지그재그로 (2번째 줄은 오른쪽 -> 왼쪽)

COLORS = {"me": "#2563eb", "router": "#0d9488", "silent": "#9ca3af", "reached": "#16a34a", "notyet": "#ea580c"}


class RouteCanvas(QWidget):
    hopClicked = Signal(int)            # 누른 홉의 응답 패킷 번호 (0부터)

    PER_ROW, COL_W, ROW_H, R, MARGIN = 6, 175, 150, 26, 40

    def __init__(self):
        super().__init__()
        self.route = None
        self.nodes = []                 # [(중심 x, y, 종류, 위 글자, 아래 글자들, 패킷 번호)]
        self.font_main = QFont(self.font())
        self.font_main.setPointSize(11)
        self.font_bold = QFont(self.font_main)
        self.font_bold.setBold(True)
        self.font_small = QFont(self.font_main)
        self.font_small.setPointSize(10)

    def set_route(self, route):
        self.route = route
        self.nodes = []
        if route:
            # 첫 노드 = 내 PC
            items = [("me", "출발 (내 PC)", [route["src"]], None, "PC")]
            for hop in route["hops"]:
                if not hop["answered"]:
                    items.append(("silent", f"{hop['ttl']}번째 홉", ["* * *", "응답 없음"], None, str(hop["ttl"])))
                    continue
                avg = sum(hop["rtts"]) / len(hop["rtts"]) * 1000
                who = hop["responders"][0] + (f" 외 {len(hop['responders']) - 1}개" if len(hop["responders"]) > 1 else "")
                kind = "reached" if hop["reached"] else "router"
                title = f"{hop['ttl']}번째 홉" + (" = 목적지" if hop["reached"] else "")
                lines = [who, f"평균 {avg:.2f} ms", f"응답 {hop['answered']}/{hop['sent']}"]
                items.append((kind, title, lines, hop["packets"][0], str(hop["ttl"])))
            if not route["reached"]:    # 아직 목적지까지 못 갔으면 목적지를 따로 흐리게
                last_ttl = route["hops"][-1]["ttl"]
                items.append(("notyet", "목적지 (아직 안 닿음)",
                              [route["dst"], f"TTL {last_ttl}까지만 보내서", "여기까지 못 감 (-m 늘려 보기)"], None, "?"))

            for n, (kind, title, lines, packet, mark) in enumerate(items):
                row, col = divmod(n, self.PER_ROW)
                if row % 2 == 1:        # 지그재그: 홀수 줄은 오른쪽부터
                    col = self.PER_ROW - 1 - col
                x = self.MARGIN + 60 + col * self.COL_W
                y = self.MARGIN + 30 + row * self.ROW_H
                self.nodes.append((x, y, kind, title, lines, packet, mark))

        rows = (len(self.nodes) - 1) // self.PER_ROW + 1 if self.nodes else 1
        self.setFixedSize(self.MARGIN * 2 + 120 + (self.PER_ROW - 1) * self.COL_W, self.MARGIN * 2 + rows * self.ROW_H)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor("white"))        # 다크모드여도 흰 바탕
        if not self.nodes:
            p.setPen(QColor("#6b7280"))
            p.setFont(self.font_main)
            p.drawText(self.rect(), Qt.AlignCenter, "traceroute 패킷이 없어요\n(캡처 중에 traceroute 명령을 실행해 보세요)")
            return

        # 화살표 먼저 (동그라미가 위에 오게)
        for (x1, y1, *_), (x2, y2, kind2, *_) in zip(self.nodes, self.nodes[1:]):
            dashed = kind2 in ("silent", "notyet")
            p.setPen(QPen(QColor("#374151"), 2, Qt.DashLine if dashed else Qt.SolidLine))
            if y1 == y2:                # 같은 줄: 옆으로
                d = 1 if x2 > x1 else -1
                start, end = QPointF(x1 + d * self.R, y1), QPointF(x2 - d * self.R, y2)
            else:                       # 줄 바뀜: 아래로
                start, end = QPointF(x1, y1 + self.R + 52), QPointF(x2, y2 - self.R - 22)
            p.drawLine(start, end)
            direction = end - start
            length = max((direction.x() ** 2 + direction.y() ** 2) ** 0.5, 1)
            ux, uy = direction.x() / length, direction.y() / length
            head = QPolygonF([end, QPointF(end.x() - 10 * ux + 5 * uy, end.y() - 10 * uy - 5 * ux),
                              QPointF(end.x() - 10 * ux - 5 * uy, end.y() - 10 * uy + 5 * ux)])
            p.setBrush(QColor("#374151"))
            p.setPen(Qt.NoPen)
            p.drawPolygon(head)

        fm = QFontMetrics(self.font_small)
        for x, y, kind, title, lines, packet, mark in self.nodes:
            color = QColor(COLORS[kind])
            # 동그라미
            if kind == "silent":
                p.setBrush(QColor("#f3f4f6"))
                p.setPen(QPen(color, 2, Qt.DashLine))
            else:
                p.setBrush(QBrush(color))
                p.setPen(QPen(color.darker(130), 2))
            p.drawEllipse(QPointF(x, y), self.R, self.R)
            p.setPen(QColor("#6b7280") if kind == "silent" else QColor("white"))
            p.setFont(self.font_bold)
            p.drawText(QRectF(x - self.R, y - self.R, 2 * self.R, 2 * self.R), Qt.AlignCenter, mark)

            # 위: 제목 / 아래: 주소, 시간
            p.setPen(QColor("#111827"))
            p.setFont(self.font_bold)
            p.drawText(QRectF(x - self.COL_W / 2, y - self.R - 22, self.COL_W, 18), Qt.AlignCenter, title)
            p.setFont(self.font_small)
            for k, line in enumerate(lines):
                p.setPen(QColor("#111827") if k == 0 else QColor("#4b5563"))
                text = fm.elidedText(line, Qt.ElideMiddle, self.COL_W - 10)
                p.drawText(QRectF(x - self.COL_W / 2, y + self.R + 4 + k * 16, self.COL_W, 16), Qt.AlignCenter, text)

    def mousePressEvent(self, event):
        pos = event.position()
        for x, y, kind, title, lines, packet, mark in self.nodes:
            if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= (self.R + 4) ** 2 and packet is not None:
                self.hopClicked.emit(packet)
                return


class RouteDialog(QDialog):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main = main_window
        self.routes = []
        self.setWindowTitle("traceroute 경로")
        self.resize(1180, 680)

        self.target = QComboBox()
        refresh = QPushButton("새로고침")
        self.status = QLabel()
        bar = QHBoxLayout()
        bar.addWidget(QLabel("목적지:"))
        bar.addWidget(self.target, 1)
        bar.addWidget(refresh)
        bar.addWidget(self.status)

        self.canvas = RouteCanvas()
        scroll = QScrollArea()
        scroll.setWidget(self.canvas)
        scroll.setStyleSheet("QScrollArea { background: white; }")

        # 아래 표: 터미널 traceroute 출력이랑 비교용
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["홉(TTL)", "응답한 라우터", "응답 시간", "응답 패킷 번호"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 260)
        self.table.setColumnWidth(2, 330)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)

        split = QSplitter(Qt.Vertical)
        split.addWidget(scroll)
        split.addWidget(self.table)
        split.setSizes([450, 200])

        layout = QVBoxLayout(self)
        layout.addLayout(bar)
        layout.addWidget(split)

        refresh.clicked.connect(self.refresh)
        self.target.currentIndexChanged.connect(self.show_route)
        self.canvas.hopClicked.connect(self.main.select_packet)
        self.table.cellClicked.connect(self.on_table_click)

    def refresh(self):
        keep = self.target.currentText()
        self.routes = build_routes(self.main.packets, self.main.analyzer.metas)
        self.target.blockSignals(True)
        self.target.clear()
        for r in self.routes:
            mark = "목적지 도착" if r["reached"] else f"TTL {r['hops'][-1]['ttl']}까지 목적지 안 닿음"
            self.target.addItem(f"{r['src']} → {r['dst']}  ({len(r['hops'])}홉, {mark})")
        if keep and self.target.findText(keep) >= 0:
            self.target.setCurrentIndex(self.target.findText(keep))
        self.target.blockSignals(False)
        self.status.setText(f"traceroute {len(self.routes)}개" if self.routes else "")
        self.show_route()

    def show_route(self):
        idx = self.target.currentIndex()
        route = self.routes[idx] if 0 <= idx < len(self.routes) else None
        self.canvas.set_route(route)

        self.table.setRowCount(0)
        for hop in (route["hops"] if route else []):
            row = self.table.rowCount()
            self.table.insertRow(row)
            times = [f"{r * 1000:.3f} ms" for r in hop["rtts"]] + ["*"] * (hop["sent"] - hop["answered"])
            values = [str(hop["ttl"]), ", ".join(hop["responders"]) or "* (응답 없음)",
                      "  ".join(times), ", ".join(str(n + 1) for n in hop["packets"])]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))

    def on_table_click(self, row, col):
        route = self.routes[self.target.currentIndex()]
        hop = route["hops"][row]
        if hop["packets"]:
            self.main.select_packet(hop["packets"][0])
