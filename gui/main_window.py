from PySide6.QtWidgets import QWidget

from ui_main import Ui_MiniWireShark
from PySide6.QtWidgets import QAbstractItemView
from PySide6.QtGui import QFont, QBrush, QColor, QFontDatabase
from PySide6.QtCore import Qt, Slot, QTimer
import time
from PySide6.QtWidgets import QTableWidgetItem, QTreeWidgetItem, QFileDialog, QMessageBox, QPlainTextEdit, QMenu

from core.sniffer import Sniffer
from core.packet_parser import summarize, hex_dump
from core.pcap_io import save_pcap, load_pcap
from core.display_filter import parse_filter
from core.analyzer import Analyzer
from core.dissector import build_tree
from core.interfaces import list_interfaces
from gui.flow_graph import FlowGraphDialog
from gui.follow_stream import FollowStreamDialog
from gui.route_view import RouteDialog


# 프로토콜별 행 배경색 (Wireshark 느낌으로)
# 글자는 검정으로 고정해서 다크모드에서도 보이게 함 (add_row 참고)
PROTO_COLORS = {
    "TCP":    "#e7e6ff",   # 연보라
    "TLS":    "#d9d6ff",   # 조금 진한 보라
    "HTTP":   "#e4ffc7",   # 연두
    "UDP":    "#daeeff",   # 연하늘
    "DNS":    "#cfe6ff",   # 조금 진한 하늘
    "ICMP":   "#fce0ff",   # 연분홍
    "ICMPv6": "#fce0ff",   # 연분홍
    "ARP":    "#faf0d7",   # 연노랑
    "IPv6":   "#e0f5e0",   # 연초록
    "IP":     "#eeeeee",   # 연회색
    "STP":    "#e0e0e0",   # 회색
    "Other":  "#e0e0e0",   # 회색
}


# 진짜 창 클래스. 버튼이랑 표 연결하는 곳
#
# 해야 할 것 (쉬운 순)
#  1. 재시작 누르면 표 비우기 (완료)
#  2. 새 패킷 오면 표 맨 아래로 스크롤 (완료)
#  3. 표에서 행 클릭하면 hex 뷰 채우기 (완료) / 상세 트리 (build_detail 완료, 트리 위젯에 넣는 것만 남음)
#  4. 저장 / 열기 (완료)
#  5. 필터 입력창 연결 + 에러 처리 + 행 색 (완료)
#  6. 표시 필터: 필터 칸에 쓰고 Enter 치면 맞는 행만 보임 (완료)
#  7. Info 칸 읽기 좋게 (완료)
#  8. 상세 트리 Wireshark처럼 + 상대 Seq/Ack + 요청/응답 짝꿍 (완료, core/analyzer.py + core/dissector.py)
#  9. 흐름도(Flow Graph) 버튼 (완료, gui/flow_graph.py)
# 10. 인터페이스 선택 (완료, core/interfaces.py) / 스트림 따라가기: 표에서 우클릭 (완료, gui/follow_stream.py)
# 11. traceroute 경로 그림 버튼 (완료, core/traceroute.py + gui/route_view.py)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        # Designer로 만든 화면을 이 창(self)에 붙인다
        self.ui = Ui_MiniWireShark()
        self.ui.setupUi(self)
        
        self.count = 0      # 패킷 번호
        self.t0 = None      # 첫 패킷의 시간 (아직 모름)
        self.packets = []   # 잡은 패킷 보관 (행 번호 == 이 리스트의 인덱스)
        self.display_pred = None    # 표시 필터 (None이면 다 보여줌)
        self.analyzer = Analyzer()  # 패킷 사이 관계 (상대 Seq, 짝꿍, 연결 단계)
        self.flow_dialog = None     # 흐름도 창 (한 번 만들면 계속 씀)
        self.follow_dialog = None   # 스트림 따라가기 창 (이것도)
        self.route_dialog = None    # traceroute 경로 창 (이것도)

        # 캡처 상태를 창 제목에 보여주기 (0.5초마다)
        self.capture_name = ""      # 지금 캡처 중인 인터페이스 이름
        self.capture_since = 0.0    # 캡처 시작한 시각
        self.capture_start_count = 0
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.update_status)

        self.sniffer = Sniffer()
        self.sniffer.packet_captured.connect(self.on_packet)
        self.sniffer.error_occurred.connect(self.on_sniffer_error)

        self.init_ui()        # 화면 초기 상태 설정
        self.init_signals()   # 버튼 클릭 등을 함수에 연결
        


    def init_ui(self):
        # 음 켰을 때의 화면 상태.
        self.setWindowTitle("MiniWireShark")
        self.ui.btnStop.setEnabled(False)   # 캡처 전이니 정지 버튼은 꺼둔다
        
        table = self.ui.showPacketTable
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])

        # 열 너비 (Info는 남는 공간을 다 차지하게)
        for col, width in enumerate([60, 100, 200, 200, 80, 70]):
            table.setColumnWidth(col, width)
        table.horizontalHeader().setStretchLastSection(True)

        table.verticalHeader().setVisible(False)                  # 왼쪽 행 번호 숨기기
        table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 행 전체 선택
        table.setSelectionMode(QAbstractItemView.SingleSelection)

        # hex 뷰는 글자 폭이 일정한 글꼴이어야 줄이 맞음
        # (맥은 Menlo, 우분투는 DejaVu Sans Mono 같은 걸 시스템이 알아서 골라줌)
        mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        mono.setPointSize(12)
        self.ui.hexView.setFont(mono)
        self.ui.hexView.setLineWrapMode(QPlainTextEdit.NoWrap)       # 줄 꺾이면 hex 정렬 깨짐 (리눅스 글꼴이 더 넓음)
        table.setWordWrap(False)                                      # 긴 Info도 한 줄로 (Wireshark처럼)

        self.ui.packetInfo.setHeaderHidden(True)                  # 트리의 "1" 헤더 숨기기

        # 표시 필터 입력칸 (Enter 치면 적용, X 버튼으로 지우면 필터 해제)
        self.ui.inputFilter.setPlaceholderText("표시 필터 (예: tcp, ip.addr == 1.1.1.1, port 80 and not udp)  Enter로 적용")
        self.ui.inputFilter.setClearButtonEnabled(True)

        # 위아래 비율 (패킷 목록 : 상세+hex = 3 : 2)
        self.ui.verticalLayout_2.setStretch(0, 3)
        self.ui.verticalLayout_2.setStretch(1, 2)

        # 인터페이스 목록 채우기 (맨 위가 기본 인터페이스)
        for item in list_interfaces():
            self.ui.ifaceCombo.addItem(item["label"], item["value"])
        # 콤보박스가 폭을 다 먹어서 버튼이 오른쪽 끝에 몰리지 않게 (버튼은 콤보 옆에 붙이고 남는 공간은 오른쪽으로)
        self.ui.ifaceCombo.setMaximumWidth(340)
        self.ui.horizontalLayout.addStretch()

        # 표에서 우클릭하면 메뉴 (스트림 따라가기 등)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        

    def init_signals(self):
        # 버튼 -> 슬롯(함수) 연결.
        self.ui.btnStart.clicked.connect(self.on_start)
        self.ui.btnStop.clicked.connect(self.on_stop)
        self.ui.btnRestart.clicked.connect(self.on_restart)
        self.ui.btnSave.clicked.connect(self.on_save)
        self.ui.btnOpen.clicked.connect(self.on_open)
        self.ui.btnFlow.clicked.connect(self.on_flow)
        self.ui.btnRoute.clicked.connect(self.on_route)

        # 클릭이든 화살표 키든 선택한 행이 바뀌면 상세/hex 갱신
        self.ui.showPacketTable.currentCellChanged.connect(self.on_current_changed)
        self.ui.showPacketTable.customContextMenuRequested.connect(self.on_table_menu)

        self.ui.inputFilter.returnPressed.connect(self.apply_filter)     # Enter 치면 필터 적용
        self.ui.inputFilter.textChanged.connect(self.on_filter_changed)  # 다 지우면 바로 해제


    # 버튼 동작 
    # 시작
    def on_start(self):
        self.ui.btnStart.setEnabled(False)      # 캡처 중이니 시작 버튼은 꺼둔다
        self.ui.btnStop.setEnabled(True)        # 캡처 중이니 정지 버튼은 켠다
        self.ui.ifaceCombo.setEnabled(False)    # 캡처 중엔 인터페이스 못 바꿈
        # self.add_row(["1", "0.000", "192.168.0.2", "8.8.8.8", "DNS", "74", "Standard query"])     # 가짜 데이터
        iface = self.ui.ifaceCombo.currentData()     # "en0" 또는 ["en0", "lo0"] (없으면 None = scapy 기본)
        self.sniffer.start(iface=iface)  # 필터 칸은 표시 필터라서 캡처 시작에는 안 씀 (apply_filter 참고)

        self.capture_name = ", ".join(iface) if isinstance(iface, list) else str(iface)
        self.capture_since = time.time()
        self.capture_start_count = len(self.packets)
        print(f"[캡처 시작] 인터페이스: {self.capture_name}", flush=True)   # 문제 생기면 터미널에서 확인용
        self.status_timer.start(500)
        self.update_status()


    # 정지
    def on_stop(self):
        self.ui.btnStart.setEnabled(True)       # 정지했으니 시작 버튼은 켠다
        self.ui.btnStop.setEnabled(False)       # 정지했으니 정지 버튼은 꺼둔다
        self.ui.ifaceCombo.setEnabled(True)
        self.stop_capture()


    # 재시작
    def on_restart(self):
        self.ui.btnStart.setEnabled(True)       # 재시작했으니 시작 버튼은 켠다
        self.ui.btnStop.setEnabled(False)       # 재시작했으니 정지 버튼은 꺼둔다
        self.ui.ifaceCombo.setEnabled(True)

        self.stop_capture()
        self.clear_all()
        self.setWindowTitle("MiniWireShark")


    # 캡처 멈추기 (정지/재시작 공통)
    def stop_capture(self):
        was_running = self.status_timer.isActive()
        self.sniffer.stop()
        self.status_timer.stop()
        if was_running:
            got = len(self.packets) - self.capture_start_count
            print(f"[캡처 정지] {self.capture_name}에서 패킷 {got}개", flush=True)
            self.setWindowTitle(f"MiniWireShark · 정지 · 패킷 {len(self.packets)}개")


    # 창 제목에 캡처 상태 보여주기 (캡처 중 0.5초마다)
    def update_status(self):
        got = len(self.packets) - self.capture_start_count
        if got == 0 and time.time() - self.capture_since > 5:
            self.setWindowTitle(f"MiniWireShark · {self.capture_name}: 5초 넘게 패킷이 안 들어와요 (인터페이스 확인)")
        else:
            self.setWindowTitle(f"MiniWireShark · {self.capture_name}에서 캡처 중 · 패킷 {len(self.packets)}개")


    # 표, 트리, hex, 번호 전부 처음 상태로 (재시작이랑 파일 열기에서 같이 씀)
    def clear_all(self):
        self.ui.showPacketTable.setRowCount(0)  # 표 비우기
        self.ui.packetInfo.clear()              # 상세 트리 비우기
        self.ui.hexView.clear()                 # 옛날 hex 안 남게

        self.count = 0
        self.t0 = None
        self.packets = []               # 패킷 목록도 비워야 행 번호랑 안 어긋남
        self.analyzer.reset()           # 관계 정보도 처음부터


    # 필터 칸 글자가 바뀔 때: 완전히 비면 바로 필터 해제
    def on_filter_changed(self, text):
        if not text.strip():
            self.apply_filter()


    # 표시 필터 적용 (Enter 쳤을 때)
    # 필터에 맞는 행만 보이고 나머지는 숨김. 이미 잡은 패킷 전부에 적용됨
    def apply_filter(self):
        box = self.ui.inputFilter

        try:
            pred = parse_filter(box.text())
        except ValueError as e:
            # 문법이 틀리면 칸을 빨갛게 하고 이유를 툴팁으로. 이전 필터는 그대로 둠
            box.setStyleSheet("background-color: #ffd6d6; color: black;")
            box.setToolTip(str(e))
            return

        box.setStyleSheet("")                   # 정상이면 원래 모양으로
        box.setToolTip("")
        self.display_pred = pred

        table = self.ui.showPacketTable
        table.setUpdatesEnabled(False)          # 패킷 많으면 느려서 그리기 잠깐 끄기
        for row in range(len(self.packets)):
            table.setRowHidden(row, not self.is_shown(row))
        table.setUpdatesEnabled(True)

        # 흐름도 창이 "필터 결과" 보기로 열려 있으면 같이 바꿔줌
        if self.flow_dialog is not None and self.flow_dialog.isVisible() and self.flow_dialog.scope.currentIndex() == 0:
            self.flow_dialog.refresh()


    # row번째 패킷을 보여줄지 (필터 없으면 항상 True)
    def is_shown(self, row):
        return self.display_pred is None or self.display_pred(self.packets[row], self.analyzer.metas[row])


    # 캡처 실패했을 때 (필터 틀림, sudo 안 씀 등)
    def on_sniffer_error(self, msg):
        self.ui.btnStart.setEnabled(True)       # 못 시작했으니 버튼 원래대로
        self.ui.btnStop.setEnabled(False)
        self.ui.ifaceCombo.setEnabled(True)
        self.status_timer.stop()
        self.setWindowTitle("MiniWireShark · 캡처 실패")
        print(f"[캡처 실패] {msg}", flush=True)
        QMessageBox.warning(self, "캡처 실패", msg)


    # 저장
    def on_save(self):
        if not self.packets:                    # 저장할 게 없으면
            QMessageBox.information(self, "저장", "저장할 패킷이 없어요.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "패킷 저장", "capture.pcap", "PCAP (*.pcap)")
        if not path:                            # 취소 눌렀음
            return
        if not path.endswith(".pcap"):          # 확장자 없으면 붙여주기
            path += ".pcap"

        try:
            save_pcap(path, self.packets)
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", str(e))


    # 파일 열람
    def on_open(self):
        path, _ = QFileDialog.getOpenFileName(self, "파일 열기", "", "PCAP (*.pcap *.pcapng *.cap)")
        if not path:                            # 취소 눌렀음
            return

        try:
            packets = load_pcap(path)           # 먼저 읽어보기 (실패하면 지금 화면은 그대로 둠)
        except Exception as e:
            QMessageBox.critical(self, "열기 실패", str(e))
            return

        self.on_stop()                          # 캡처 중이었으면 멈추기
        self.clear_all()                        # 화면 비우고 새로 시작

        table = self.ui.showPacketTable
        table.setUpdatesEnabled(False)          # 패킷 많으면 느려서 그리기 잠깐 끄기
        for pkt in packets:
            self.on_packet(pkt)                 # 캡처할 때랑 똑같이 표에 추가
        table.setUpdatesEnabled(True)
        
        
    def add_row(self, values):
        # 패킷 테이블에 행 추가.
        row = self.ui.showPacketTable.rowCount()  # 현재 행 수
        self.ui.showPacketTable.insertRow(row)     # 새 행 추가
        
        color = PROTO_COLORS.get(values[4])    # 프로토콜 칸(5번째) 보고 행 색 고르기

        for col, value in enumerate(values):   # 각 열에 값 넣기
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)  # 편집 불가
            if color:
                item.setBackground(QBrush(QColor(color)))
                item.setForeground(QBrush(QColor("black")))  # 다크모드에서도 글자 보이게
            self.ui.showPacketTable.setItem(row, col, item)


    # 선택한 행이 바뀌었을 때 (클릭, 화살표 키, 흐름도에서 누른 것 전부)
    def on_current_changed(self, row, col, prev_row, prev_col):
        if 0 <= row < len(self.packets):
            self.on_row_clicked(row, col)


    # 표에서 행 클릭하면 hex 뷰랑 상세 트리 채우기
    def on_row_clicked(self, row, col):
        pkt = self.packets[row]                          # 행 번호 == 리스트 인덱스
        self.ui.hexView.setPlainText(hex_dump(pkt))      # 오른쪽 hex 뷰

        tree = self.ui.packetInfo
        tree.clear()                                     # 이전 클릭 내용 지우기

        # Wireshark처럼 Frame / Ethernet / IP / TCP / HTTP ... 순서로 (core/dissector.py)
        nodes = build_tree(pkt, row + 1, self.analyzer.metas[row], self.t0, self.packets, self.analyzer.metas)
        for node in nodes:
            tree.addTopLevelItem(self.make_tree_item(node))
        for i, node in enumerate(nodes):                 # 펼치기는 트리에 올린 다음에 해야 먹힘
            self.expand_tree_item(tree.topLevelItem(i), node)


    # Node(글자 + 자식들) -> QTreeWidgetItem (자식들까지 쭉)
    def make_tree_item(self, node):
        item = QTreeWidgetItem([node.text])
        for child in node.children:
            item.addChild(self.make_tree_item(child))
        return item


    def expand_tree_item(self, item, node):
        item.setExpanded(node.expanded)
        for i, child in enumerate(node.children):
            self.expand_tree_item(item.child(i), child)


    # row번째 행의 Info 칸만 다시 계산 (ping 요청에 "reply in N" 붙일 때)
    def refresh_info(self, row):
        values = summarize(self.packets[row], row + 1, self.t0, self.analyzer.metas[row])
        item = self.ui.showPacketTable.item(row, 6)
        if item:
            item.setText(values[6])


    # 필터 칸에 글자 넣고 바로 적용 (스트림 따라가기에서 씀)
    def set_filter(self, text):
        self.ui.inputFilter.setText(text)
        self.apply_filter()


    # 표에서 우클릭했을 때 메뉴
    def on_table_menu(self, pos):
        table = self.ui.showPacketTable
        row = table.rowAt(pos.y())
        if row < 0 or row >= len(self.packets):
            return
        table.selectRow(row)
        meta = self.analyzer.metas[row]

        menu = QMenu(self)
        tcp = menu.addAction("TCP 스트림 따라가기 (Follow TCP Stream)")
        udp = menu.addAction("UDP 스트림 따라가기 (Follow UDP Stream)")
        tcp.setEnabled(meta.stream_proto == "tcp")
        udp.setEnabled(meta.stream_proto == "udp")
        menu.addSeparator()
        flow = menu.addAction("흐름도 (이 연결만)")
        flow.setEnabled(meta.stream is not None)
        unfilter = menu.addAction("필터 지우기")

        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen in (tcp, udp):
            self.follow_stream(meta.stream_proto, meta.stream)
        elif chosen == flow:
            self.on_flow()
            self.flow_dialog.scope.setCurrentIndex(1)
            self.flow_dialog.refresh()
        elif chosen == unfilter:
            self.set_filter("")


    # 스트림 따라가기 창 열기
    def follow_stream(self, proto, stream_id):
        if self.follow_dialog is None:
            self.follow_dialog = FollowStreamDialog(self)
        self.follow_dialog.show_stream(proto, stream_id)
        self.follow_dialog.show()
        self.follow_dialog.raise_()


    # traceroute 경로 버튼
    def on_route(self):
        if self.route_dialog is None:
            self.route_dialog = RouteDialog(self)
        self.route_dialog.refresh()
        self.route_dialog.show()
        self.route_dialog.raise_()


    # 흐름도 버튼
    def on_flow(self):
        if self.flow_dialog is None:
            self.flow_dialog = FlowGraphDialog(self)
        self.flow_dialog.refresh()
        self.flow_dialog.show()
        self.flow_dialog.raise_()


    # 흐름도에 그릴 패킷 번호들. (번호 목록, 문제 있으면 안내 글자)
    def flow_indices(self, stream_only=False):
        if not stream_only:                              # 표시 필터로 보이는 것 전부
            return [i for i in range(len(self.packets)) if not self.ui.showPacketTable.isRowHidden(i)], None

        row = self.ui.showPacketTable.currentRow()
        if row < 0:
            return [], "표에서 패킷을 먼저 하나 선택해 주세요"
        meta = self.analyzer.metas[row]
        if meta.stream is None:
            return [], "선택한 패킷은 TCP/UDP 연결이 아니에요"
        key = (meta.stream_proto, meta.stream)
        return [i for i, m in enumerate(self.analyzer.metas) if (m.stream_proto, m.stream) == key], None


    # 흐름도에서 누른 패킷을 표에서 선택
    def select_packet(self, row):
        table = self.ui.showPacketTable
        table.selectRow(row)
        table.scrollToItem(table.item(row, 0))
        self.on_row_clicked(row, 0)


    # add_row에 값을 넘겨줌
    def on_packet(self, pkt):
        self.count += 1

        if self.t0 is None:     # 첫 패킷 처리를 위한 코드
            self.t0 = pkt.time

        meta = self.analyzer.add(pkt)                    # 상대 Seq, 짝꿍 같은 관계 정보
        row = summarize(pkt, self.count, self.t0, meta)

        self.add_row(row)
        self.packets.append(pkt)

        # 응답이 와서 짝이 생겼으면 요청 쪽 Info도 다시 (ping: "reply in N")
        if meta.request_in is not None:
            self.refresh_info(meta.request_in)
        for index in self.analyzer.reassembled_now:     # HTTP 조각들: "[TCP PDU reassembled in N]" 붙이기
            self.refresh_info(index)

        # 지금 걸려 있는 표시 필터에 안 맞으면 숨기기
        if not self.is_shown(len(self.packets) - 1):
            self.ui.showPacketTable.setRowHidden(len(self.packets) - 1, True)

        self.ui.showPacketTable.scrollToBottom()
        # TODO: 나중에 "자동 스크롤 끄기" 버튼 만들면 scrollToBottom을 if로 감싸기            
            
