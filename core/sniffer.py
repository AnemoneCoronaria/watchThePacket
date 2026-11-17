from PySide6.QtCore import QObject, Signal, QTimer
from scapy.all import AsyncSniffer
from scapy.arch.common import compile_filter

# 패킷 잡아서 "잡았다!" 하고 외치는 파일
# 창이 어떻게 생겼는지는 얘가 모름. 그냥 외치기만 함 ㅋㅋ
#
# 흐름
#   start() 누름 -> 백그라운드에서 캡처 시작
#   패킷 하나 올 때마다 _on_packet이 불림 (창이랑 다른 스레드임, 주의)
#   _on_packet이 emit으로 외침 -> main_window의 on_packet이 받아서 표에 추가
#   stop() 누르면 끝
#
# 에러가 나면 error_occurred로 외침 (필터 문법 틀림, sudo 안 씀 등)


class Sniffer(QObject):
    packet_captured = Signal(object)
    error_occurred = Signal(str)      # 캡처 못 했을 때 이유를 글자로 전달

    def __init__(self):
        super().__init__()
        self._sniffer = None
        self._last_loopback = (None, 0.0)   # 리눅스 lo 중복 거르기용 (마지막 바이트, 시각)


    def start(self, iface=None, bpf_filter=""):
        if self._sniffer is not None:
            return

        bpf_filter = bpf_filter.strip()

        # 필터 문법 미리 검사 (sudo 없어도 됨). 틀리면 캡처 시작 안 하고 에러만 외침
        if bpf_filter:
            try:
                compile_filter(bpf_filter)
            except Exception:
                self.error_occurred.emit(
                    f"필터 문법이 이상해요: {bpf_filter}\n(예: tcp, udp, port 80, host 1.1.1.1)"
                )
                return

        self._sniffer = AsyncSniffer(iface=iface, filter=bpf_filter or None, prn=self._on_packet, store=False)
                # iface=iface : 어느 인터페이스를 잡을지
                # filter=bpf_filter or None : 필터가 비어 있으면 필터 없이 다 잡음
                # prn=self._on_packet : 패킷이 하나 올 때마다 _on_packet을 불러 달라는 뜻
                # store=False : 패킷을 쌓아 두지 않고 흘려보냄

        self._sniffer.start()

        # 시작하자마자 죽는 경우(sudo 안 씀 등)는 다른 스레드에서 조용히 터져서
        # 잠깐 뒤에 한 번 확인해 봐야 알 수 있음
        QTimer.singleShot(700, self._check_started)


    def stop(self):
        if self._sniffer is None:
            return

        try:
            self._sniffer.stop()
        except Exception:
            pass            # 시작도 못 하고 죽은 상태에서 stop하면 에러를 던져서 그냥 무시
        self._sniffer = None


    def _check_started(self):
        sniffer = self._sniffer
        if sniffer is None:         # 그 사이에 정지 눌렀으면 할 일 없음
            return

        if sniffer.exception is not None:
            msg = str(sniffer.exception)
            self._sniffer = None

            # 권한 문제면 sudo 안내를 붙여줌
            if "bpf" in msg.lower() or "permission" in msg.lower() or "not permitted" in msg.lower():
                msg += "\n\n관리자 권한이 필요해요. sudo로 실행했는지 확인해 주세요."

            self.error_occurred.emit(f"캡처를 시작하지 못했어요.\n{msg}")


    def _on_packet(self, pkt):
        # 리눅스 루프백(lo)은 보내는 사본 + 받는 사본이 둘 다 들어와서 패킷이 두 번씩 잡힘
        # -> lo 에서 똑같은 바이트가 아주 짧은 사이(0.01초)에 또 오면 하나는 버림
        if getattr(pkt, "sniffed_on", None) == "lo":
            raw, when = bytes(pkt), float(pkt.time)
            last_raw, last_when = self._last_loopback
            if raw == last_raw and when - last_when < 0.01:
                return
            self._last_loopback = (raw, when)
        self.packet_captured.emit(pkt)


# 창 없이 혼자 테스트하는 곳 (나중에 필요하면 채우기)
# 캡처는 sudo 필요함
if __name__ == "__main__":
    pass
