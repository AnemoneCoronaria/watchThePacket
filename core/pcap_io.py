from scapy.all import wrpcap, rdpcap

# pcap 파일 저장하고 불러오는 파일
# 에러(파일 없음, 깨진 파일 등)는 여기서 안 잡고 부르는 쪽(main_window)에서 잡음


def save_pcap(path, packets):
    # 패킷 리스트를 pcap 파일로 저장
    wrpcap(path, packets)


def load_pcap(path):
    # pcap 파일 읽어서 패킷 리스트로 돌려줌
    return list(rdpcap(path))
