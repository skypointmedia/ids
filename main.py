from scapy.all import *

def packet_callback(packet):
    if packet[TCP].payload:
        tcp_payload = str(packet[TCP].payload)

        if "bad_keyword" in tcp_payload:
            print("ALERT: Intrusion detected!")

def start_intrusion_detection():
    sniff(filter="tcp", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_intrusion_detection()
