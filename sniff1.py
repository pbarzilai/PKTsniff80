from scapy.all import IP, sniff
from scapy.layers import http
import re


def process_tcp_packet(packet):
    try:
        if not (packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse)):
            return
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            pkt_txt = ""
            pkt_txt = "{0[Method]} {0[Path]}".format(http_layer.fields) + "\n"
            pkt_txt += "Source IP: " + packet.sprintf("%IP.src%") + "\n"
            pkt_txt += "Source Port: " + packet.sprintf("%TCP.sport%") + "\n"
            pkt_txt += "Destination IP: " + packet.sprintf("%IP.dst%") + "\n"
            pkt_txt += "Destination Port: " + packet.sprintf("%TCP.dport%") + "\n"
            result = re.search(r'(?:HTTP/).*$', str(packet), re.DOTALL)
            pkt_txt += result.group(0) + "\n"
            print pkt_txt
        elif packet.haslayer(http.HTTPResponse):
            pkt_txt = ""
            pkt_txt += "Source IP: " + packet.sprintf("%IP.src%") + "\n"
            pkt_txt += "Source Port: " + packet.sprintf("%TCP.sport%") + "\n"
            pkt_txt += "Destination IP: " + packet.sprintf("%IP.dst%") + "\n"
            pkt_txt += "Destination Port: " + packet.sprintf("%TCP.dport%") + "\n"
            result = re.search(r'(?:HTTP/).*$', str(packet), re.DOTALL)
            pkt_txt += result.group(0)
            print pkt_txt
    except () as e:
        print e


#sniff(filter='tcp', prn=process_tcp_packet)
sniff(filter='host *****', prn=process_tcp_packet)

        
