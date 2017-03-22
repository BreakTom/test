#!coding:utf8
import sys
from scapy.all import *
reload(sys)
sys.setdefaultencoding("utf-8")

class SniffServer(object):
    def __init__(self, local_mac="20:7c:8f:6f:b3:0f", iface="mon0"):
        self.local_mac = local_mac
        self.iface = iface

    def start(self):
        sniff(iface=self.iface,prn=self.probe_response_handler)

    def probe_response_handler(self, pkt):

        if pkt.haslayer(Dot11):
            if pkt.type==0 and pkt.subtype==5 and pkt.addr1 == self.local_mac:
                    ap_channel = int(ord(pkt[Dot11Elt:3].info))
                    ap_mac = pkt.addr2
                    ap_ssid = pkt[Dot11Elt:1].info
                    ap_rates = ((pkt[Dot11Elt:2].info))
                    rss = -(256-ord(pkt.notdecoded[-4:-3]))
                    capture_channel = (ord(pkt.notdecoded[-11:-10])*256+\
                        ord(pkt.notdecoded[-12:-11])-2407)/5
                    arrive_time = pkt.timestamp

                    ap_rates = [int(ord(ap_rates[i])) for i in range(len(ap_rates))]
                    rates = []
                    for rate in ap_rates:
                        if rate > 128:
                            rates.append((0-rate+128)/2)
                        else:
                            rates.append(rate/2)

                    print "arr_time:%s capture_ch:%s ap_ch:%s ap_mac:%s SSID:%s RSS:%sdbm rates:%s"\
                        %(arrive_time, capture_channel, ap_channel, ap_mac, ap_ssid, rss, rates)


if __name__ == "__main__":
    svrd = SniffServer()
    svrd.start()
