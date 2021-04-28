#arg is what you want type of packet you want to sniff
#arg 2 is either what you want for the tcp (port and host)
#or what subnet you want
from scapy.all import *
import sys

#sniffer
print("sniffing packets...")

def print_pkt(pkt):
    pkt.show()

pkt = sys.argv[1]
if sys.argv[1] != 'icmp':
    tcpin = sys.argv[2]
    tcpuse = tcpin.split(" ")
    tcphost = str('tcp port ' + tcpuse[0] + ' and ip host ' + tcpuse[1])

    subnetin = sys.argv[2]
    sn = str('net ' + sn)


icmp = sniff(filter='icmp', prn=print_pkt)
tcp = sniff(filter=tcphost, prn=print_pkt)
subnet = sniff(filter=sn, prn=print_pkt)
