from scapy.all import *

packets = rdpcap('capture.pcap')
p = b""
for x in packets:
	load = x[Raw].load
	char = load[14:15]#'!"#$%&\'()*+,-.T0123456789'
	p += char
print(p)

#flag}siht_dnif_uoy_did_woH{
#flag{How_did_you_find_this}