#!/usr/bin/env python

import os, sys, logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import pyshark

# Function to extract TCP streams

pcap = sys.argv[1]

def tcp_stream(pcap_file_in):

	if not os.path.exists(folder):
		print("Folder doesn't exist so creating " + str(folder))
		os.makedirs(folder)

	tcp_stream_index = []

	print('[+] Extracting TCP streams')
	# Create a list of the tcp streams in the pcap file and save them as an index
	cap = pyshark.FileCapture(pcap_file_in)
	for pkt in cap:
		try:
			if pkt.tcp.stream not in tcp_stream_index:
				tcp_stream_index.append(pkt.tcp.stream)
		except:
			pass
	if len(tcp_stream_index) == 0:
		print("No TCP Found")
	for stream in tcp_stream_index:
		cap_filtered = pyshark.FileCapture(pcap_file_in, display_filter = 'tcp.stream eq %d' % int(stream), use_json=True, include_raw=True)
		for pkt in cap_filtered:
			pktdump = PcapWriter('filtered_stream_%d.pcap' % int(stream), append=True, sync=True)
			pktdump.write(pkt.get_raw_packet())


	print('Done')


tcp_stream(pcap)