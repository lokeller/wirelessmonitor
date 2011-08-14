#!/usr/bin/python

import subprocess
import signal
import sys
import os
import struct
import tempfile
import radiotap
import sniffer
import macframe
import time

radio_tap_hdr = struct.Struct('BxHI')

def shutdown():
	print "Shutting down monitor interface"
	s.shutdown()

def signal_handler(signal, frame):
	print "Interrupted by the user"
	shutdown()
	sys.exit(0)

if __name__ == "__main__":

	s = sniffer.Sniffer('phy0')

	s.setup()

	print "Sniffing on channel at %f GHz" % s.get_channel()

	signal.signal(signal.SIGINT, signal_handler)

	macAddress = struct.Struct('BBBBBB')

	try :
		
		last_print = time.time()
		busy_time = 0

		while True:
			pkt = s.read_packet()
			len_hdr = radiotap.get_length(pkt['data'])
			rt_hdr = radiotap.parse(pkt['data'])

			# skip transmitted frames
			if radiotap.RTAP_DATA_RETRIES in rt_hdr.keys() :
				continue

			mac_hdr = macframe.parse(pkt['data'][len_hdr:])
			
			rate = rt_hdr[radiotap.RTAP_RATE] * 500.0 * 1000.0;

			frame_time = (len(pkt['data']) - len_hdr) * 8.0 / rate
			
			busy_time += frame_time

			if time.time() - last_print > 5 :
				occupation = busy_time / ( time.time() - last_print )  * 100
				print "Current channel occupation: %f %%" % occupation
				last_print = time.time()
				busy_time = 0


	except IOError as e:
		print "Finished", e

	shutdown()
#	signal.pause()
