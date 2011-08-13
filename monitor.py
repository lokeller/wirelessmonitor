#!/usr/bin/python

import subprocess
import signal
import sys
import os
import struct
import tempfile
import radiotap


class Sniffer:
	def __init__(self, phy):
		self.phy = phy

	def setup_monitor_if(self):
		
		try :
			subprocess.check_call(['iw', 'phy', self.phy, 
						'interface', 'add', self.phy + ".monitor",
						'type', 'monitor', 
						'flags', 'fcsfail', 
							 'control', 
							 'otherbss'])
			subprocess.check_call(['ifconfig', self.phy + ".monitor", 'up'])
		except :
			print "Error while setting up the monitor device"
		
	def setup(self):

		self.setup_monitor_if()

		# create a fifo 
		self.dir = tempfile.mkdtemp()
		self.fifo = self.dir + "/fifo"
		os.mkfifo(self.fifo)	

		# start tcpdump
		self.pid = subprocess.Popen(['tcpdump', '-i', self.phy + '.monitor', '-w', self.fifo, '-U', '-s','0'])

		# setup the pcap parsing
		self.pcap = PcapFile(self.fifo)
		self.pcap.open()
	
	def shutdown_monitor_if(self):
		try :
			subprocess.check_call(['iw', 'dev', self.phy + ".monitor", 'del']) 
		except :
			print "Error while removing monitor interface"

	def shutdown(self):
		# shutdown pcap parsing
		self.pcap.close()

		# kill tcpdump
		self.pid.terminate()
		self.pid.wait()

		# delete the fifo
		os.unlink(self.fifo)
		os.rmdir(self.dir)

		self.shutdown_monitor_if()
	
	def read_packet(self):
		return self.pcap.read_packet()



class PcapFile:
	pkt_hdr_struct = struct.Struct('IIII')
	header_struct = struct.Struct('IHHiIII')

	def __init__(self, file):
		self.filename = file

	def open(self):
		self.file = open(self.filename, 'r')
		try:
			self.__read_header()
		except Exception as e:
			print e
	
	def close(self):
		self.file.close()

	def __read_header(self):
		header_bytes = self.file.read(self.header_struct.size)

		if len(header_bytes) < self.header_struct.size :
			raise IOError

		header_fields = self.header_struct.unpack(header_bytes)

		if header_fields[0] != 0xa1b2c3d4:
			raise Exception('Wrong file format ( expected %xd found %xd' % (0xa1b2c3d4, header_fields[0]) )

		self.version_major = header_fields[1]
		self.version_minor = header_fields[2]
		self.delta_to_gmt = header_fields[3]
		self.sigfigs = header_fields[4]
		self.snaplen = header_fields[5]
		self.network_type = header_fields[6]

	def read_packet(self):
		hdr_bytes = self.file.read(self.pkt_hdr_struct.size)

		if len(hdr_bytes) < self.pkt_hdr_struct.size :
			raise IOError

		hdr_fields = self.pkt_hdr_struct.unpack(hdr_bytes)
		field_names = [ 'ts_sec', 'ts_usec', 'incl_len', 'orig_len' ]
		pkt = dict(zip( field_names, hdr_fields))
		pkt['data'] = self.file.read(pkt['incl_len'])
		return pkt

radio_tap_hdr = struct.Struct('BxHI')

def shutdown():
	print "Shutting down monitor interface"
	sniffer.shutdown()

def signal_handler(signal, frame):
	print "Interrupted by the user"
	shutdown()
	sys.exit(0)

if __name__ == "__main__":

	sniffer = Sniffer('phy0')

	sniffer.setup()

	signal.signal(signal.SIGINT, signal_handler)

	macAddress = struct.Struct('BBBBBB')

	try :
		while True:
			pkt = sniffer.read_packet()
			len_hdr = radiotap.get_length(pkt['data'])
			rt_hdr = radiotap.parse(pkt['data'])

			# skip transmitted frames
			if 17 in rt_hdr.keys() :
				continue

			fc = ord(pkt['data'][len_hdr])

			type = (fc >> 2 ) & 0x2
			subtype = fc >> 4
			if type & 0x2 != 2 or subtype != 0 :
				print "Non data frame (type: %d subtype: %d)" % ( type , subtype )
				continue

			src_bytes = pkt['data'][len_hdr+4+6:len_hdr+4+6+6]
			sender = macAddress.unpack(src_bytes)
		
			print rt_hdr
			print len(pkt['data']) - len_hdr

			print ":".join([ "%x" % x for x in sender])  + " Link gain: "  + str(rt_hdr[5])


	except IOError as e:
		print "Finished", e

	
#	signal.pause()
