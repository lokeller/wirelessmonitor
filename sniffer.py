import subprocess
import sys
import os
import struct
import tempfile
import pcapfile
import re


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
		
	def get_channel(self):
		output = subprocess.Popen(["iwconfig", self.phy + '.monitor'], stdout=subprocess.PIPE).communicate()[0]	
		m = re.search('Frequency:([0-9.]+)', output)
		return float(m.group(1))


	def setup(self):

		self.setup_monitor_if()

		# create a fifo 
		self.dir = tempfile.mkdtemp()
		self.fifo = self.dir + "/fifo"
		os.mkfifo(self.fifo)	

		# start tcpdump
		self.pid = subprocess.Popen(['tcpdump', '-i', self.phy + '.monitor', '-w', self.fifo, '-U', '-s','0'])

		# setup the pcap parsing
		self.pcap = pcapfile.PcapFile(self.fifo)
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


