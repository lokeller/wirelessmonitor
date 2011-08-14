import struct

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

