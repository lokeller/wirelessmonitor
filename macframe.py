import struct

macAddress = struct.Struct('BBBBBB')

def format_address(addr):
	return ":".join([ '%x' % x for x in macAddress.unpack(addr)])


def parse(buf):

	frame_control = ord(buf[0])
	
	frame_type = (frame_control >> 2 ) & 0x3
	frame_subtype = frame_control >> 4

	if frame_type == 1 :
		# RTS frame
		if frame_subtype == int('1011',2): 
			tx_addr = buf[10:10+6]
			rx_addr = buf[4:4+6]
		# CTS frame
		elif frame_subtype == int('1100',2): 
			rx_addr = buf[4:4+6]
		# ACK frame
		elif frame_subtype == int('1101',2): 
			rx_addr = buf[4:4+6]
		# PS-Poll frame
		elif frame_subtype == int('1010',2): 
			tx_addr = buf[10:10+6]
			bssid = buf[4:4+6]
		# CF-End frame
		elif frame_subtype == int('1110',2): 
			bssid = buf[10:10+6]
			rx_addr = buf[4:4+6]
		# CF-End+CF-Ack
		elif frame_subtype == int('1111',2): 
			rx_addr = buf[4:4+6]
			bssid = buf[10:10+6]
		# Block Ack Req frame
		elif frame_subtype == int('1000',2): 
			rx_addr = buf[4:4+6]
			tx_addr = buf[10:10+6]
		# Block Ack frame
		elif frame_subtype == int('1001',2): 
			rx_addr = buf[4:4+6]
			tx_addr = buf[10:10+6]
	# Data frame
	elif frame_type == 2 :
		to_ds = ( ord(buf[1]) >> 1 ) & 1 > 0
		from_ds = ( ord(buf[1]) ) & 1 > 0
		if to_ds == 0 :
			if from_ds == 0 :
				rx_addr = buf[4:4+6]
				tx_addr = buf[10:10+6]
				ra = rx_addr
				da = rx_addr
				ta = tx_addr
				sa = rx_addr
				bssid = buf[16:16+6]
			else :
				rx_addr = buf[4:4+6]
				bssid = buf[10:10+6]
				ra = rx_addr
				da = rx_addr
				ta = bssid
				sa = buf[16:16+6]
		else :
			if from_ds == 0:
				bssid = buf[4:4+6]
				tx_addr = buf[10:10+6]
				ra = bssid
				ta = tx_addr
				sa = tx_addr
				da = buf[16:16+6]
			else :
				rx_addr = buf[4:4+6]
				tx_addr = buf[10:10+6]
				ra = rx_addr
				ta = tx_addr
				da = buf[16:16+6]
				sa = buf[22:22+6]
	# Management frame
	elif frame_type == 0 :
		rx_addr = buf[4:4+6]
		tx_addr = buf[10:10+6]
		bssid = buf[16:16+6]

	ret = locals()
	del ret['buf']
	return ret
