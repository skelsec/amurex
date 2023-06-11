import traceback
from asysocks.unicomm.common.packetizers import Packetizer
import os

class SSHPacketizer(Packetizer):
	def __init__(self, buffer_size = 65535, init_buffer = b''):
		Packetizer.__init__(self, buffer_size)
		self.in_buffer = init_buffer
		self.__total_size = -1
		self.is_encrypted = False

		self.client_to_server_enc = None
		self.server_to_client_enc = None
		self.client_to_server_mac = None
		self.server_to_client_mac = None
		self.client_to_server_compression = None
		self.server_to_client_compression = None
		self.__decrypted_header = None
		self.__encrypted_header = None
		self.client_to_server_sequence_number = 0
		self.server_to_client_sequence_number = 0

		#mac computed from the compressed payload, encryption is done after

	def calc_packet_size(self):
		if self.server_to_client_enc is None:
			if len(self.in_buffer) >= 5:
				packet_length = int.from_bytes(self.in_buffer[0:4], byteorder='big', signed = False)
				self.__total_size = packet_length + 4
			else:
				self.__total_size = -1
		else:
			if len(self.in_buffer) >= self.server_to_client_enc.blocksize:
				self.__encrypted_header = self.in_buffer[:self.server_to_client_enc.blocksize]
				self.__decrypted_header = self.server_to_client_enc.decrypt(self.__encrypted_header)
				self.__total_size = int.from_bytes(self.__decrypted_header[0:4], byteorder='big', signed = False) + 4
				if self.server_to_client_mac is not None:
					self.__total_size += self.server_to_client_mac.blocksize
			else:
				self.__total_size = -1
	

	def get_payload(self, data):
		if self.server_to_client_enc is None:
			padsize = self.in_buffer[4]
			return data[5:-padsize]
		else:
			macdata = None
			if self.server_to_client_mac is not None:
				macdata = data[-self.server_to_client_mac.blocksize:]
				data = data[:-self.server_to_client_mac.blocksize]
			
			decdata = self.server_to_client_enc.decrypt(data[len(self.__encrypted_header):])
			decdata = self.__decrypted_header + decdata

			if self.server_to_client_mac is not None:
				res = self.server_to_client_mac.verify(decdata, macdata, self.server_to_client_sequence_number)
				if res is False:
					raise Exception('Incorrect MAC!')
			
			padsize = decdata[4]
			payload = decdata[5:-padsize]
			

			if self.server_to_client_compression is not None:
				payload = self.server_to_client_compression.decompress(payload)
			self.__decrypted_header = None
			self.__encrypted_header = None
			return payload

	
	def process_buffer(self):
		if self.__total_size == -1:
			self.calc_packet_size()

		while self.__total_size > -1 and len(self.in_buffer) >= self.__total_size:
			if self.__total_size > -1 and len(self.in_buffer) >= self.__total_size:
				payload = self.get_payload(self.in_buffer[:self.__total_size])
				self.in_buffer = self.in_buffer[self.__total_size:]
				self.calc_packet_size()

				self.server_to_client_sequence_number = (self.server_to_client_sequence_number + 1) & 0xffffffff
				yield payload

	async def data_out(self, payload):
		if payload is None:
			return
		if self.client_to_server_enc is None:
			align = 8
			padlen = 3 + align - ((len(payload) + 8) % align)
			random_padding = os.urandom(padlen)
			packet_length = len(payload) + len(random_padding)  + 1
			self.client_to_server_sequence_number = (self.client_to_server_sequence_number+1) & 0xffffffff
			yield packet_length.to_bytes(4, byteorder="big", signed = False) + len(random_padding).to_bytes(1, byteorder="big", signed = False) + payload + random_padding
		else:
			align = self.client_to_server_enc.blocksize
			if self.client_to_server_compression is not None:
				payload = self.client_to_server_compression.compress(payload)
			
			padlen = 3 + align - ((len(payload) + 8) % align)
			random_padding = os.urandom(padlen)
			packet_length = len(payload) + len(random_padding)  + 1
			macdata = b''
			packet = packet_length.to_bytes(4, byteorder="big", signed = False) + \
				len(random_padding).to_bytes(1, byteorder="big", signed = False) + \
				payload + \
				random_padding
			
			if self.client_to_server_mac is not None:
				macdata = self.client_to_server_mac.digest(packet, self.client_to_server_sequence_number)
			
			packet = self.client_to_server_enc.encrypt(packet)
			self.client_to_server_sequence_number = (self.client_to_server_sequence_number+1) & 0xffffffff

			yield packet+macdata
			
	
	async def data_in(self, data):
		if data is not None:
			self.in_buffer += data
		for packet in self.process_buffer():
			yield packet
		
		
