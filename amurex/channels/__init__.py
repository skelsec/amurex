import traceback
import typing
import asyncio
from amurex.protocol.messages import SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_OPEN, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_REQUEST

AMUREX_SSH_WINDOWSIZE_MIN = 0x10000
AMUREX_SSH_WINDOWSIZE_MAX = 0xffffffff
AMUREX_SSH_PACKETSIZE_MIN = 0x8000
AMUREX_SSH_WINDOWSIZE_MAX = 0x10000

def minmax(minsize, maxsize, size):
	if minsize <= size <= maxsize:
		return size
	return max(minsize, min(size, maxsize))

class SSHChannel:
	def __init__(self, type:str, recipientid:int, windowsize:int, packetsize:int, data = b''):
		self.type = type
		self.recipientid = recipientid
		self.windowsize = minmax(AMUREX_SSH_WINDOWSIZE_MIN, AMUREX_SSH_WINDOWSIZE_MAX, windowsize)
		self.windowsize_server = None
		self.windowsize_server_updated = asyncio.Event()
		self.packetsize = minmax(AMUREX_SSH_PACKETSIZE_MIN, AMUREX_SSH_WINDOWSIZE_MAX, packetsize)
		self.packetsize_server = None
		self.senderid = None
		self.connection = None
		self.data = data
		self.channel_opened_evt = asyncio.Event()
		self.channel_closed_evt = asyncio.Event()

	async def msg_in(self, msgtype, msg):
		try:
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, msg)
				self.windowsize_server = msg.windowsize
				self.packetsize_server = msg.packetsize
				self.senderid = msg.sender
				self.channel_opened_evt.set()
				await self.channel_opened(msg)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_FAILURE, msg)
				self.channel_closed_evt.set()
				await self.channel_failed(msg)
			
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST:
				msg = typing.cast(SSH_MSG_CHANNEL_WINDOW_ADJUST, msg)
				self.windowsize += msg.extend
				self.windowsize_server_updated.set()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_DATA, msg)
				await self.data_in(None, msg.data)
				self.windowsize -= len(msg.data)
				if self.windowsize <= AMUREX_SSH_WINDOWSIZE_MIN:
					await self.adjust_window(AMUREX_SSH_WINDOWSIZE_MIN)
					self.windowsize += AMUREX_SSH_WINDOWSIZE_MIN

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_EXTENDED_DATA, msg)
				await self.data_in(msg.datatype, msg.data)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EOF:
				await self.channel_eof()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE:
				self.channel_closed_evt.set()
				await self.channel_close()

		except Exception as e:
			traceback.print_exc()
			return False, e
		
	async def close(self):
		await self.channel_close()

	async def channel_failed(self, msg:SSH_MSG_CHANNEL_OPEN_FAILURE):
		print('Channel failed to open! Reason: %s, Description: %s' % (msg.reason, msg.description))
		self.channel_closed_evt.set()
		await self.close()

	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		print('Channel opened!')

	async def channel_eof(self):
		print('Channel EOF')
		

	async def channel_close(self):
		print('Channel Close')
		if self.channel_closed_evt.is_set():
			return
		self.channel_closed_evt.set()
		await self.connection.write(SSH_MSG_CHANNEL_CLOSE(self.senderid).to_bytes())

	async def data_in(self, datatype:int, data:bytes):
		print('!!!!!!!!!!!!!! data incoming!!!! %s' % data)

	async def adjust_window(self, size):
		req = SSH_MSG_CHANNEL_WINDOW_ADJUST(self.senderid, size)
		await self.connection.write(req.to_bytes())

	async def data_out(self, data:bytes, datatype:int = None, skip_windowcheck = False):
		try:
			if skip_windowcheck is False:
				while self.windowsize_server < len(data):
					await self.windowsize_server_updated.wait()
					self.windowsize_server_updated.clear()
				
				self.windowsize_server -= len(data)
			
			data_to_send = []
			if len(data) >= (self.packetsize_server - 0x100):
				while len(data) >= (self.packetsize_server - 0x100):
					chunk = data[:self.packetsize_server-0x100]
					data = data[self.packetsize_server-0x100:]
					data_to_send.append(chunk)
			else:
				data_to_send.append(data)
			for chunk in data_to_send:
				if datatype is None:
					await self.connection.write(SSH_MSG_CHANNEL_DATA(self.senderid, chunk).to_bytes())
				else:
					await self.connection.write(SSH_MSG_CHANNEL_EXTENDED_DATA(self.senderid, datatype, chunk).to_bytes())
		
		except Exception as e:
			traceback.print_exc()
	
	async def channel_request(self, request:str, wantreply:bool=True, data:bytes=b''):
		req = SSH_MSG_CHANNEL_REQUEST(self.senderid, request, wantreply, data)
		await self.connection.write(req.to_bytes())

	async def write_eof(self):
		req = SSH_MSG_CHANNEL_EOF(self.senderid)
		await self.connection.write(req.to_bytes())

	def get_channel_open(self):
		return SSH_MSG_CHANNEL_OPEN(
			self.type,
			self.recipientid,
			self.windowsize, 
			self.packetsize,
			self.data
		).to_bytes()


