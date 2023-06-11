import traceback
import typing
import asyncio
from amurex.protocol.messages import SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_EOF, \
	SSH_MSG_CHANNEL_OPEN, SSHMessageNumber, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, \
	SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
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
		self.windowsize_updated = asyncio.Event()
		self.packetsize = minmax(AMUREX_SSH_PACKETSIZE_MIN, AMUREX_SSH_WINDOWSIZE_MAX, packetsize)
		self.packetsize_server = None
		self.senderid = None
		self.connection = None
		self.data = data
		self.channel_opened_evt = asyncio.Event()
		self.channel_setup_completed_evt = asyncio.Event()
		self.channel_closed_evt = asyncio.Event()
		self.__request_lock = asyncio.Lock()
		self.__reply_evt = asyncio.Event()
		self.__reply_msg = None

	async def msg_in(self, msgtype, msg):
		try:
			#print('SSHChannel.msg_in: %s' % msgtype)
			if self.channel_closed_evt.is_set() is True:
				return
			
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, msg)
				self.windowsize_server = msg.windowsize
				self.packetsize_server = msg.packetsize
				self.senderid = msg.sender
				self.channel_opened_evt.set()
				await self.channel_opened(msg)
				self.channel_setup_completed_evt.set()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_FAILURE, msg)
				self.channel_closed_evt.set()
				await self.channel_failed(msg)
			
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST:
				msg = typing.cast(SSH_MSG_CHANNEL_WINDOW_ADJUST, msg)
				self.windowsize += msg.extend
				self.windowsize_updated.set()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_DATA, msg)
				await self.channel_data_in(None, msg.data)
				self.windowsize_server -= len(msg.data)
				if self.windowsize_server <= AMUREX_SSH_WINDOWSIZE_MIN:
					await self.adjust_window(AMUREX_SSH_WINDOWSIZE_MIN)
					self.windowsize_server += AMUREX_SSH_WINDOWSIZE_MIN

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_EXTENDED_DATA, msg)
				await self.channel_data_in(msg.datatype, msg.data)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EOF:
				await self.channel_eof()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE:
				await self.close(True)
			
			if msgtype in [SSHMessageNumber.SSH_MSG_CHANNEL_SUCCESS, SSHMessageNumber.SSH_MSG_CHANNEL_FAILURE]:
				if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_SUCCESS:
					self.__reply_msg = True
				else:
					self.__reply_msg = False
				self.__reply_evt.set()

		except Exception as e:
			traceback.print_exc()
			return False, e
		
	async def close(self, server_side:bool=False):
		"""Don't overwrite this function, use channel_close instead"""
		try:
			await self.channel_close(server_side)
		except:
			pass
		finally:
			self.channel_closed_evt.set()
		

	async def channel_init(self, *args, **kwargs):
		"""Override this function to do something when the channel is initialized"""
		pass

	async def channel_failed(self, msg:SSH_MSG_CHANNEL_OPEN_FAILURE):
		"""Override this function to do something when the channel failed to open"""
		#print('Channel failed to open! Reason: %s, Description: %s' % (msg.reason, msg.description))
		self.channel_closed_evt.set()
		await self.close()

	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		"""Override this function to do something when the channel is opened"""
		pass

	async def channel_eof(self):
		"""Override this function to do something when the channel is EOF"""
		pass

	async def channel_close(self):
		"""Override this function to do something when the channel is closed"""
		if self.channel_closed_evt.is_set():
			return
		self.channel_closed_evt.set()
		await self.connection.write(SSH_MSG_CHANNEL_CLOSE(self.senderid).to_bytes())
	
	async def channel_request(self, request:str, wantreply:bool=True, data:bytes=b''):
		"""Send a channel request to the server. If wantreply is True, it will wait for the reply and return it."""
		"""Only one request can be sent at a time, so if you want to send multiple requests, you need to wait for the reply first."""
		async with self.__request_lock:
			try:
				if wantreply is True:
					self.__reply_evt.clear()
				
				req = SSH_MSG_CHANNEL_REQUEST(self.senderid, request, wantreply, data)
				await self.connection.write(req.to_bytes())
				if wantreply is True:
					await self.__reply_evt.wait()
					self.__reply_evt.clear()
					return self.__reply_msg, None
				return True, None
			except Exception as e:
				return False, e
			finally:
				self.__reply_evt.clear()
				self.__reply_msg = None

	
	async def channel_data_in(self, datatype:int, data:bytes):
		"""Override this function to do something when data is received"""
		pass
		
	async def adjust_window(self, size):
		req = SSH_MSG_CHANNEL_WINDOW_ADJUST(self.senderid, size)
		#print('Adjusting window to %s' % size)
		await self.connection.write(req.to_bytes())

	async def channel_data_out(self, data:bytes, datatype:int = None):
		try:
			if self.channel_closed_evt.is_set():
				raise Exception('Channel is closed! Cannot send data!')
			
			while self.windowsize < len(data):
				await self.windowsize_updated.wait()
				self.windowsize_updated.clear()
				
			self.windowsize -= len(data)
			
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

			return True, None
		except Exception as e:
			await self.close()
			return None, e
	
	async def write_eof(self):
		"""Send EOF to the server"""
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


