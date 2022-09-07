import traceback
import typing
from amurex.protocol.messages import SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_OPEN, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_REQUEST


class SSHChannel:
	def __init__(self, type:str, recipientid:int, windowsize:int, packetsize:int, data = b''):
		self.type = type
		self.recipientid = recipientid
		self.windowsize = windowsize
		self.packetsize = packetsize
		self.senderid = None
		self.connection = None
		self.data = data

	async def msg_in(self, msgtype, msg):
		try:
			print(msgtype)
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, msg)
				print(str(msg))
				self.windowsize = msg.windowsize
				self.packetsize = msg.packetsize
				self.senderid = msg.sender
				await self.channel_opened(msg)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE:
				msg = typing.cast(SSH_MSG_CHANNEL_OPEN_FAILURE, msg)
				await self.channel_failed(msg)
			
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST:
				msg = typing.cast(SSH_MSG_CHANNEL_WINDOW_ADJUST, msg)
				self.windowsize += msg.extend
				print('windowsize: %s' % self.windowsize)

				
			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_DATA, msg)
				await self.data_in(None, msg.data)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA:
				msg = typing.cast(SSH_MSG_CHANNEL_EXTENDED_DATA, msg)
				await self.data_in(msg.datatype, msg.data)

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_EOF:
				await self.channel_eof()

			if msgtype == SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE:
				await self.channel_close()

		except Exception as e:
			traceback.print_exc()
			return False, e

	async def channel_failed(self, msg:SSH_MSG_CHANNEL_OPEN_FAILURE):
		print('Channel failed to open! Reason: %s, Description: %s' % (msg.reason, msg.description))

	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		print('Channel opened!')

	async def channel_eof(self):
		print('Channel EOF')

	async def channel_close(self):
		print('Channel Close')

	async def data_in(self, datatype:int, data:bytes):
		print('!!!!!!!!!!!!!! data incoming!!!! %s' % data)

	async def adjust_window(self, size):
		req = SSH_MSG_CHANNEL_WINDOW_ADJUST(self.senderid, 2096)
		print(str(req))
		await self.connection.write(req.to_bytes())

	async def data_out(self, data:bytes, datatype:int = None):
		try:
			self.windowsize -= len(data)
			print('windowsize: %s' % self.windowsize)
			if datatype is None:	
				await self.connection.write(SSH_MSG_CHANNEL_DATA(self.senderid, data).to_bytes())
			else:
				await self.connection.write(SSH_MSG_CHANNEL_EXTENDED_DATA(self.senderid, datatype, data).to_bytes())
		except Exception as e:
			traceback.print_exc()
	
	async def channel_request(self, request:str, wantreply:bool=True, data:bytes=b''):
		req = SSH_MSG_CHANNEL_REQUEST(self.senderid, request, wantreply, data)
		print(str(req))
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


