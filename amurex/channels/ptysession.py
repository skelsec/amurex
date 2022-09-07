import asyncio
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSH_MSG_CHANNEL_OPEN, SSHString, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA


class SSHPTYSession(SSHChannel):
	def __init__(self, recipientid, term = 'vt100', row_width=80, row_height=24, pixel_width=0, pixel_height=0):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
		self.term = term
		self.row_width = row_width
		self.row_height = row_height
		self.pixel_width = pixel_width
		self.pixel_height = pixel_height
	
	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		print('Channel opened!')
		await asyncio.sleep(10)
		data = b''
		data += SSHString.to_bytes(self.term)
		data += self.row_width.to_bytes(4, byteorder='big', signed=False)
		data += self.row_height.to_bytes(4, byteorder='big', signed=False)
		data += self.pixel_width.to_bytes(4, byteorder='big', signed=False)
		data += self.pixel_height.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(b'') # terminal modes
		await self.channel_request('pty-req', True, data)
	

	async def channel_success(self):
		print('Channel setup done!')
	
	async def channel_failure(self):
		print('Channel setup error!')
