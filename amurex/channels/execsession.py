
import asyncio
import traceback
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSH_MSG_CHANNEL_OPEN, SSHString, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST,\
		SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA


class SSHExecSession(SSHChannel):
	def __init__(self, recipientid):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
	
	async def channel_opened(self, msg:SSH_MSG_CHANNEL_OPEN_CONFIRMATION):
		try:
			print('Channel opened!')
			data = b'ls -la'
			await self.channel_request('exec', True, data)
			await self.write_eof()
		except Exception as e:
			traceback.print_exc()
	

	async def channel_success(self):
		try:
			print('Channel setup done!')
			
		except Exception as e:
			traceback.print_exc()
	
	async def channel_failure(self):
		print('Channel setup error!')

	async def data_in(self, datatype:int, data:bytes):
		data = data.decode()
		print(data)