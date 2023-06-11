
import asyncio
import traceback
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSHString


class SSHExecSession(SSHChannel):
	def __init__(self, recipientid, command):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
		self.command = command
		if isinstance(command, str):
			self.command = command.encode()
		self.stdout = asyncio.Queue()
		self.stderr = asyncio.Queue()

	async def channel_init(self, *args, **kwargs):
		try:
			cmd = SSHString.to_bytes(self.command)
			return await self.channel_request('exec', True, cmd)
		except Exception as e:
			return None, e
	
	async def channel_close(self, server_side:bool=False):
		self.stderr.put_nowait(b'')
		self.stdout.put_nowait(b'')

	async def channel_data_in(self, datatype:int, data:bytes):
		if datatype is None:
			await self.stdout.put(data)
		else:
			await self.stderr.put(data)
