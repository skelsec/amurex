import traceback
from typing import List
from amurex.clientconnection import SSHClientConnection
from amurex.channels.ptysession import SSHPTYSession
from amurex.channels.shellsession import SSHShellSession
from amurex.channels.execsession import SSHExecSession
from amurex.channels.sftp import SSHSFTPSession
from amurex.channels.pflocal import SSHLocalPortForward
from amurex.extras.socks import SSHPortfowardDynamicSOCKS
from amurex.extras.pfsocket import SSHPortfowardLocalSocket

from asysocks.unicomm.common.target import UniProto, UniTarget
from amurex.common.settings import SSHClientSettings
from amurex.common.credential import SSHCredentialPrivKey
from amurex.common.credential import SSHCredentialPassword


class SSHClient:
	def __init__(self, connection:SSHClientConnection = None):
		self.connection = connection
		
	@staticmethod
	async def connect(host:str, username:str=None, password:str=None, domain:str = None, private_key:str=None, private_key_passphrase:str=None, known_hosts:str=None, verify:bool = True, timeout:int=10, proxies:List=None, port:int=22):
		"""Connects to a remote SSH server and returns a new SSHClient instance"""
		try:
			target = UniTarget(
				host,
				port,
				UniProto.CLIENT_TCP,
				timeout=timeout,
				proxies=proxies
			)

			if username is not None and password is not None:
				credential = SSHCredentialPassword(username, password, domain=domain)
			elif username is not None and private_key is not None:
				credential = SSHCredentialPrivKey(username, private_key, passphrase=private_key_passphrase, domain=domain)
			else:
				raise Exception('Either username/password or username/private_key must be provided!')
			
			settings = SSHClientSettings()
			if known_hosts is not None:
				settings.known_hosts.load_file(known_hosts)
			settings.skip_hostkey_verification = not verify

			connection = SSHClientConnection([credential], target, settings)
			_, err = await connection.connect()
			if err is not None:
				raise err
			client = SSHClient(connection)
			return client, None
		except Exception as e:
			return None, e
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		if self.connection is not None:
			await self.connection.close()

	async def get_ptysession(self, row_width=80, row_height=24, pixel_width=640, pixel_height=480, term = 'vt100'):
		"""Creates a new PTY session, which can be later used to create a shell session or execute a command"""
		pty = SSHPTYSession(
			None, 
			term = term,
			row_width=row_width, 
			row_height=row_height, 
			pixel_width=pixel_width, 
			pixel_height=pixel_height
		)
		_, err = await self.connection.open_channel_obj(pty)
		if err is not None:
			return None, err
		
		_, err = await pty.channel_init()
		if err is not None:
			return None, err
		return pty, None

	async def get_shell(self):
		"""Creates a new shell session and returns the stdin, stdout, stderr queues"""
		shell = SSHShellSession(None)
		_, err = await self.connection.open_channel_obj(shell)
		if err is not None:
			return None, None, None, err
		_, err = await shell.channel_init()
		if err is not None:
			return None, None, None, err
		return shell.stdin, shell.stdout, shell.stderr, None

	async def get_sftp(self):
		"""Creates a new SFTP session"""
		sftp = SSHSFTPSession(None)
		_, err = await self.connection.open_channel_obj(sftp)
		if err is not None:
			return None, err
		_, err = await sftp.channel_init()
		if err is not None:
			return None, err
		return sftp, None

	async def execute_command_queue(self, cmd):
		"""Creates a new channel and executes the command on the remote server. Returns the stdout, stderr queues"""
		execshell = SSHExecSession(None, cmd)
		_, err = await self.connection.open_channel_obj(execshell)
		if err is not None:
			return None, None, err
		
		_, err = await execshell.channel_init()
		if err is not None:
			return None, None, err
		
		return execshell.stdout, execshell.stderr, None
	
	async def execute_command(self, cmd):
		"""Creates a new channel and executes the command on the remote server. Reads the stdout, stderr queues and returns the results"""
		execshell = SSHExecSession(None, cmd)
		_, err = await self.connection.open_channel_obj(execshell)
		if err is not None:
			return None, None, err
		
		_, err = await execshell.channel_init()
		if err is not None:
			return None, None, err
		
		stdout = b''
		stderr = b''
		while True:
			try:
				data = await execshell.stdout.get()
				if data == b'':
					break
				stdout += data
			except Exception as e:
				break

		while True:
			try:
				data = await execshell.stderr.get()
				if data == b'':
					break
				stderr += data
			except Exception as e:
				break
		
		return stdout, stderr, None


	async def portforward_local_queue(self, raddr:str, rport:int, laddr:str="", lport:int = 0):
		try:
			pfo = SSHLocalPortForward(None, raddr, rport, laddr, lport)
			await self.connection.open_channel_obj(pfo)
			_, err = await pfo.channel_init()
			if err is not None:
				raise err
			return pfo, None
		except Exception as e:
			return False, e
	
	async def portforward_local(self, raddr:str, rport:int, laddr:str="", lport:int = 0):
		try:
			dfo = SSHPortfowardLocalSocket(raddr, rport, laddr, lport, self)
			await dfo.run()
		except Exception as e:
			traceback.print_exc()
			return False, e

	
	async def portforward_dynamic(self, lport:int, laddr:str=''):
		try:
			dfo = SSHPortfowardDynamicSOCKS(laddr, lport, self)
			await dfo.run()
		except Exception as e:
			traceback.print_exc()
			return False, e
		
