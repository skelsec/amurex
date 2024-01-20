import copy
from asyauth.common.credentials import UniCredential
from amurex.common.target import SSHTarget
from amurex.common.credential import SSHCredentialPrivKey, SSHCredentialPassword
from amurex.clientconnection import SSHClientConnection
from amurex.client import SSHClient
from amurex.common.settings import SSHClientSettings
from urllib.parse import urlparse, parse_qs


class SSHConnectionFactory:
	def __init__(self, credential:UniCredential = None, target:SSHTarget = None):
		self.credential = credential
		self.target = target
		self.proxies= None
		
	@staticmethod
	def from_url(connection_url:str):
		"""Creates SSHConnectionFactory from url string"""
		url_e = urlparse(connection_url)
		target = SSHTarget.from_url(connection_url)
		
		username = url_e.username
		password = url_e.password
		domain = None
		if username is not None:
			if username.find('\\') != -1:
				domain, username = username.split('\\')
				if domain == '.':
					domain = None
			else:
				domain = None
				username = username
		else:
			raise Exception('Username must be provided!')
		
		query = parse_qs(url_e.query)
		privkey = None
		if 'privkey' in query:
			privkey = query['privkey'][0]


		schemes = url_e.scheme.upper().split('+')		
		if 'KEY' in schemes or 'PRIVKEY' in schemes:
			if privkey is None:
				raise Exception('Private key must be provided!')
			credential = SSHCredentialPrivKey(username, privkey, password, domain = domain)
		if 'PASS' in schemes or 'PASSWORD' in schemes:
			credential = SSHCredentialPassword(username, password, domain = domain)

		return SSHConnectionFactory(credential, target)
	
	def get_connection(self):
		"""Creates a new SMBConnection object"""
		cred = self.get_credential()
		target = self.get_target()
		settings = SSHClientSettings()
		settings.skip_hostkey_verification = True
		
		return SSHClientConnection([cred], target, settings)
	
	def get_client(self):
		connection = self.get_connection()
		return SSHClient(connection)
	
	def create_connection_newtarget(self, ip_or_hostname):
		target = self.get_target()
		target.get_newtarget(ip_or_hostname)

	def get_proxies(self):
		"""Returns a copy of proxies from the target object"""
		return copy.deepcopy(self.target.proxies)

	def get_target(self):
		"""Returns a copy of the target object"""
		return copy.deepcopy(self.target)

	def get_credential(self):
		"""Returns a new SSHCredetial object with the credential from the factory"""
		return copy.deepcopy(self.credential)
