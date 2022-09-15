from typing import List
from amurex.common.knownhosts import KnownHosts
from amurex.crypto.compression import AMUREX_COMPRESSION_ALGORITHMS
from amurex.crypto.kex import AMUREX_KEX_ALGORITHMS
from amurex.crypto.mac import AMUREX_MAC_ALGORITHMS
from amurex.crypto.encryption import AMUREX_ENCRYPTION_ALGORITHMS
from amurex.crypto.keys import AMUREX_HOST_KEY_ALGORITHMS

class SSHClientSettings:
	def __init__(self):
		self.banner:str = 'SSH-2.0-AMUREX_0.1'
		self.known_hosts:KnownHosts = KnownHosts()
		self.skip_hostkey_verification:bool = False
		self.kex_algorithms:List[str] = list(AMUREX_KEX_ALGORITHMS.keys())
		self.host_key_algorithms:List[str] = list(AMUREX_HOST_KEY_ALGORITHMS.keys())
		self.encryption_algorithms:List[str] = list(AMUREX_ENCRYPTION_ALGORITHMS.keys())
		self.encryption_algorithms:List[str] = list(AMUREX_ENCRYPTION_ALGORITHMS.keys())
		self.mac_algorithms:List[str] = list(AMUREX_MAC_ALGORITHMS.keys())
		self.compression_algorithms:List[str] = list(AMUREX_COMPRESSION_ALGORITHMS.keys())
		self.languages:List[str] = []

	def get_banner(self):
		return self.banner.encode() + b'\r\n'