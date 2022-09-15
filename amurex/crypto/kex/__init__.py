from typing import Dict
from amurex.protocol.messages import SSH2_MSG_KEXDH_INIT

class SSHKEXAlgo:
	def __init__(self):
		self.shared_secret = None
		self.exchange_hash = None

		self.certificate = None
		self.signature = None

	def init(self, selected_method:str, client_banner:bytes, server_banner:bytes, client_kex:SSH2_MSG_KEXDH_INIT, server_kex:SSH2_MSG_KEXDH_INIT, host_key:bytes):
		raise NotImplementedError()

	async def authenticate(self, selected_method, client_banner, server_banner, client_kex, server_kex, host_key, server_msg = None):
		raise NotImplementedError()

from amurex.crypto.kex.dh import SSHKEXDH
from amurex.crypto.kex.curve25519 import SSHKEXCurve25519
from amurex.crypto.kex.nistp256 import SSHKEXNISTP256
from amurex.crypto.kex.nistp384 import SSHKEXNISTP384
from amurex.crypto.kex.nistp521 import SSHKEXNISTP521


AMUREX_KEX_ALGORITHMS:Dict[str, SSHKEXAlgo] = {
	'curve25519-sha256@libssh.org': SSHKEXCurve25519,
	'curve25519-sha256': SSHKEXCurve25519,
	#'ecdh-sha2-nistp521' : SSHKEXNISTP521,
	#'ecdh-sha2-nistp384' : SSHKEXNISTP384,
	#'ecdh-sha2-nistp256' : SSHKEXNISTP256,
	#'diffie-hellman-group18-sha512': SSHKEXDH,
	#'diffie-hellman-group16-sha512': SSHKEXDH,
	#'diffie-hellman-group14-sha256': SSHKEXDH,
	#'diffie-hellman-group14-sha1': SSHKEXDH,
	#'diffie-hellman-group1-sha1': SSHKEXDH
}