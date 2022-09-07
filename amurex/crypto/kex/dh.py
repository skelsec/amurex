import traceback
import os
import asyncio

from amurex.crypto.kex import SSHKEXAlgo
from unicrypto.hashlib import sha1, sha256, sha512
from amurex.crypto.kex.dhprimes import DHPRIMES
from amurex.crypto.mpint import deflate_long, inflate_long
from amurex.protocol.messages import SSH2_MSG_KEXDH_INIT, SSH2_MSG_KEXDH_REPLY, SSHString

#diffie-hellman-group-exchange-sha256,
#diffie-hellman-group16-sha512,
#diffie-hellman-group18-sha512,
#diffie-hellman-group14-sha256,
#

# https://www.ietf.org/rfc/rfc4419.txt
# https://datatracker.ietf.org/doc/html/rfc4253

class SSHKEXDH(SSHKEXAlgo):
	def __init__(self):
		self.supported_hashes = ['sha1', 'sha256', 'sha512']
		self.supported_groups = [str(gid) for gid in DHPRIMES]
		self.hashname_lookup = {
			'sha1':sha1,
			'sha256':sha256,
			'sha512':sha512
		}
		SSHKEXAlgo.__init__(self)
		self.__iteration = 0

		self.hashobj = None
		self.exchange_hash = None #session-id according to the RFC...
		self.shared_secret = None

	def init(self, selected_method, client_banner, server_banner, client_kex, server_kex, host_key):
		self.selected_method = selected_method
		self.client_banner = client_banner
		self.server_banner = server_banner
		self.client_kex = client_kex
		self.server_kex = server_kex
		self.host_key = host_key

		selected_method = selected_method.split('@')[0].split('diffie-hellman-group')[1]
		self.gid, self.hashname  = selected_method.split('-')
		self.gid = int(self.gid)
		self.hashobj = self.hashname_lookup[self.hashname]

	async def authenticate(self, server_msg = None):
		try:
			if self.selected_method.lower().startswith('diffie-hellman-group-exchange'):
				return await self.dh_group_exchange(server_msg)
			else:
				return await self.dh_kex(server_msg)

		except Exception as e:
			traceback.print_exc()
			return None, True, e

	async def dh_kex(self, server_msg = None):
		try:
			if self.__iteration == 0 and server_msg is None:
				self.__iteration = 1
				self.p = int.from_bytes(DHPRIMES[self.gid], byteorder='big', signed=False)
				self.g = 2
				print(self.p.bit_length()//8)
				self.x = int.from_bytes(os.urandom(8), byteorder='big', signed=False)
				self.e = pow(self.g,self.x,self.p)

				msg = SSH2_MSG_KEXDH_INIT(self.e)
				return msg.to_bytes(), False, None

			if self.__iteration == 1:
				if server_msg is None:
					raise Exception('Server message is empty?!')
				
				smsg = SSH2_MSG_KEXDH_REPLY.from_bytes(server_msg)				
				K = pow(smsg.f, self.x, self.p)
				self.shared_secret = SSHString.to_bytes(deflate_long(K))

				to_hash =   SSHString.to_bytes(self.client_banner.strip())+\
							SSHString.to_bytes(self.server_banner.strip())+\
							SSHString.to_bytes(self.client_kex.rawdata)+\
							SSHString.to_bytes(self.server_kex.rawdata)+\
							SSHString.to_bytes(smsg.pubkey_string)+\
							SSHString.to_bytes(deflate_long(self.e))+\
							SSHString.to_bytes(deflate_long(smsg.f))+\
							self.shared_secret

				self.exchange_hash = self.hashobj(to_hash).digest()
				return None, True, None

		except Exception as e:
			traceback.print_exc()
			return None, True, e

	