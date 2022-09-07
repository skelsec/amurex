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
		SSHKEXAlgo.__init__(self, 'diffie-hellman-group14-sha1')
		self.__iteration = 0

		self.hashobj = None
		self.exchange_hash = None #session-id according to the RFC...
		self.shared_secret = None

		self.supported_algos = [
			'diffie-hellman-group16-sha512',
			'diffie-hellman-group14-sha256',
			'diffie-hellman-group14-sha1',
			'diffie-hellman-group1-sha1',
		]



	def get_names(self):
		return self.supported_algos

	async def authenticate(self, selected_method, client_banner, server_banner, client_kex, server_kex, host_key, server_msg = None):
		try:
			if selected_method.lower().startswith('diffie-hellman-group-exchange'):
				return await self.dh_group_exchange(client_banner, server_banner, client_kex, server_kex, host_key, server_msg)
			else:
				print('selected_method: %s' % selected_method)
				selected_method = selected_method.split('@')[0].split('diffie-hellman-group')[1]
				
				gid,hashname  = selected_method.split('-')

				return await self.dh_kex(gid, hashname, client_banner, server_banner, client_kex, server_kex, host_key, server_msg)

		except Exception as e:
			traceback.print_exc()
			return None, True, e

	async def dh_kex(self, gid, hashname, client_banner, server_banner, client_kex, server_kex, host_key, server_msg = None):
		try:
			if self.__iteration == 0 and server_msg is None:
				self.__iteration = 1
				gid = int(gid)
				print('gid: %s' % gid)
				self.p = int.from_bytes(DHPRIMES[gid], byteorder='big', signed=False)
				self.g = 2
				print(self.p.bit_length()//8)
				self.x = int.from_bytes(os.urandom(8), byteorder='big', signed=False)
				self.e = pow(self.g,self.x,self.p)
				print('e: %s' % self.e)
				print('P: %s' % self.p)

				msg = SSH2_MSG_KEXDH_INIT(self.e)
				return msg.to_bytes(), False, None

			if self.__iteration == 1:
				if server_msg is None:
					raise Exception('Server message is empty?!')
				
				smsg = SSH2_MSG_KEXDH_REPLY.from_bytes(server_msg)
				print(str(smsg))
				
				print('smsg.f: %s' % smsg.f)
				K = pow(smsg.f, self.x, self.p)
				print('e: %s' % self.e)
				print('K: %s' % hex(K))
				print('P: %s' % self.p)
				print('key: %s' % smsg.pubkey_string)
				self.shared_secret = SSHString.to_bytes(deflate_long(K))

				#### TEST TEST TEST

				self.hashobj = self.hashname_lookup[hashname]
				to_hash = SSHString.to_bytes(client_banner.strip())+\
							SSHString.to_bytes(server_banner.strip())+\
							SSHString.to_bytes(client_kex.rawdata)+\
							SSHString.to_bytes(server_kex.rawdata)+\
							SSHString.to_bytes(smsg.pubkey_string)+\
							SSHString.to_bytes(deflate_long(self.e))+\
							SSHString.to_bytes(deflate_long(smsg.f))+\
							SSHString.to_bytes(deflate_long(K))

				print('')
				print('to_hash: %s' % to_hash.hex())
				print('')

				self.exchange_hash = self.hashobj(
					to_hash	
				).digest()
				print('H: %s' % self.exchange_hash.hex() )
				#await asyncio.sleep(100)
				return None, True, None

		except Exception as e:
			traceback.print_exc()
			return None, True, e

	