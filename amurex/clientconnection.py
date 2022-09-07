import copy
import asyncio
import traceback
from typing import Dict
from amurex import logger
from amurex.protocol.packetizer import SSHPacketizer
from amurex.protocol.messages import SSH_MSG_USERAUTH_REQUEST, parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, \
	SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_REQUEST_PASSWORD
from asysocks.unicomm.common.packetizers import Packetizer

from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.target import UniProto, UniTarget

### will not be here!
from amurex.crypto.compression import AMUREX_COMPRESSION_ALGORITHMS
from amurex.crypto.kex import AMUREX_KEX_ALGORITHMS
from amurex.crypto.mac import AMUREX_MAC_ALGORITHMS
from amurex.crypto.encryption import AMUREX_ENCRYPTION_ALGORITHMS
from amurex.crypto.keys import AMUREX_HOST_KEY_ALGORITHMS
from amurex.channels import SSHChannel
from amurex.channels.ptysession import SSHPTYSession
from amurex.channels.shellsession import SSHShellSession
from amurex.channels.execsession import SSHExecSession


class SSHClientConnection:
	def __init__(self, credential, target:UniTarget):
		self.target = target
		self.credential = credential
		self.__packetizer = SSHPacketizer()
		self.__connection = None
		self.__incoming_task = None

		self.__kex_algorithms = []
		self.__host_key_algorithms = []
		self.__encryption_algorithms = []
		self.__compression_algorithms = []
		self.__languages = []
		self.__channels:Dict[int,SSHChannel] = {}
		self.__channelid_ctr = 10

		self.banner = b'SSH-2.0-AMUREX_0.1\r\n'
		self.__server_banner = None

		self.__kex_algo = None
		self.__kex_algo_name = None
		self.__hostkey_algo = None
		self.__hostkey_algo_name = None
		self.__encryption_client_to_server = None
		self.__encryption_server_to_client = None
		self.__mac_client_to_server = None
		self.__mac_server_to_client = None
		self.__compression_client_to_server = None
		self.__compression_server_to_client = None
		self.__language_client_to_server = None
		self.__language_server_to_client = None

		self.client_to_server_init_IV = None
		self.server_to_client_init_IV = None
		self.client_to_server_cipher_key = None
		self.server_to_client_cipher_key = None
		self.client_to_server_integrity_key = None
		self.server_to_client_integrity_key = None

	async def __handle_in(self):
		try:
			async for payload in self.__connection.read():
				msgtype, smsg = parse_ssh_payload(payload, None)
				print('INCOMING msgtype: %s' % msgtype)
				print('message msgtype: %s' % str(smsg))
				if msgtype == SSHMessageNumber.SSH_MSG_GLOBAL_REQUEST:
					_, err = await self.__process_global_request(smsg)
					if err is not None:
						raise err
				elif msgtype in [
							SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
							SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE,
							SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST,
							SSHMessageNumber.SSH_MSG_CHANNEL_DATA,
							SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA,
							SSHMessageNumber.SSH_MSG_CHANNEL_EOF,
							SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE,
							SSHMessageNumber.SSH_MSG_CHANNEL_OPEN,
							SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE,
							SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
						]:
					if smsg.recipient not in self.__channels:
						print('Missing recipientid "%s"' % smsg.recipient)
						continue
					await self.__channels[smsg.recipient].msg_in(msgtype, smsg)

		except Exception as e:
			traceback.print_exc()

	async def connect(self, noauth = False):
		try:
			client = UniClient(self.target, Packetizer())
			self.__connection = await client.connect()

			_, err = await self.banner_exchange()
			if err is not None:
				raise err

			self.__connection.change_packetizer(SSHPacketizer())

			_, err = await self.key_exchange()
			if err is not None:
				raise err

			if noauth is True:
				return True, None
			
			_, err = await self.authenticate()
			if err is not None:
				raise err

			self.__incoming_task = asyncio.create_task(self.__handle_in())
		
			return True, None
		except Exception as e:
			return None, e

	async def banner_exchange(self):
		try:
			await self.__connection.write(self.banner)
			self.__server_banner = await self.__connection.read_one()
			return True, None
		except Exception as e:
			return False, e

	def calculate_key(self, keyid:bytes, keysize:int):
		if len(keyid) != 1 or keyid not in [b'A',b'B',b'C',b'E',b'D',b'F']:
			raise ValueError('keyid must be 1 bytes long in the range of ABCDEF')
		K = self.__kex_algo.shared_secret
		H = self.__kex_algo.exchange_hash
		session_id = self.__kex_algo.exchange_hash
		result = self.__kex_algo.hashobj(K + H + keyid + session_id).digest()
		while len(result) < keysize:
			result += self.__kex_algo.hashobj(K + H + result).digest()
		return result[:keysize]

	async def open_channel_obj(self, channelobj):
		try:
			recipientid = self.__channelid_ctr
			self.__channelid_ctr += 1
			channelobj.recipientid = recipientid
			channelobj.connection = self.__connection
			self.__channels[recipientid] = channelobj

			print('Sending chennl open...')
			print(channelobj.get_channel_open())
			await self.__connection.write(channelobj.get_channel_open())

			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e

	async def open_channel(self, channel_type):
		try:
			if channel_type == 'pty':
				print('pty')
				await self.open_channel_obj(SSHPTYSession(None))
			elif channel_type == 'shell':
				print('shell')
				await self.open_channel_obj(SSHShellSession(None))

			elif channel_type == 'exec':
				print('exec')
				await self.open_channel_obj(SSHExecSession(None))


			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e

	async def key_exchange(self):
		try:
			self.__kex_algorithms = list(AMUREX_KEX_ALGORITHMS.keys())
			self.__host_key_algorithms = list(AMUREX_HOST_KEY_ALGORITHMS.keys())
			self.__encryption_algorithms = list(AMUREX_ENCRYPTION_ALGORITHMS.keys())
			self.__encryption_algorithms = list(AMUREX_ENCRYPTION_ALGORITHMS.keys())
			self.__mac_algorithms = list(AMUREX_MAC_ALGORITHMS.keys())
			self.__compression_algorithms = list(AMUREX_COMPRESSION_ALGORITHMS.keys())
			self.__languages = []

			client_kex = SSH_MSG_KEXINIT(
				self.__kex_algorithms,
				self.__host_key_algorithms,
				self.__encryption_algorithms,
				self.__encryption_algorithms,
				self.__mac_algorithms,
				self.__mac_algorithms,
				self.__compression_algorithms,
				self.__compression_algorithms,
				self.__languages,
				self.__languages,
			)
			
			await self.__connection.write(client_kex.to_bytes())
			server_kex_data = await self.__connection.read_one()
			server_kex = SSH_MSG_KEXINIT.from_bytes(server_kex_data)

			for algo in client_kex.kex_algorithms:
				if algo in server_kex.kex_algorithms:
					self.__kex_algo = AMUREX_KEX_ALGORITHMS[algo]()
					self.__kex_algo_name = algo
					break
			else:
				raise Exception('No common KEX algorithm with server!')
			
			for algo in client_kex.server_host_key_algorithms:
				if algo in server_kex.server_host_key_algorithms:
					# when we get to implement it...
					#self.__hostkey_algo = AMUREX_HOST_KEY_ALGORITHMS[algo]()
					self.__hostkey_algo_name = algo
					break
			else:
				raise Exception('No common Key algorithm with server!')
			
			for algo in client_kex.encryption_algorithms_client_to_server:
				if algo in server_kex.encryption_algorithms_client_to_server:
					self.__encryption_client_to_server = AMUREX_ENCRYPTION_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Client-to-Server encryption algorithm with server!')
			
			for algo in client_kex.encryption_algorithms_server_to_client:
				if algo in client_kex.encryption_algorithms_server_to_client:
					self.__encryption_server_to_client = AMUREX_ENCRYPTION_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Server-to-Client encryption algorithm with server!')
			
			
			for algo in client_kex.mac_algorithms_client_to_server:
				if algo in server_kex.mac_algorithms_client_to_server:
					self.__mac_client_to_server = AMUREX_MAC_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Client-to-Server MAC algorithm with server!')
			
			for algo in client_kex.mac_algorithms_server_to_client:
				if algo in server_kex.mac_algorithms_server_to_client:
					self.__mac_server_to_client = AMUREX_MAC_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Server-to-Client MAC algorithm with server!')

			
			for algo in client_kex.compression_algorithms_client_to_server:
				if algo in server_kex.compression_algorithms_client_to_server:
					self.__compression_client_to_server = AMUREX_COMPRESSION_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Client-to-Server compression algorithm with server!')
			
			for algo in client_kex.compression_algorithms_server_to_client:
				if algo in server_kex.compression_algorithms_server_to_client:
					self.__compression_server_to_client = AMUREX_COMPRESSION_ALGORITHMS[algo]()
					break
			else:
				raise Exception('No common Server-to-Client compression algorithm with server!')

			for algo in client_kex.languages_client_to_server:
				if algo in server_kex.languages_client_to_server:
					self.__language_client_to_server = algo
					break
			
			for algo in client_kex.languages_server_to_client:
				if algo in client_kex.languages_server_to_client:
					self.__language_server_to_client = algo
					break


			self.__kex_algo.init(self.__kex_algo_name, self.banner, self.__server_banner, client_kex, server_kex, None)
			srv_msg = None
			for _ in range(255): #adding a max limit of 255 steps for KEX
				authmsg, is_done, err = await self.__kex_algo.authenticate(srv_msg)
				if err is not None:
					raise err
				if is_done is True:
					break

				await self.__connection.write(authmsg)
				srv_msg = await self.__connection.read_one()

			
			# calculating keys
			self.client_to_server_init_IV       = self.calculate_key(b'A', self.__encryption_client_to_server.ivsize)
			self.server_to_client_init_IV       = self.calculate_key(b'B', self.__encryption_server_to_client.ivsize)
			self.client_to_server_cipher_key    = self.calculate_key(b'C', self.__encryption_client_to_server.keysize)
			self.server_to_client_cipher_key    = self.calculate_key(b'D', self.__encryption_server_to_client.keysize)
			self.client_to_server_integrity_key = self.calculate_key(b'E', self.__mac_client_to_server.blocksize)
			self.server_to_client_integrity_key = self.calculate_key(b'F', self.__mac_server_to_client.blocksize)
			
			logger.debug('client_to_server_init_IV       : %s' % self.client_to_server_init_IV.hex())
			logger.debug('server_to_client_init_IV       : %s' % self.server_to_client_init_IV.hex())
			logger.debug('client_to_server_cipher_key    : %s' % self.client_to_server_cipher_key.hex())
			logger.debug('server_to_client_cipher_key    : %s' % self.server_to_client_cipher_key.hex())
			logger.debug('client_to_server_integrity_key : %s' % self.client_to_server_integrity_key.hex())
			logger.debug('server_to_client_integrity_key : %s' % self.server_to_client_integrity_key.hex())

			# initializing ciphers
			self.__encryption_client_to_server.init_keys(self.client_to_server_cipher_key, self.client_to_server_init_IV)
			self.__encryption_server_to_client.init_keys(self.server_to_client_cipher_key, self.server_to_client_init_IV)
			self.__mac_client_to_server.init_keys(self.client_to_server_integrity_key)
			self.__mac_server_to_client.init_keys(self.server_to_client_integrity_key)

			# signaling that KEX is complete and we can start encrypting all messages
			await self.__connection.write(SSH_MSG_NEWKEYS().to_bytes())
			srv_msg = await self.__connection.read_one()
			smsg = SSH_MSG_NEWKEYS.from_bytes(srv_msg)

			# setting crypto stuff to packetzier
			self.__connection.packetizer.client_to_server_enc = self.__encryption_client_to_server
			self.__connection.packetizer.server_to_client_enc = self.__encryption_server_to_client
			self.__connection.packetizer.client_to_server_mac = self.__mac_client_to_server
			self.__connection.packetizer.server_to_client_mac = self.__mac_server_to_client
			self.__connection.packetizer.client_to_server_compression = self.__compression_client_to_server
			self.__connection.packetizer.server_to_client_compression = self.__compression_server_to_client
	
			return True, None
		except Exception as e:
			return False, e

	async def list_authentication_methods(self):
		try:
			result = []
			await self.__connection.write(SSH_MSG_SERVICE_REQUEST('ssh-userauth').to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT)

			await self.__connection.write(SSH_MSG_USERAUTH_REQUEST('', 'ssh-userauth', 'none').to_bytes())
			srvmsg = await self.__connection.read_one()
			print('srvmsg: %s' % srvmsg)
			
			msgtype, smsg = parse_ssh_payload(srvmsg, None)

			if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:
				print('User is not reuired to perform authentication!')
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
				result = smsg.authmethods

			print(result)

			return result, None

		except Exception as e:
			traceback.print_exc()
			return False, e

	async def authenticate(self):
		try:
			_, err = await self.authenticate_password()
			if err is not None:
				raise err

			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e

	async def authenticate_password(self):
		try:
			username = 'webdev'
			password = 'webdev'
			await self.__connection.write(SSH_MSG_SERVICE_REQUEST('ssh-userauth').to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT)
			await self.__connection.write(SSH_MSG_USERAUTH_REQUEST_PASSWORD(username, 'ssh-connection', password).to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, None)
			if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:
				print('Auth okay!')
				return True, None
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
				print('Auth failed!')
				return False, Exception('Authentication failed!')
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
				print('Password must be changed!')
				raise NotImplementedError()
			
			raise Exception('Unexpected message incoming! %s' % msgtype)
		except Exception as e:
			traceback.print_exc()
			return False, e

	async def __process_global_request(self, msg):
		try:
			print(msg)

			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e
		

async def amain():
	target = UniTarget(
		'127.0.0.1',
		22,
		UniProto.CLIENT_TCP
	)

	sshcli = SSHClientConnection(None, target)
	_, err = await sshcli.connect()
	if err is not None:
		raise err
	print('Connect Done!')
	await sshcli.open_channel('shell')
	while True:
		await asyncio.sleep(10)

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()