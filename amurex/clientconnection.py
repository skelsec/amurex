import asyncio
import io
import traceback
from typing import Dict, List
from amurex.protocol.packetizer import SSHPacketizer
from amurex.protocol.messages import SSHString, SSH_MSG_USERAUTH_REQUEST,\
	parse_ssh_payload, SSHMessageNumber, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS,\
	SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_REQUEST_PASSWORD,\
	SSH_MSG_USERAUTH_PK_OK
from asysocks.unicomm.common.packetizers import Packetizer

from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.target import UniProto, UniTarget
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret

from amurex import logger
from amurex.crypto.compression import AMUREX_COMPRESSION_ALGORITHMS
from amurex.crypto.kex import AMUREX_KEX_ALGORITHMS
from amurex.crypto.mac import AMUREX_MAC_ALGORITHMS
from amurex.crypto.encryption import AMUREX_ENCRYPTION_ALGORITHMS
from amurex.crypto.keys import AMUREX_HOST_KEY_ALGORITHMS
from amurex.channels import SSHChannel
from amurex.common.settings import SSHClientSettings


class SSHClientConnection:
	def __init__(self, credentials:List[UniCredential], target:UniTarget, settings: SSHClientSettings):
		self.target = target
		self.credentials:List[UniCredential] = credentials
		self.settings = settings
		self.__connection = None
		self.connected_evt = asyncio.Event()
		self.__incoming_task = None

		self.__channels:Dict[int,SSHChannel] = {}
		self.__channelid_ctr = 10

		self.__client_banner = self.settings.get_banner()
		self.__server_banner = None

		self.__kex_algo = None
		self.__kex_algo_name = None
		self.__hostkey_algo = None
		self.__encryption_client_to_server = None
		self.__encryption_server_to_client = None
		self.__mac_client_to_server = None
		self.__mac_server_to_client = None
		self.__compression_client_to_server = None
		self.__compression_server_to_client = None
		self.__language_client_to_server = None
		self.__language_server_to_client = None
		self.__server_kex_packet = None #for security tests

		self.client_to_server_init_IV = None
		self.server_to_client_init_IV = None
		self.client_to_server_cipher_key = None
		self.server_to_client_cipher_key = None
		self.client_to_server_integrity_key = None
		self.server_to_client_integrity_key = None
		self.session_id = None

		if isinstance(self.credentials, list) is False:
			self.credentials = [self.credentials]

	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
	
	async def close(self):
		for channel in self.__channels:
			await self.__channels[channel].close()
		if self.__connection is not None:
			await self.__connection.close()
		if self.__incoming_task is not None:
			self.__incoming_task.cancel()

	async def __handle_in(self):
		try:
			async for payload in self.__connection.read():
				if payload is None:
					break
				msgtype, smsg = parse_ssh_payload(payload, None)
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
							SSHMessageNumber.SSH_MSG_CHANNEL_SUCCESS,
							SSHMessageNumber.SSH_MSG_CHANNEL_FAILURE,
						]:
					if smsg.recipient not in self.__channels:
						print('Missing recipientid "%s"' % smsg.recipient)
						continue
					asyncio.create_task(self.__channels[smsg.recipient].msg_in(msgtype, smsg))
				elif msgtype == SSHMessageNumber.SSH_MSG_IGNORE:
					continue
				elif msgtype == SSHMessageNumber.SSH_MSG_DEBUG:
					continue
				elif msgtype == SSHMessageNumber.SSH_MSG_DISCONNECT:
					logger.debug('Server is terminating the connection!')
					return
				elif msgtype == SSHMessageNumber.SSH_MSG_KEXINIT:
					logger.debug('Server wants a rekey! TODO!!!1')
				else:
					logger.debug('Unknown message type recieved: %s' % msgtype)

			#print('END?')
		except Exception as e:
			traceback.print_exc()
		finally:
			await self.close()

	def get_server_banner(self):
		return self.__server_banner

	async def connect(self, noauth = False):
		try:
			logger.debug('Connecting to server')
			client = UniClient(self.target, Packetizer())
			self.__connection = await client.connect()
			
			logger.debug('Connection OK')

			logger.debug('Banner exchange')
			_, bufferdata, err = await self.banner_exchange()
			if err is not None:
				logger.debug('Banner exchange FAILED')
				raise err
			logger.debug('Banner exchange OK')

			self.__connection.change_packetizer(SSHPacketizer(init_buffer=bufferdata))
			logger.debug('Key exchange')
			_, err = await self.key_exchange()
			if err is not None:
				logger.debug('Key exchange FAILED')
				raise err
			logger.debug('Key exchange OK')

			if noauth is True:
				return self.__server_kex_packet, None
			
			logger.debug('Authenticating to server')
			_, err = await self.authenticate()
			if err is not None:
				raise err
			logger.debug('Authentication OK')

			self.__incoming_task = asyncio.create_task(self.__handle_in())
			self.connected_evt.set()

			logger.debug('SSH connection OK')
			return True, None
		except Exception as e:
			return None, e

	async def banner_exchange(self):
		try:
			await self.__connection.write(self.__client_banner)
			rawbuffer = await self.__connection.read_one()
			linemarker = rawbuffer.find(b'\n')
			self.__server_banner = rawbuffer[:linemarker+1]
			logger.debug('Server banner: %s' % self.__server_banner)
			return True, rawbuffer[linemarker+1:], None
		except Exception as e:
			return False, e

	def calculate_key(self, keyid:bytes, keysize:int):
		if len(keyid) != 1 or keyid not in [b'A',b'B',b'C',b'E',b'D',b'F']:
			raise ValueError('keyid must be 1 bytes long in the range of ABCDEF')
		K = self.__kex_algo.shared_secret
		H = self.__kex_algo.exchange_hash
		result = self.__kex_algo.hashobj(K + H + keyid + self.session_id).digest()
		while len(result) < keysize:
			result += self.__kex_algo.hashobj(K + H + result).digest()
		return result[:keysize]

	async def open_channel_obj(self, channelobj:SSHChannel):
		try:
			recipientid = self.__channelid_ctr
			self.__channelid_ctr += 1
			channelobj.recipientid = recipientid
			channelobj.connection = self.__connection
			self.__channels[recipientid] = channelobj
			await self.__connection.write(channelobj.get_channel_open())
			await channelobj.channel_setup_completed_evt.wait()
			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e
	
	async def key_exchange(self):
		try:
			client_kex = SSH_MSG_KEXINIT(
				self.settings.kex_algorithms,
				self.settings.host_key_algorithms,
				self.settings.encryption_algorithms,
				self.settings.encryption_algorithms,
				self.settings.mac_algorithms,
				self.settings.mac_algorithms,
				self.settings.compression_algorithms,
				self.settings.compression_algorithms,
				self.settings.languages,
				self.settings.languages,
			)
			
			await self.__connection.write(client_kex.to_bytes())
			logger.debug('Reading server KEX init')
			server_kex_data = await self.__connection.read_one()
			server_kex = SSH_MSG_KEXINIT.from_bytes(server_kex_data)
			self.__server_kex_packet = server_kex
			logger.debug('Server KEX init message ok')
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
					self.__hostkey_algo = AMUREX_HOST_KEY_ALGORITHMS[algo]()
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

			logger.debug('Starting KEX crypto part')
			self.__kex_algo.init(self.__kex_algo_name, self.__client_banner, self.__server_banner, client_kex, server_kex, None)
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
			if self.session_id is None:
				# for rekeying purposes the sessionid is the same as before!
				self.session_id = self.__kex_algo.exchange_hash

				self.__hostkey_algo.load_pubkey_bytes(self.__kex_algo.certificate)
				server_keytype, server_pubkey = self.__hostkey_algo.to_knownhostline()
				res = self.settings.known_hosts.verify_certificate(self.target.get_hostname_or_ip(), server_keytype, server_pubkey)
				if res is False:
					if self.settings.skip_hostkey_verification is not True:
						raise Exception('Host key verification failed!')

				res = self.__hostkey_algo.verify_server_signature(self.__kex_algo.signature, self.__kex_algo.exchange_hash)
				if res is not True:
					raise Exception('Host session signature verification failed!')

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
			msgtype, smsg = parse_ssh_payload(srvmsg, None)

			if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:
				print('User is not reuired to perform authentication!')
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
				result = smsg.authmethods

			return result, None

		except Exception as e:
			return False, e

	async def authenticate(self):
		try:
			for credential in self.credentials:
				if credential.stype == asyauthSecret.PASSWORD:
					res, err = await self.authenticate_password(credential.username, credential.secret)
					if res is True:
						break
				elif credential.stype == asyauthSecret.SSHPRIVKEY:
					res, err = await self.authenticate_privkey(credential)
					if res is True:
						break
			else:
				raise Exception('Authentication failed!')
			
			return True, None
		except Exception as e:
			return False, e

	async def authenticate_privkey(self, credential):
		try:
			key = credential.build_context()
			await self.__connection.write(SSH_MSG_SERVICE_REQUEST('ssh-userauth').to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT)
			initial_req = SSH_MSG_USERAUTH_REQUEST(
				credential.username, 
				'ssh-connection', 
				'publickey',
				b'\x00' + key.to_pubkeyblob()
			).to_bytes()
			await self.__connection.write(initial_req)

			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg)
			if msgtype.value != 60:
				if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
					raise Exception('Pubkey auth failed')
				else:
					raise Exception('Pubkey auth failed. Server sent incorrect message %s' % msgtype.name)
			
			#reparsing it because the "unique" message id collides with another... :(
			smsg = SSH_MSG_USERAUTH_PK_OK.from_bytes(srvmsg)
			ssid = SSHString.to_bytes(self.session_id)
			to_sign  = ssid
			to_sign += b'\x32' #SSH_MSG_SERVICE_ACCEPT
			to_sign += SSHString.to_bytes(credential.username)
			to_sign += SSHString.to_bytes('ssh-connection')
			to_sign += SSHString.to_bytes('publickey')
			to_sign += b'\x01'
			to_sign += key.to_pubkeyblob()
			
			# the signature data is the same what we want to send next except the beginning
			# we detach the beginning and append the signature at the bottom and boom!
			authreq = to_sign[len(ssid):] + SSHString.to_bytes(key.sign(to_sign, smsg.keytype))

			await self.__connection.write(authreq)
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg)
			if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:
				return True, None
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
				# either actually fail or more auth steps needed, but currently we don't have such 
				# auth algos implemented, so we just fail
				return False, Exception('User auth failed!')
			
			raise Exception('Unexpected server reply: %s' % msgtype)

		except Exception as e:
			return False, e

	async def authenticate_password(self, username, password):
		try:
			logger.debug('Plaintext authentication started')
			await self.__connection.write(SSH_MSG_SERVICE_REQUEST('ssh-userauth').to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT)
			await self.__connection.write(SSH_MSG_USERAUTH_REQUEST_PASSWORD(username, 'ssh-connection', password).to_bytes())
			srvmsg = await self.__connection.read_one()
			msgtype, smsg = parse_ssh_payload(srvmsg, None)
			if msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:
				logger.debug('Plaintext authentication success')
				return True, None
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:
				logger.debug('Bad username or password')
				return False, Exception('Authentication failed!')
			elif msgtype == SSHMessageNumber.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
				# TODO
				logger.debug('Password must be changed! This is not implemented!!!')
				raise NotImplementedError()
			
			raise Exception('Unexpected message incoming! %s' % msgtype)
		except Exception as e:
			return False, e

	async def __process_global_request(self, msg):
		try:
			if msg.requestname == 'hostkeys-00@openssh.com':
				data = io.BytesIO(msg.data)
				for _ in range(10):
					pubkeydata = SSHString.from_buff(data)
					if pubkeydata is None:
						break
					#TODO: implement this if needed

			else:
				print(msg)

			return True, None
		except Exception as e:
			traceback.print_exc()
			return False, e
		
