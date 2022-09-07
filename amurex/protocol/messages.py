
import io
import os
import enum
from amurex.crypto.mpint import inflate_long, deflate_long

class SSHMessageNumber(enum.Enum):
	SSH_MSG_DISCONNECT = 1
	SSH_MSG_IGNORE=2
	SSH_MSG_UNIMPLEMENTED=3
	SSH_MSG_DEBUG=4
	SSH_MSG_SERVICE_REQUEST=5
	SSH_MSG_SERVICE_ACCEPT=6

	SSH_MSG_KEXINIT=20
	SSH_MSG_NEWKEYS=21
	
	SSH2_MSG_KEXDH_INIT = 30
	SSH2_MSG_KEXDH_REPLY = 31
	
	SSH_MSG_USERAUTH_REQUEST = 50
	SSH_MSG_USERAUTH_FAILURE = 51
	SSH_MSG_USERAUTH_SUCCESS = 52
	SSH_MSG_USERAUTH_BANNER = 53
	SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60

	SSH_MSG_GLOBAL_REQUEST = 80
	SSH_MSG_REQUEST_SUCCESS = 81
	SSH_MSG_REQUEST_FAILURE = 82
	SSH_MSG_CHANNEL_OPEN = 90
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
	SSH_MSG_CHANNEL_OPEN_FAILURE = 92
	SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
	SSH_MSG_CHANNEL_DATA = 94
	SSH_MSG_CHANNEL_EXTENDED_DATA = 95
	SSH_MSG_CHANNEL_EOF = 96
	SSH_MSG_CHANNEL_CLOSE = 97
	SSH_MSG_CHANNEL_REQUEST = 98
	SSH_MSG_CHANNEL_SUCCESS = 99
	SSH_MSG_CHANNEL_FAILURE = 100

def parse_ssh_payload(payload:bytes, expected:SSHMessageNumber = None):
	msgtype = SSHMessageNumber(payload[0])
	if expected is not None and msgtype != expected:
		raise Exception('SSH Message type "%s" is not expected! Expectation: %s' % (msgtype, expected))
	if msgtype not in ssh_payload_type_lookup:
		raise ValueError('SSH Message type "%s" is not known' % msgtype)
	if ssh_payload_type_lookup[msgtype] is None:
		return msgtype, None
	return msgtype, ssh_payload_type_lookup[msgtype].from_bytes(payload)

class SSHString:
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff, as_string = False):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		data = buff.read(length)
		if as_string is True:
			return data.decode()
		return data
		
	@staticmethod
	def to_bytes(s):
		if not s:
			return b''
		data = s
		if isinstance(s, str):
			data = s.encode()
		length = len(data).to_bytes(4, byteorder="big", signed = False)
		return length + data

class SSHBytes:
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		return buff.read(length)
		
	@staticmethod
	def to_bytes(s):
		if not s:
			data = b''
			return len(data).to_bytes(4, byteorder="big", signed = False)
		
		length = len(s).to_bytes(4, byteorder="big", signed = False)
		return length + s

class NameList:
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return []
		data = buff.read(length).decode()
		return data.split(',')
		
	@staticmethod
	def to_bytes(lst):
		if len(lst) == 0:
			return len(lst).to_bytes(4, byteorder="big", signed = False)
		data = ','.join(lst)
		data = data.encode()
		length = len(data).to_bytes(4, byteorder="big", signed = False)
		return length + data

class SSH_MSG_KEXINIT:
	def __init__(self, kex_algorithms, server_host_key_algorithms, encryption_algorithms_client_to_server,
					encryption_algorithms_server_to_client, mac_algorithms_client_to_server, mac_algorithms_server_to_client,
					compression_algorithms_client_to_server, compression_algorithms_server_to_client, languages_client_to_server,
					languages_server_to_client, first_kex_packet_follows = False, cookie = None, reserved = 0, rawdata = None):
		self.packet_type = SSHMessageNumber.SSH_MSG_KEXINIT
		self.cookie = cookie
		self.kex_algorithms = kex_algorithms
		self.server_host_key_algorithms = server_host_key_algorithms
		self.encryption_algorithms_client_to_server = encryption_algorithms_client_to_server
		self.encryption_algorithms_server_to_client = encryption_algorithms_server_to_client
		self.mac_algorithms_client_to_server = mac_algorithms_client_to_server
		self.mac_algorithms_server_to_client = mac_algorithms_server_to_client
		self.compression_algorithms_client_to_server = compression_algorithms_client_to_server
		self.compression_algorithms_server_to_client = compression_algorithms_server_to_client
		self.languages_client_to_server = languages_client_to_server
		self.languages_server_to_client = languages_server_to_client
		self.first_kex_packet_follows = first_kex_packet_follows
		self.reserved = reserved
		self.rawdata = rawdata

		if self.cookie is None:
			self.cookie = os.urandom(16)
				
	@staticmethod
	def from_bytes(data):
		return SSH_MSG_KEXINIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		startpos = buff.tell()
		packet_type = SSHMessageNumber(buff.read(1)[0])
		cookie = buff.read(16)
		kex_algorithms = NameList.from_buff(buff)
		server_host_key_algorithms = NameList.from_buff(buff)
		encryption_algorithms_client_to_server = NameList.from_buff(buff)
		encryption_algorithms_server_to_client = NameList.from_buff(buff)
		mac_algorithms_client_to_server = NameList.from_buff(buff)
		mac_algorithms_server_to_client = NameList.from_buff(buff)
		compression_algorithms_client_to_server = NameList.from_buff(buff)
		compression_algorithms_server_to_client = NameList.from_buff(buff)
		languages_client_to_server = NameList.from_buff(buff)
		languages_server_to_client = NameList.from_buff(buff)
		first_kex_packet_follows = bool(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		reserved = int.from_bytes(buff.read(4), byteorder = 'big', signed = False) #should be 0
		endpos = buff.tell()
		buff.seek(startpos)
		rawdata = buff.read(endpos-startpos)
		buff.seek(endpos)

		msg = SSH_MSG_KEXINIT(
			kex_algorithms,
			server_host_key_algorithms,
			encryption_algorithms_client_to_server,
			encryption_algorithms_server_to_client,
			mac_algorithms_client_to_server,
			mac_algorithms_server_to_client,
			compression_algorithms_client_to_server,
			compression_algorithms_server_to_client,
			languages_client_to_server,
			languages_server_to_client,
			first_kex_packet_follows,
			cookie=cookie,
			reserved = reserved,
			rawdata = rawdata
		)
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.cookie
		data += NameList.to_bytes(self.kex_algorithms)
		data += NameList.to_bytes(self.server_host_key_algorithms)
		data += NameList.to_bytes(self.encryption_algorithms_client_to_server)
		data += NameList.to_bytes(self.encryption_algorithms_server_to_client)
		data += NameList.to_bytes(self.mac_algorithms_client_to_server)
		data += NameList.to_bytes(self.mac_algorithms_server_to_client)
		data += NameList.to_bytes(self.compression_algorithms_client_to_server)
		data += NameList.to_bytes(self.compression_algorithms_server_to_client)
		data += NameList.to_bytes(self.languages_client_to_server)
		data += NameList.to_bytes(self.languages_server_to_client)
		data += b'\x00' if not self.first_kex_packet_follows else b'\x01'
		data += self.reserved.to_bytes(4, byteorder = 'big', signed = False)

		self.rawdata = data
		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'cookie: %s\r\n' % self.cookie.hex()
		t += 'kex_algorithms: %s\r\n' % ','.join(self.kex_algorithms)
		t += 'server_host_key_algorithms: %s\r\n' % ','.join(self.server_host_key_algorithms)
		t += 'encryption_algorithms_client_to_server: %s\r\n' % ','.join(self.encryption_algorithms_client_to_server)
		t += 'encryption_algorithms_server_to_client: %s\r\n' % ','.join(self.encryption_algorithms_server_to_client)
		t += 'mac_algorithms_client_to_server: %s\r\n' % ','.join(self.mac_algorithms_client_to_server)
		t += 'mac_algorithms_server_to_client: %s\r\n' % ','.join(self.mac_algorithms_server_to_client)
		t += 'compression_algorithms_client_to_server: %s\r\n' % ','.join(self.compression_algorithms_client_to_server)
		t += 'compression_algorithms_server_to_client: %s\r\n' % ','.join(self.compression_algorithms_server_to_client)
		t += 'languages_client_to_server: %s\r\n' % ','.join(self.languages_client_to_server)
		t += 'languages_server_to_client: %s\r\n' % ','.join(self.languages_server_to_client)
		t += 'first_kex_packet_follows: %s\r\n' % str(self.first_kex_packet_follows)
		t += 'reserved: %s\r\n' % str(self.reserved)
		
		return t

class SSH2_MSG_KEXDH_INIT:
	def __init__(self, e):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_INIT
		self.e = e #https://tools.ietf.org/html/rfc4253 section 8

	@staticmethod
	def from_bytes(data):
		return SSH2_MSG_KEXDH_INIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		e = inflate_long(SSHString.from_bytes(buff.read()), always_positive=True)
		msg = SSH2_MSG_KEXDH_INIT(e)
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(deflate_long(self.e))
		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'e: %s\r\n' % self.e
		return t


class SSH2_MSG_KEXDH_REPLY:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_REPLY
		self.pubkey_string = None
		self.f = None
		self.h_sig = None
		
	@staticmethod
	def from_bytes(data):
		return SSH2_MSG_KEXDH_REPLY.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH2_MSG_KEXDH_REPLY()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.pubkey_string = SSHString.from_buff(buff)
		msg.f = inflate_long(SSHString.from_buff(buff))
		msg.h_sig = inflate_long(SSHString.from_buff(buff))
		return msg
		
	def to_bytes(self):
		raise NotImplementedError()
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.pubkey_string.to_bytes()
		data += MPInt.to_bytes(self.f)
		data += self.h_sig.to_bytes()
		return data
		
	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_NEWKEYS:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_NEWKEYS

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_NEWKEYS.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_NEWKEYS()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return data

class SSH_MSG_SERVICE_REQUEST:
	def __init__(self, service_name):
		self.packet_type = SSHMessageNumber.SSH_MSG_SERVICE_REQUEST
		self.service_name = service_name

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_SERVICE_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		service_name = SSHString.from_buff(buff)
		return SSH_MSG_SERVICE_REQUEST(service_name)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.service_name)
		return data
	
	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_SERVICE_ACCEPT:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT
		self.service_name = None

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_SERVICE_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_SERVICE_REQUEST()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.service_name = SSHString.from_buff(buff)
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.service_name)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_USERAUTH_BANNER:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_BANNER
		self.message = ''
		self.language = ''

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_BANNER.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_BANNER()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.message = SSHString.from_buff(buff)
		msg.language = SSHString.from_buff(buff)
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.message)
		data += SSHString.to_bytes(self.language)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_USERAUTH_FAILURE:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE
		self.authmethods = []
		self.partial_success = None

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_FAILURE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_FAILURE()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.authmethods = NameList.from_buff(buff)
		msg.partial_success = bool(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += NameList.to_bytes(self.authmethods)
		data += int(self.partial_success).to_bytes(1, byteorder = 'big', signed = False)
		return data

	def __str__(self):
		t  = '==== SSH_MSG_USERAUTH_FAILURE ====\r\n'
		t += 'authmethods : %s\r\n' % ','.join(self.authmethods)
		t += 'partial_success : %s\r\n' % self.partial_success
		return t

class SSH_MSG_USERAUTH_SUCCESS:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_SUCCESS.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_SUCCESS()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return data

	def __str__(self):
		t  = '==== SSH_MSG_USERAUTH_SUCCESS ====\r\n'
		return t

class SSH_MSG_USERAUTH_REQUEST:
	def __init__(self, username, service_name, method_name, method = None):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_REQUEST
		self.username = username
		self.service_name = service_name
		self.method_name = method_name
		self.method = method #this can be an object or None

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_REQUEST()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.username = SSHString.from_buff(buff)
		msg.service_name = SSHString.from_buff(buff)
		msg.method_name = SSHString.from_buff(buff)
		#if msg.method_name == 'password':
		#	msg.method = SSH_MSG_USERAUTH_REQUEST_PW_METHOD.from_buffer(buff)
		#TODO: the other types https://tools.ietf.org/html/rfc4252#section-6
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.username)
		data += SSHString.to_bytes(self.service_name)
		data += SSHString.to_bytes(self.method_name)
		if self.method:
			data += self.method.to_bytes()
		return data

	def __str__(self):
		t  = '==== SSH_MSG_USERAUTH_REQUEST ====\r\n'
		t += 'packet_type : %s\r\n' % self.packet_type
		t += 'username : %s\r\n' % self.username
		t += 'service_name : %s\r\n' % self.service_name
		t += 'method_name : %s\r\n' % self.method_name
		t += 'method : %s\r\n' % self.method
		return t

class SSH_MSG_USERAUTH_REQUEST_PASSWORD:
	def __init__(self, username, service_name, password):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_REQUEST
		self.username = username
		self.service_name = service_name
		self.method_name = 'password'
		self.password = password

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_REQUEST_PASSWORD.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_REQUEST_PASSWORD()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.username = SSHString.from_buff(buff)
		msg.service_name = SSHString.from_buff(buff)
		msg.method_name = SSHString.from_buff(buff)
		#if msg.method_name == 'password':
		#	msg.method = SSH_MSG_USERAUTH_REQUEST_PW_METHOD.from_buffer(buff)
		#TODO: the other types https://tools.ietf.org/html/rfc4252#section-6
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.username)
		data += SSHString.to_bytes(self.service_name)
		data += SSHString.to_bytes(self.method_name)
		data += b'\x00' #boolean False
		data += SSHString.to_bytes(self.password)
		
		return data

	def __str__(self):
		t  = '==== SSH_MSG_USERAUTH_REQUEST_PASSWORD ====\r\n'
		t += 'packet_type : %s\r\n' % self.packet_type
		t += 'username : %s\r\n' % self.username
		t += 'service_name : %s\r\n' % self.service_name
		t += 'method_name : %s\r\n' % self.method_name
		t += 'method : %s\r\n' % self.method
		t += 'password : %s\r\n' % self.password
		return t

class SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
		self.prompt = ''
		self.language = 'en'

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_USERAUTH_PASSWD_CHANGEREQ.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.prompt   = SSHString.from_buff(buff)
		msg.language = SSHString.from_buff(buff)
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.prompt)
		data += SSHString.to_bytes(self.language)
		return data

	def __str__(self):
		t  = '==== SSH_MSG_USERAUTH_PASSWD_CHANGEREQ ====\r\n'
		return t

class SSH_MSG_GLOBAL_REQUEST:
	def __init__(self, requestname, wantreply, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_GLOBAL_REQUEST
		self.requestname:str = requestname
		self.wantreply:bool = wantreply
		self.data:bytes = data

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_GLOBAL_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		requestname = SSHString.from_buff(buff)
		wantreply = bool(buff.read(1)[0])
		data = buff.read()
		return SSH_MSG_GLOBAL_REQUEST(requestname, wantreply, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.requestname)
		data += b'\x01' if self.wantreply is True else b'\x00'
		data += data
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_OPEN:
	def __init__(self, channeltype, channelid, windowsize, packetsize, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_OPEN
		self.channeltype:str = channeltype
		self.channelid:int = channelid
		self.windowsize:int = windowsize
		self.packetsize:int = packetsize
		self.data:bytes = data

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_OPEN.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		channeltype = SSHString.from_buff(buff)
		channelid = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		windowsize = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		packetsize = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		data = buff.read()
		return SSH_MSG_CHANNEL_OPEN(channeltype, channelid, windowsize, packetsize, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.channeltype)
		data += self.channelid.to_bytes(4, byteorder='big', signed=False)
		data += self.windowsize.to_bytes(4, byteorder='big', signed=False)
		data += self.packetsize.to_bytes(4, byteorder='big', signed=False)
		if self.data is not None:
			data += self.data
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
	def __init__(self, recipient, sender, windowsize, packetsize, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		self.recipient:int = recipient
		self.sender:int = sender
		self.windowsize:int = windowsize
		self.packetsize:int = packetsize
		self.data:bytes = data

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_OPEN_CONFIRMATION.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		sender = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		windowsize = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		packetsize = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		data = buff.read()
		return SSH_MSG_CHANNEL_OPEN_CONFIRMATION(recipient, sender, windowsize, packetsize, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += self.sender.to_bytes(4, byteorder='big', signed=False)
		data += self.windowsize.to_bytes(4, byteorder='big', signed=False)
		data += self.packetsize.to_bytes(4, byteorder='big', signed=False)
		data += self.data
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_CHANNEL_OPEN_FAILURE:
	def __init__(self, recipient, reason, description, language):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_FAILURE
		self.recipient:int = recipient
		self.reason:int = reason
		self.description:str = description
		self.language:str = language

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_OPEN_FAILURE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		reason = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		description = SSHString.from_buff(buff)
		language = SSHString.from_buff(buff)
		return SSH_MSG_CHANNEL_OPEN_FAILURE(recipient, reason, description, language)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += self.reason.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(self.description)
		data += SSHString.to_bytes(self.language)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t



class SSH_MSG_CHANNEL_WINDOW_ADJUST:
	def __init__(self, recipient, extend):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST
		self.recipient:int = recipient
		self.extend:int = extend


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_WINDOW_ADJUST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		extend = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		return SSH_MSG_CHANNEL_WINDOW_ADJUST(recipient, extend)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += self.extend.to_bytes(4, byteorder='big', signed=False)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_DATA:
	def __init__(self, recipient, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_DATA
		self.recipient:int = recipient
		self.data:bytes = data


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_DATA.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		data = SSHString.from_buff(buff)
		return SSH_MSG_CHANNEL_DATA(recipient, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(self.data)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_EXTENDED_DATA:
	def __init__(self, recipient, datatype, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA
		self.recipient:int = recipient
		self.datatype:int = datatype
		self.data:bytes = data


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_EXTENDED_DATA.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		datatype = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		data = SSHString.from_buff(buff)
		return SSH_MSG_CHANNEL_EXTENDED_DATA(recipient, datatype, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += self.datatype.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(self.data)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_REQUEST:
	def __init__(self, recipient, request, wantreply, data):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_REQUEST
		self.recipient:int = recipient
		self.request:str = request
		self.wantreply:bool = wantreply
		self.data:bytes = data


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		request = SSHString.from_buff(buff)
		wantreply = bool(buff.read(1)[0])
		data = SSHString.from_buff(buff)
		return SSH_MSG_CHANNEL_REQUEST(recipient, request, wantreply, data)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		data += SSHString.to_bytes(self.request)
		data += b'\x01' if self.wantreply is True else b'\x00'
		if self.data is not None and len(self.data) > 0:
			data += SSHString.to_bytes(self.data)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_CHANNEL_EOF:
	def __init__(self, recipient):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_EOF
		self.recipient:int = recipient


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_EOF.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		return SSH_MSG_CHANNEL_EOF(recipient)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_CHANNEL_CLOSE:
	def __init__(self, recipient):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE
		self.recipient:int = recipient


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_CLOSE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		return SSH_MSG_CHANNEL_CLOSE(recipient)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_SUCCESS:
	def __init__(self, recipient):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_SUCCESS
		self.recipient:int = recipient


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_SUCCESS.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		return SSH_MSG_CHANNEL_SUCCESS(recipient)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_CHANNEL_FAILURE:
	def __init__(self, recipient):
		self.packet_type = SSHMessageNumber.SSH_MSG_CHANNEL_FAILURE
		self.recipient:int = recipient


	@staticmethod
	def from_bytes(data):
		return SSH_MSG_CHANNEL_FAILURE.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		recipient = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		return SSH_MSG_CHANNEL_FAILURE(recipient)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.recipient.to_bytes(4, byteorder='big', signed=False)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t


class SSH_MSG_KEXECDH_INIT:
	def __init__(self, qc):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_INIT
		self.qc:bytes = qc

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_KEXECDH_INIT.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		qc = SSHString.from_buff(buff)
		return SSH_MSG_KEXECDH_INIT(qc)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.qc)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

class SSH_MSG_KEXECDH_REPLY:
	def __init__(self, ks, qs, sigs):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_REPLY
		self.ks:bytes = ks
		self.qs:bytes = qs
		self.sigs:bytes = sigs

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_KEXECDH_REPLY.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		packet_type = SSHMessageNumber(buff.read(1)[0])
		ks = SSHString.from_buff(buff)
		qs = SSHString.from_buff(buff)
		sigs = SSHString.from_buff(buff)

		return SSH_MSG_KEXECDH_REPLY(ks, qs, sigs)

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += SSHString.to_bytes(self.ks)
		data += SSHString.to_bytes(self.qs)
		data += SSHString.to_bytes(self.sigs)
		return data

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s : %s\r\n' % (k, self.__dict__[k])
		return t

ssh_payload_type_lookup = {
	SSHMessageNumber.SSH_MSG_DISCONNECT : None,
	SSHMessageNumber.SSH_MSG_IGNORE: None,
	SSHMessageNumber.SSH_MSG_UNIMPLEMENTED: None,
	SSHMessageNumber.SSH_MSG_DEBUG: None,
	SSHMessageNumber.SSH_MSG_SERVICE_REQUEST: SSH_MSG_SERVICE_REQUEST,
	SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT: SSH_MSG_SERVICE_ACCEPT,
	SSHMessageNumber.SSH_MSG_KEXINIT: SSH_MSG_KEXINIT,
	SSHMessageNumber.SSH_MSG_NEWKEYS: SSH_MSG_NEWKEYS,
	SSHMessageNumber.SSH2_MSG_KEXDH_INIT: SSH2_MSG_KEXDH_INIT,
	SSHMessageNumber.SSH2_MSG_KEXDH_REPLY: SSH2_MSG_KEXDH_REPLY,
	SSHMessageNumber.SSH_MSG_USERAUTH_REQUEST:SSH_MSG_USERAUTH_REQUEST,
	SSHMessageNumber.SSH_MSG_USERAUTH_FAILURE:SSH_MSG_USERAUTH_FAILURE,
	SSHMessageNumber.SSH_MSG_USERAUTH_SUCCESS:SSH_MSG_USERAUTH_SUCCESS,
	SSHMessageNumber.SSH_MSG_USERAUTH_BANNER:SSH_MSG_USERAUTH_BANNER,
	SSHMessageNumber.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
	SSHMessageNumber.SSH_MSG_GLOBAL_REQUEST: SSH_MSG_GLOBAL_REQUEST,
	SSHMessageNumber.SSH_MSG_CHANNEL_OPEN:SSH_MSG_CHANNEL_OPEN,
	SSHMessageNumber.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSHMessageNumber.SSH_MSG_CHANNEL_FAILURE:SSH_MSG_CHANNEL_OPEN_FAILURE,
	SSHMessageNumber.SSH_MSG_CHANNEL_WINDOW_ADJUST:SSH_MSG_CHANNEL_WINDOW_ADJUST,
	SSHMessageNumber.SSH_MSG_CHANNEL_DATA:SSH_MSG_CHANNEL_DATA,
	SSHMessageNumber.SSH_MSG_CHANNEL_EXTENDED_DATA:SSH_MSG_CHANNEL_EXTENDED_DATA,
	SSHMessageNumber.SSH_MSG_CHANNEL_EOF: SSH_MSG_CHANNEL_EOF,
	SSHMessageNumber.SSH_MSG_CHANNEL_CLOSE: SSH_MSG_CHANNEL_CLOSE,
	SSHMessageNumber.SSH_MSG_CHANNEL_REQUEST: SSH_MSG_CHANNEL_REQUEST,
	SSHMessageNumber.SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_SUCCESS,
	SSHMessageNumber.SSH_MSG_CHANNEL_FAILURE : SSH_MSG_CHANNEL_FAILURE,
}