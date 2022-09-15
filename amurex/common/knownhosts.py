
import base64
import os
import hmac
from typing import List
from amurex import logger
from amurex.crypto.keys import AMUREX_HOST_KEY_ALGORITHMS, SSHKeyAlgo

class KnownHostEntry:
	def __init__(self, addr, key, keytype):
		self.key = keytype
		self.keytype = key
		self.addr = None
		self.addr_hashed = None
		self.addr_hashed_salt = None
		self.addr_hashed_full = None

		if addr.startswith('|1|') is True:
			self.addr_hashed_salt, self.addr_hashed = addr[3:].split('|')
			self.addr_hashed_salt = base64.b64decode(self.addr_hashed_salt.encode())
			self.addr_hashed_full = addr
		else:
			self.addr = addr
			self.addr_hashed, self.addr_hashed_salt = KnownHosts.hash_addr(addr)
	
	def verify_addr(self, newaddr:str):
		if self.addr == newaddr:
			return True
		if self.addr_hashed == newaddr:
			return True

		if newaddr.startswith('|1|') is False:
			newaddr, newaddr_salt = KnownHosts.hash_addr(newaddr, self.addr_hashed_salt)
			if newaddr == self.addr_hashed_full:
				return True
		return False

class KnownHosts:
	def __init__(self):
		self.entries:List[KnownHostEntry] = []

	def load_file(self, fname):
		kf = KnownHosts.from_file(fname)
		self.entries += kf.entries

	@staticmethod
	def from_file(fname):
		with open(fname, 'rb') as f:
			return KnownHosts.from_bytes(f.read())

	@staticmethod
	def from_bytes(data):
		kh = KnownHosts()
		data = data.decode()
		for line in data.split('\n'):
			line = line.strip()
			if line == '':
				continue
			addr, keytype, pubkey = line.split(' ')
			if keytype not in AMUREX_HOST_KEY_ALGORITHMS:
				logger.debug('Missing parser for keytype %s' % keytype)
				continue
			key = SSHKeyAlgo.load_pubkey_from_string_b64(keytype, pubkey)		
			kh.entries.append(KnownHostEntry(addr, keytype, key))
		return kh
	
	@staticmethod
	def hash_addr(addr, salt = None):
		if salt is None:
			salt = os.urandom(20)
		if isinstance(addr, (tuple, list)) is True:
			hostname = addr[0]
			ip = None
			addr = hostname
			if len(addr) > 1:
				ip = addr[1]
				addr = '%s,%s' % (hostname, ip)
		
		h = hmac.HMAC(salt, addr.encode(), 'sha1').digest()
		salt_enc = base64.b64encode(salt).decode()
		h_enc = base64.b64encode(h).decode()
		return '|1|%s|%s' % (salt_enc, h_enc), salt
		
	def get_pubkey_for_addr(self, addr, keytype):
		for entry in self.entries:
			if entry.keytype == keytype:
				if entry.verify_addr(addr) is True:
					return entry.key
		return None


	def verify_certificate(self, addr, keytype, pubkey):
		local_pubkey = self.get_pubkey_for_addr(addr, keytype)
		if local_pubkey is None:
			return False
		_, local_pubkey_string = local_pubkey.to_knownhostline()
		if isinstance(pubkey, str) is False:
			pubkey = pubkey.to_knownhostline()
		if local_pubkey_string == pubkey:
			return True
		raise Exception('Remote host identification has changed!')
		return False
