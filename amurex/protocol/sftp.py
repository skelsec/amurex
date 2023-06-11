
import io
import enum
import datetime
from typing import List, Tuple, Dict

# https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
# http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL
# https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

AMUREX_WINDOWS_EPOCH = datetime.datetime(1601, 1, 1)
AMUREX_UNIX_EPOCH = datetime.datetime(1970, 1, 1)
AMUREX_EPOCH_DIFF = (AMUREX_UNIX_EPOCH - AMUREX_WINDOWS_EPOCH).total_seconds() * 10**7

def unix_time_to_windows_filetime(unix_time):
	if unix_time is None:
		return AMUREX_WINDOWS_EPOCH
	windows_filetime = unix_time * 10**7 + AMUREX_EPOCH_DIFF
	return windows_filetime

class SSH_FXP(enum.Enum):
	INIT = 1
	VERSION = 2
	OPEN = 3
	CLOSE = 4
	READ = 5
	WRITE = 6
	LSTAT = 7
	FSTAT = 8
	SETSTAT = 9
	FSETSTAT = 10
	OPENDIR = 11
	READDIR = 12
	REMOVE = 13
	MKDIR = 14
	RMDIR = 15
	REALPATH = 16
	STAT = 17
	RENAME = 18
	READLINK = 19
	SYMLINK = 20
	STATUS = 101
	HANDLE = 102
	DATA = 103
	NAME = 104
	ATTRS = 105
	EXTENDED = 200
	EXTENDED_REPLY = 201

class SSH_FXF(enum.IntFlag):
	READ = 0x00000001
	WRITE = 0x00000002
	APPEND = 0x00000004
	CREAT = 0x00000008
	TRUNC = 0x00000010
	EXCL = 0x00000020

PY_OPEN_TO_SSH_FXF = {
	'r': SSH_FXF.READ,
	'w': SSH_FXF.WRITE | SSH_FXF.TRUNC | SSH_FXF.CREAT,
	'x': SSH_FXF.WRITE | SSH_FXF.CREAT | SSH_FXF.EXCL,
	'a': SSH_FXF.WRITE | SSH_FXF.APPEND | SSH_FXF.CREAT,
	'r+': SSH_FXF.READ | SSH_FXF.WRITE,
	'w+': SSH_FXF.READ | SSH_FXF.WRITE | SSH_FXF.TRUNC | SSH_FXF.CREAT,
	'a+': SSH_FXF.READ | SSH_FXF.WRITE | SSH_FXF.APPEND | SSH_FXF.CREAT,
}

class SSH_FILEXFER_ATTR(enum.IntFlag):
	SIZE = 0x00000001
	UIDGID = 0x00000002
	PERMISSIONS = 0x00000004
	ACMODTIME = 0x00000008
	EXTENDED = 0x80000000

class SSH_FX(enum.Enum):
	OK = 0
	EOF = 1
	NO_SUCH_FILE = 2
	PERMISSION_DENIED = 3
	FAILURE = 4
	BAD_MESSAGE = 5
	NO_CONNECTION = 6
	CONNECTION_LOST = 7
	OP_UNSUPPORTED = 8

class SFTPException(Exception):
	def __init__(self, error_code:SSH_FX, msg = None):
		self.error_code = error_code.value
		self.error_code_name = error_code.name
		self.message = msg

class ATTRS:
	def __init__(self):
		self.flags = None
		self.size = None
		self.uid = None
		self.gid = None
		self.permissions = None
		self.atime = None
		self.mtime = None
		self.extended = []
	
	@property
	def suid(self):
		return bool(self.permissions & 0o4000)
	
	@property
	def sgid(self):
		return bool(self.permissions & 0o2000)
	
	@property
	def sticky(self):
		return bool(self.permissions & 0o1000)
	
	@property
	def ftype(self):
		return (self.permissions & 0o170000) >> 12

	@property
	def owner(self):
		return self.uid
	
	@property
	def group(self):
		return self.gid
	
	@property
	def mode(self):
		return self.permissions & 0o777

	@property
	def is_dir(self):
		return self.ftype == 0o4
	
	@property
	def is_file(self):
		return self.ftype == 0o10
	
	@property
	def is_link(self):
		return self.ftype == 0o12
	
	@property
	def mtime_windows(self):
		return unix_time_to_windows_filetime(self.mtime)
	
	@property
	def atime_windows(self):
		return unix_time_to_windows_filetime(self.atime)
	
	@staticmethod
	def from_bytes(data):
		return ATTRS.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		attrs = ATTRS()
		attrs.flags = SSH_FILEXFER_ATTR(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		if attrs.flags & SSH_FILEXFER_ATTR.SIZE:
			attrs.size = int.from_bytes(buff.read(8), byteorder='big', signed = False)
		if attrs.flags & SSH_FILEXFER_ATTR.UIDGID:
			attrs.uid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
			attrs.gid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		if attrs.flags & SSH_FILEXFER_ATTR.PERMISSIONS:
			attrs.permissions = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		if attrs.flags & SSH_FILEXFER_ATTR.ACMODTIME:
			attrs.atime = int.from_bytes(buff.read(4), byteorder='big', signed = False)
			attrs.mtime = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		if attrs.flags & SSH_FILEXFER_ATTR.EXTENDED:
			extended_count = int.from_bytes(buff.read(4), byteorder='big', signed = False)
			for _ in range(extended_count):
				etype = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
				edata = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
				attrs.extended.append((etype, edata))
		return attrs

	def to_bytes(self):

		if self.flags is None or self.flags == 0:
			self.flags = SSH_FILEXFER_ATTR(0)
			if self.size is not None:
				self.flags |= SSH_FILEXFER_ATTR.SIZE
			if self.uid is not None and self.gid is not None:
				self.flags |= SSH_FILEXFER_ATTR.UIDGID
			if self.permissions is not None:
				self.flags |= SSH_FILEXFER_ATTR.PERMISSIONS
			if self.atime is not None and self.mtime is not None:
				self.flags |= SSH_FILEXFER_ATTR.ACMODTIME
			if len(self.extended) > 0:
				self.flags |= SSH_FILEXFER_ATTR.EXTENDED
		
		t  = self.flags.value.to_bytes(4, byteorder='big', signed = False)
		if self.flags & SSH_FILEXFER_ATTR.SIZE:
			t += self.size.to_bytes(8, byteorder='big', signed = False)
		if self.flags & SSH_FILEXFER_ATTR.UIDGID:
			t += self.uid.to_bytes(4, byteorder='big', signed = False)
			t += self.gid.to_bytes(4, byteorder='big', signed = False)
		if self.flags & SSH_FILEXFER_ATTR.PERMISSIONS:
			t += self.permissions.to_bytes(4, byteorder='big', signed = False)
		if self.flags & SSH_FILEXFER_ATTR.ACMODTIME:
			t += self.atime.to_bytes(4, byteorder='big', signed = False)
			t += self.mtime.to_bytes(4, byteorder='big', signed = False)
		if self.flags & SSH_FILEXFER_ATTR.EXTENDED:
			t += len(self.extended).to_bytes(4, byteorder='big', signed = False)
			for etype, edata in self.extended:
				t += len(etype).to_bytes(4, byteorder='big', signed = False)
				t += etype.encode()
				t += len(edata).to_bytes(4, byteorder='big', signed = False)
				t += edata
		return t

	def __str__(self):
		t = 'ATTRS:\r\n'
		t += 'flags: %s\r\n' % self.flags
		if self.flags & SSH_FILEXFER_ATTR.SIZE:
			t += 'size: %s\r\n' % self.size
		if self.flags & SSH_FILEXFER_ATTR.UIDGID:
			t += 'uid: %s\r\n' % self.uid
			t += 'gid: %s\r\n' % self.gid
		if self.flags & SSH_FILEXFER_ATTR.PERMISSIONS:
			t += 'permissions: %s\r\n' % self.permissions
		if self.flags & SSH_FILEXFER_ATTR.ACMODTIME:
			t += 'atime: %s\r\n' % self.atime
			t += 'mtime: %s\r\n' % self.mtime
		if self.flags & SSH_FILEXFER_ATTR.EXTENDED:
			t += 'extended: %s\r\n' % self.extended
		return t
	
	
class SSH_FXP_INIT:
	def __init__(self, version:int, extensions:Dict[str, bytes] = None):
		self.length:int = None
		self.command = SSH_FXP.INIT
		self.version = version
		self.extensions = extensions
		
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_INIT.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		startpos = buff.tell()
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		version = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		extensions = {}
		if length > 5:
			while buff.tell() - startpos < length:
				etype = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
				edata = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
				if etype.endswith('@openssh.com'):
					edata = edata.decode()
				extensions[etype] = edata
		return SSH_FXP_INIT(version, extensions)
	
	def to_bytes(self):
		extensions_raw = b''
		if self.extensions is not None:
			for k,v in self.extensions.items():
				extensions_raw += len(k).to_bytes(4, byteorder='big', signed = False)
				extensions_raw += k.encode()
				extensions_raw += len(v).to_bytes(4, byteorder='big', signed = False)
				extensions_raw += v

		if self.length is None:
			self.length = 5 + len(extensions_raw)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.version.to_bytes(4, byteorder='big', signed = False)
		t += extensions_raw
		
		return t

class SSH_FXP_VERSION:
	def __init__(self, version:int, extensions:Dict[str, bytes] = None):
		self.length = 5
		self.command = SSH_FXP.VERSION
		self.version = version
		self.extensions = extensions
		
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_VERSION.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		startpos = buff.tell()
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		version = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		extensions = {}
		if length > 5:
			while buff.tell() - startpos < length:
				etype = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
				edata = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
				if etype.endswith('@openssh.com'):
					edata = edata.decode()
				extensions[etype] = edata
		return SSH_FXP_VERSION(version, extensions)
	
	def to_bytes(self):
		extensions_raw = b''
		for k,v in self.extensions.items():
			extensions_raw += len(k).to_bytes(4, byteorder='big', signed = False)
			extensions_raw += k.encode()
			extensions_raw += len(v).to_bytes(4, byteorder='big', signed = False)
			extensions_raw += v
		if self.length is None:
			self.length = 5 + len(extensions_raw)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.version.to_bytes(4, byteorder='big', signed = False)
		t += extensions_raw
		return t


class SSH_FXP_OPEN:
	def __init__(self, filename:str, pflags:SSH_FXF, attrs:ATTRS = None, pid:int = None):
		self.length = None
		self.command = SSH_FXP.OPEN
		self.pid = pid
		self.filename = filename
		self.pflags = pflags
		self.attrs = attrs
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_OPEN.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		filename = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
		pflags = SSH_FXF(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		attrs = ATTRS.from_buffer(buff)
		return SSH_FXP_OPEN(filename, pflags, attrs, pid = pid)
	
	def to_bytes(self):
		if self.attrs is None:
			self.attrs = ATTRS()
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.filename.encode()) + 4 + len(self.attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.filename.encode()).to_bytes(4, byteorder='big', signed = False)
		t += self.filename.encode()
		t += self.pflags.value.to_bytes(4, byteorder='big', signed = False)
		t += self.attrs.to_bytes()
		return t
	
class SSH_FXP_CLOSE:
	def __init__(self, handle:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.CLOSE
		self.pid = pid
		self.handle = handle
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_CLOSE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_CLOSE(handle, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		return t

class SSH_FXP_READ:
	def __init__(self, handle:bytes, offset:int, dlength:int, pid:int = None):
		self.length = None
		self.command = SSH_FXP.READ
		self.pid = pid
		self.handle = handle
		self.offset = offset
		self.dlength = dlength
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_READ.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		offset = int.from_bytes(buff.read(8), byteorder='big', signed = False)
		dlength = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		return SSH_FXP_READ(handle, offset, dlength, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle) + 8 + 4
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		t += self.offset.to_bytes(8, byteorder='big', signed = False)
		t += self.dlength.to_bytes(4, byteorder='big', signed = False)
		return t

class SSH_FXP_WRITE:
	def __init__(self, handle:bytes, offset:int, data:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.WRITE
		self.pid = pid
		self.handle = handle
		self.offset = offset
		self.data = data
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_WRITE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		offset = int.from_bytes(buff.read(8), byteorder='big', signed = False)
		data = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_WRITE(handle, offset, data, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle) + 8 + 4 + len(self.data)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		t += self.offset.to_bytes(8, byteorder='big', signed = False)
		t += len(self.data).to_bytes(4, byteorder='big', signed = False)
		t += self.data
		return t

class SSH_FXP_LSTAT:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.LSTAT
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_LSTAT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_LSTAT(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t

class SSH_FXP_STAT(SSH_FXP_LSTAT):
	"""Only difference is that STAT follows symlinks, LSTAT doesn't"""
	def __init__(self, path:str):
		super().__init__(path)
		self.command = SSH_FXP.STAT

class SSH_FXP_FSTAT:
	def __init__(self, handle:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.FSTAT
		self.pid = pid
		self.handle = handle
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_FSTAT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_FSTAT(handle, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		return t

class SSH_FXP_SETSTAT:
	def __init__(self, path:str, attrs:ATTRS, pid:int = None):
		self.length = None
		self.command = SSH_FXP.SETSTAT
		self.pid = pid
		self.path = path
		self.attrs = attrs
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_SETSTAT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		attrs = ATTRS.from_buffer(buff)
		return SSH_FXP_SETSTAT(path.decode(), attrs, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path) + len(self.attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		t += self.attrs.to_bytes()
		return t
	
class SSH_FXP_FSETSTAT:
	def __init__(self, handle:bytes, attrs:ATTRS, pid:int = None):
		self.length = None
		self.command = SSH_FXP.FSETSTAT
		self.pid = pid
		self.handle = handle
		self.attrs = attrs
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_FSETSTAT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		attrs = ATTRS.from_buffer(buff)
		return SSH_FXP_FSETSTAT(handle, attrs, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle) + len(self.attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		t += self.attrs.to_bytes()
		return t

class SSH_FXP_OPENDIR:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.OPENDIR
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_OPENDIR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_OPENDIR(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t
	
class SSH_FXP_READDIR:
	def __init__(self, handle:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.READDIR
		self.pid = pid
		self.handle = handle
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_READDIR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_READDIR(handle, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		return t

class SSH_FXP_REMOVE:
	def __init__(self, filename:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.REMOVE
		self.pid = pid
		self.filename = filename
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_REMOVE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		filename = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_REMOVE(filename.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.filename)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.filename).to_bytes(4, byteorder='big', signed = False)
		t += self.filename.encode()
		return t

class SSH_FXP_MKDIR:
	def __init__(self, path:str, attrs:ATTRS, pid:int = None):
		self.length = None
		self.command = SSH_FXP.MKDIR
		self.pid = pid
		self.path = path
		self.attrs = attrs
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_MKDIR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		attrs = ATTRS.from_buffer(buff)
		return SSH_FXP_MKDIR(path.decode(), attrs, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path) + len(self.attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		t += self.attrs.to_bytes()
		return t

class SSH_FXP_RMDIR:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.RMDIR
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_RMDIR.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_RMDIR(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t

class SSH_FXP_REALPATH:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.REALPATH
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_REALPATH.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_REALPATH(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t

class SSH_FXP_STAT:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.STAT
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_STAT.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_STAT(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t

class SSH_FXP_RENAME:
	def __init__(self, oldpath:str, newpath:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.RENAME
		self.pid = pid
		self.oldpath = oldpath
		self.newpath = newpath
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_RENAME.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		oldpath = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		newpath = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_RENAME(oldpath.decode(), newpath.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.oldpath) + len(self.newpath)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.oldpath).to_bytes(4, byteorder='big', signed = False)
		t += self.oldpath.encode()
		t += len(self.newpath).to_bytes(4, byteorder='big', signed = False)
		t += self.newpath.encode()
		return t

class SSH_FXP_READLINK:
	def __init__(self, path:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.READLINK
		self.pid = pid
		self.path = path
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_READLINK.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		path = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_READLINK(path.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.path)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.path).to_bytes(4, byteorder='big', signed = False)
		t += self.path.encode()
		return t

class SSH_FXP_SYMLINK:
	def __init__(self, linkpath:str, targetpath:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.SYMLINK
		self.pid = pid
		self.linkpath = linkpath
		self.targetpath = targetpath
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_SYMLINK.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		linkpath = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		targetpath = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_SYMLINK(linkpath.decode(), targetpath.decode(), pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.linkpath) + len(self.targetpath)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.linkpath).to_bytes(4, byteorder='big', signed = False)
		t += self.linkpath.encode()
		t += len(self.targetpath).to_bytes(4, byteorder='big', signed = False)
		t += self.targetpath.encode()
		return t

class SSH_FXP_STATUS:
	def __init__(self, error_code:SSH_FX, error_message:str, language:str, pid:int = None):
		self.length = None
		self.command = SSH_FXP.STATUS
		self.pid = pid
		self.error_code = error_code
		self.error_message = error_message
		self.language = language
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_STATUS.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		error_code = SSH_FX(buff.read(4)[0])
		error_message = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		language = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_STATUS(error_code, error_message.decode(), language, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + 4 + len(self.error_message)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += self.error_code.value.to_bytes(4, byteorder='big', signed = False)
		t += len(self.error_message).to_bytes(4, byteorder='big', signed = False)
		t += self.error_message.encode()
		t += len(self.language).to_bytes(4, byteorder='big', signed = False)
		t += self.language.encode()
		return t
	
	def get_exception(self):
		return SFTPException(self.error_code, self.error_message)

class SSH_FXP_HANDLE:
	def __init__(self, handle:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.HANDLE
		self.pid = pid
		self.handle = handle
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_HANDLE.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		handle = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_HANDLE(handle, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.handle)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.handle).to_bytes(4, byteorder='big', signed = False)
		t += self.handle
		return t

class SSH_FXP_DATA:
	def __init__(self, data:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.DATA
		self.pid = pid
		self.data = data
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_DATA.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		data = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_DATA(data, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.data)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.data).to_bytes(4, byteorder='big', signed = False)
		t += self.data
		return t

class SSH_FXP_NAME:
	def __init__(self, entries:List[Tuple[str, str, ATTRS]], pid:int = None):
		self.length = None
		self.command = SSH_FXP.NAME
		self.pid = pid
		self.entries = entries
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_NAME.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		count = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		entries = []
		for _ in range(count):
			filename = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
			longname = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
			attrs = ATTRS.from_buffer(buff)
			entries.append( (filename, longname, attrs) )
		return SSH_FXP_NAME(entries, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + 4
			for filename, longname, attrs in self.entries:
				self.length += 4 + len(filename)
				self.length += 4 + len(longname)
				self.length += len(attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.entries).to_bytes(4, byteorder='big', signed = False)
		for filename, longname, attrs in self.entries:
			t += len(filename).to_bytes(4, byteorder='big', signed = False)
			t += filename.encode()
			t += len(longname).to_bytes(4, byteorder='big', signed = False)
			t += longname.encode()
			t += attrs.to_bytes()
		return t

class SSH_FXP_ATTRS:
	def __init__(self, attrs:ATTRS, pid:int = None):
		self.length = None
		self.command = SSH_FXP.ATTRS
		self.pid = pid
		self.attrs = attrs
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_ATTRS.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		attrs = ATTRS.from_buffer(buff)
		return SSH_FXP_ATTRS(attrs, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + len(self.attrs.to_bytes())
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += self.attrs.to_bytes()
		return t

class SSH_FXP_EXTENDED:
	def __init__(self, extended_name:str, extended_data:bytes, pid:int = None):
		self.length = None
		self.command = SSH_FXP.EXTENDED
		self.pid = pid
		self.extended_name = extended_name
		self.extended_data = extended_data
	
	@staticmethod
	def from_bytes(data):
		return SSH_FXP_EXTENDED.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		command = SSH_FXP(buff.read(1)[0])
		pid = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		extended_name = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False)).decode()
		extended_data = buff.read(int.from_bytes(buff.read(4), byteorder='big', signed = False))
		return SSH_FXP_EXTENDED(extended_name, extended_data, pid = pid)
	
	def to_bytes(self):
		if self.length is None:
			self.length = 4 + 1 + 4 + 4 + len(self.extended_name) + len(self.extended_data)
		t  = self.length.to_bytes(4, byteorder='big', signed = False)
		t += self.command.value.to_bytes(1, byteorder='big', signed = False)
		t += self.pid.to_bytes(4, byteorder='big', signed = False)
		t += len(self.extended_name).to_bytes(4, byteorder='big', signed = False)
		t += self.extended_name.encode()
		t += len(self.extended_data).to_bytes(4, byteorder='big', signed = False)
		t += self.extended_data
		return t
	


SFTP_PACKET_TYPE_LOOKUP = {
	SSH_FXP.INIT: SSH_FXP_INIT,
	SSH_FXP.VERSION: SSH_FXP_VERSION,
	SSH_FXP.OPEN: SSH_FXP_OPEN,
	SSH_FXP.CLOSE: SSH_FXP_CLOSE,
	SSH_FXP.READ: SSH_FXP_READ,
	SSH_FXP.WRITE: SSH_FXP_WRITE,
	SSH_FXP.LSTAT: SSH_FXP_LSTAT,
	SSH_FXP.FSTAT: SSH_FXP_FSTAT,
	SSH_FXP.SETSTAT: SSH_FXP_SETSTAT,
	SSH_FXP.FSETSTAT: SSH_FXP_FSETSTAT,
	SSH_FXP.OPENDIR: SSH_FXP_OPENDIR,
	SSH_FXP.READDIR: SSH_FXP_READDIR,
	SSH_FXP.REMOVE: SSH_FXP_REMOVE,
	SSH_FXP.MKDIR: SSH_FXP_MKDIR,
	SSH_FXP.RMDIR: SSH_FXP_RMDIR,
	SSH_FXP.REALPATH: SSH_FXP_REALPATH,
	SSH_FXP.STAT: SSH_FXP_STAT,
	SSH_FXP.RENAME: SSH_FXP_RENAME,
	SSH_FXP.READLINK: SSH_FXP_READLINK,
	SSH_FXP.SYMLINK: SSH_FXP_SYMLINK,
	SSH_FXP.STATUS: SSH_FXP_STATUS,
	SSH_FXP.HANDLE: SSH_FXP_HANDLE,
	SSH_FXP.DATA: SSH_FXP_DATA,
	SSH_FXP.NAME: SSH_FXP_NAME,
	SSH_FXP.ATTRS: SSH_FXP_ATTRS,
}

SFTP_EXPECTED_RESPONSES = {
	SSH_FXP.INIT: SSH_FXP.VERSION,
	SSH_FXP.OPEN: SSH_FXP.HANDLE,
	SSH_FXP.CLOSE: SSH_FXP.STATUS,
	SSH_FXP.READ: SSH_FXP.DATA,
	SSH_FXP.WRITE: SSH_FXP.STATUS,
	SSH_FXP.LSTAT: SSH_FXP.ATTRS,
	SSH_FXP.FSTAT: SSH_FXP.ATTRS,
	SSH_FXP.SETSTAT: SSH_FXP.STATUS,
	SSH_FXP.FSETSTAT: SSH_FXP.STATUS,
	SSH_FXP.OPENDIR: SSH_FXP.HANDLE,
	SSH_FXP.READDIR: SSH_FXP.NAME,
	SSH_FXP.REMOVE: SSH_FXP.STATUS,
	SSH_FXP.MKDIR: SSH_FXP.STATUS,
	SSH_FXP.RMDIR: SSH_FXP.STATUS,
	SSH_FXP.REALPATH: SSH_FXP.NAME,
	SSH_FXP.STAT: SSH_FXP.ATTRS,
	SSH_FXP.RENAME: SSH_FXP.STATUS,
	SSH_FXP.READLINK: SSH_FXP.NAME,
	SSH_FXP.SYMLINK: SSH_FXP.STATUS,
	SSH_FXP.STATUS: None,
	SSH_FXP.HANDLE: None,
	SSH_FXP.DATA: None,
	SSH_FXP.NAME: None,
	SSH_FXP.ATTRS: None,
}