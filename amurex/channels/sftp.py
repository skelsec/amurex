
import asyncio
import traceback
from typing import Dict
from pathlib import Path
from amurex.channels import SSHChannel
from amurex.protocol.messages import SSHString
from amurex.protocol.sftp import SSH_FXF, SSH_FX, SSH_FXP, SFTP_PACKET_TYPE_LOOKUP,\
	SSH_FXP_INIT, SSH_FXP_OPENDIR, SSH_FXP_CLOSE, SSH_FXP_READDIR, SSH_FXP_STATUS, \
	SFTP_EXPECTED_RESPONSES, PY_OPEN_TO_SSH_FXF, ATTRS, SSH_FXP_OPEN, SSH_FXP_READ, \
	SSH_FXP_WRITE, SSH_FXP_CLOSE, SSH_FXP_LSTAT, SSH_FXP_STAT, SSH_FXP_FSTAT,\
	SSH_FXP_MKDIR, SSH_FXP_RMDIR, SSH_FXP_REALPATH, SSH_FXP_SETSTAT, SSH_FXP_READLINK,\
	SSH_FXP_SYMLINK, SSH_FXP_REMOVE

async def resolve_response(fut: asyncio.Future, expected_packet_type:SSH_FXP):
	try:
		resp = await fut
		if resp.command == SSH_FXP.STATUS:
			if resp.error_code != SSH_FX.OK:
				return None, resp.get_exception()
			return None, None
		if resp.command != expected_packet_type:
			return None, Exception('Invalid response type! Expected: %s Got: %s' % (expected_packet_type, resp.command))
		return resp, None
	except Exception as e:
		return None, e
	
async def resolve_exception(exception:Exception):
	return None, exception

class SSHSFTPSession(SSHChannel):
	def __init__(self, recipientid):
		SSHChannel.__init__(self, 'session', recipientid, 0x200000, 0x8000)
		self.init_complete_evt = asyncio.Event()
		self.server_extensions = {}
		self.__buffer = b''
		self.__handles = {}
		self.__outstanding_requests:Dict[int, asyncio.Future] = {}
		self.__next_pid = 0
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.channel_close(server_side=False)
	
	def get_pid(self):
		"""Returns the next packet id"""
		while True:
			self.__next_pid += 1
			self.__next_pid &= 0xffffffff
			if self.__next_pid not in self.__outstanding_requests:
				break
		
		return self.__next_pid

	async def channel_close(self, server_side:bool=False):
		for pid in self.__outstanding_requests:
			self.__outstanding_requests[pid].set_result(Exception('Channel is closed!'))
		if server_side is False:
			for handle in self.__handles:
				fut = await self.send_message(SSH_FXP_CLOSE(handle))
				packet, err = await fut

	async def channel_init(self, *args, **kwargs):
		try:
			_, err = await self.channel_request('subsystem', True, SSHString.to_bytes('sftp'))
			if err is not None:
				return None, err
			
			_, err = await self.channel_data_out(SSH_FXP_INIT(3).to_bytes())
			if err is not None:
				return None, err
			
			await self.init_complete_evt.wait()
			return True, None
		except Exception as e:
			return None, e
	
	async def channel_data_in(self, datatype:int, data:bytes):
		self.__buffer += data
		while len(self.__buffer) > 4:
			packetlen = int.from_bytes(self.__buffer[:4], byteorder='big', signed=False) + 4
			if len(self.__buffer) >= packetlen:
				packet = self.__buffer[:packetlen]
				self.__buffer = self.__buffer[packetlen:]
				await self.process_packet(packet)
			else:
				break

	async def send_message(self, message):
		try:
			if self.channel_closed_evt.is_set() is True:
				return resolve_exception(Exception('Channel is closed!'))
			pid = self.get_pid()
			message.pid = pid
			fut = asyncio.Future()
			self.__outstanding_requests[pid] = fut
			await self.channel_data_out(message.to_bytes())
			return resolve_response(fut, SFTP_EXPECTED_RESPONSES[message.command])
		except Exception as e:
			traceback.print_exc()

	async def process_packet(self, packet_raw:bytes):
		#print('SFTP PROCESS PACKET: %s...' % packet_raw[:0x10])
		packet_type = SSH_FXP(packet_raw[4])
		packet = SFTP_PACKET_TYPE_LOOKUP[packet_type].from_bytes(packet_raw)
		#print('SFTP PACKET: %s' % packet)
		if packet_type == SSH_FXP.VERSION:
			self.server_extensions = packet.extensions
			self.init_complete_evt.set()
			return
		if packet.pid in self.__outstanding_requests:
			if packet_type == SSH_FXP.HANDLE:
				self.__handles[packet.handle] = packet.handle
			elif packet_type == SSH_FXP.CLOSE:
				del self.__handles[packet.handle]
			self.__outstanding_requests[packet.pid].set_result(packet)
			del self.__outstanding_requests[packet.pid]
			return
		else:
			print('SFTP UNHANDLED PID: %s PACKET: %s' % (packet.pid, packet))
		return
	
	async def opendir(self, path):
		"""Opens a directory"""
		try:
			fut = await self.send_message(SSH_FXP_OPENDIR(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			fullpath, err = await self.realpath(path)
			if err is not None:
				raise err
			fullpath = Path(fullpath)			
			return SFTPDirectory(path, handle = packet.handle, session = self, fullpath = fullpath), None
		except Exception as e:
			return None, e
		
	async def mkdir(self, path):
		"""Creates a directory"""
		try:
			fut = await self.send_message(SSH_FXP_MKDIR(path, ATTRS()))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
		
	async def rmdir(self, path):
		"""Removes a directory"""
		try:
			fut = await self.send_message(SSH_FXP_RMDIR(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
		
	async def cwd(self):
		"""Gets the current working directory"""
		try:
			fut = await self.send_message(SSH_FXP_REALPATH('.'))
			packet, err = await fut
			if err is not None:
				raise err
			
			return packet.entries[0][1], None
		except Exception as e:
			return None, e
		
	async def realpath(self, path:str):
		"""Gets the real path of a file or directory"""
		try:
			fut = await self.send_message(SSH_FXP_REALPATH(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return packet.entries[0][1], None
		except Exception as e:
			return None, e
	
	async def open(self, path: str, mode:str):
		"""Opens a file"""
		try:
			if 't' in mode:
				raise Exception('Text mode not supported!')
			
			if 'b' in mode:
				# remove b from mode
				mode = mode.replace('b', '')
			
			if mode not in PY_OPEN_TO_SSH_FXF:
				raise Exception('Invalid mode!')
			
			smode = PY_OPEN_TO_SSH_FXF[mode]
			fut = await self.send_message(SSH_FXP_OPEN(path, smode))
			packet, err = await fut
			if err is not None:
				raise err

			if 'r' in mode:
				fut = await self.send_message(SSH_FXP_FSTAT(packet.handle))
				stat, err = await fut
				if err is not None:
					raise err
				attrs = stat.attrs
			else:
				attrs = ATTRS()
			
			return SFTPFile(path, smode, attrs= attrs, handle = packet.handle, session = self), None
		except Exception as e:
			return None, e

	async def unlink(self, path:str):
		"""Deletes a file"""
		try:
			fut = await self.send_message(SSH_FXP_REMOVE(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
		
	async def stat(self, path:str):
		"""Gets the stats of a file or directory"""
		try:
			fut = await self.send_message(SSH_FXP_STAT(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return packet.attrs, None
		except Exception as e:
			return None, e
	
	async def lstat(self, path:str):
		"""Gets the stats of a file or directory. Does NOT follow symlinks"""
		try:
			fut = await self.send_message(SSH_FXP_LSTAT(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return packet.attrs, None
		except Exception as e:
			return None, e
		
	async def setstat(self, path:str, attrs:ATTRS):
		"""Sets the stats of a file or directory"""
		try:
			fut = await self.send_message(SSH_FXP_SETSTAT(path, attrs))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
	
	async def readlink(self, path:str):
		"""Gets the target of a symlink"""
		try:
			fut = await self.send_message(SSH_FXP_READLINK(path))
			packet, err = await fut
			if err is not None:
				raise err
			
			return packet.entries[0][1], None
		except Exception as e:
			return None, e
	
	async def symlink(self, srcpath:str, dstpath:str):
		"""Creates a symlink"""
		try:
			fut = await self.send_message(SSH_FXP_SYMLINK(srcpath, dstpath))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return None, e
		
	async def download(self, srcpath:str, dstpath:str):
		"""Downloads a file from the remote server to the local machine"""
		sfile = None
		try:
			sfile, err = await self.open(srcpath, 'r')
			if err is not None:
				raise err
			
			with open(dstpath, 'wb') as f:
				async for data, err in sfile.read_chunked():
					if err is not None:
						raise err
					
					f.write(data)
			
			return True, None
		except Exception as e:
			return False, e
		finally:
			if sfile is not None:
				await sfile.close()
	
	async def download_chunked(self, srcpath:str):
		"""Downloads a file from the remote server to the local machine"""
		try:
			sfile, err = await self.open(srcpath, 'r')
			if err is not None:
				raise err
			
			async for data, err in sfile.read_chunked():
				if err is not None:
					raise err
				
				yield data
		except Exception as e:
			raise e
		finally:
			if sfile is not None:
				await sfile.close()
	
	async def upload(self, srcpath:str, dstpath:str):
		"""Uploads a file from the local machine to the remote server"""
		sfile = None
		try:
			sfile, err = await self.open(dstpath, 'w')
			if err is not None:
				raise err
			
			with open(srcpath, 'rb') as f:
				while True:
					data = f.read(sfile.max_chunk_size)
					if len(data) == 0:
						break
					
					_, err = await sfile.write(data)
					if err is not None:
						raise err
					
			
			return True, None
		except Exception as e:
			return False, e
		finally:
			if sfile is not None:
				await sfile.close()

	async def enum_all(self, path:str = None, depth:int=3, filter_cb=None):
		"""Enumerates all files and directories in a given path"""
		try:
			if path is None:
				path, err = await self.cwd()
				if err is not None:
					raise err
			
			dirobj, err = await self.opendir(path)
			if err is not None:
				raise err

			async for entry, err in dirobj.ls_obj_r(depth = depth, filter_cb=filter_cb):
				if err is not None:
					yield entry, err
					continue
				yield entry, None
		except Exception as e:
			raise e
		finally:
			await dirobj.close()
	#async def rename_posix(self, oldpath:str, newpath:str):
	#	"""Renames a file or directory"""
	#	try:
	#		if 'posix-rename@openssh.com' not in self.server_extensions:
	#			raise Exception('Server does not support POSIX rename!')
	#		
	#		
	#		
	#		return True, None
	#	except Exception as e:
	#		return False, e


class SFTPFile:
	def __init__(self, path:str, mode:SSH_FXF=None, attrs:ATTRS=None, handle = None, session:SSHSFTPSession=None, longname:str=None):
		self.__session = session
		self.handle = handle
		self.path = path
		self.longname = longname
		self.attrs = attrs
		self.mode = mode
		self.__offset = 0
		self.max_chunk_size = 30000
	
	def __str__(self):
		return '<SFTPFile path=%s mode=%s>' % (self.path, self.mode)
	
	def to_uni_dict(self):
		return {
			'type': 'file',
			'name' : self.path.split('/')[-1],
			'fullpath' : self.path,
			'size' : self.attrs.size,
			'creationtime' : self.attrs.atime_windows,
			'lastaccesstime' : self.attrs.atime_windows,
			'lastwritetime' : self.attrs.mtime_windows,
			'changetime' : self.attrs.mtime_windows,
			'allocationsize' : self.attrs.size,
			'attributes' : self.attrs.to_dict(),
		}
		
	async def close(self):
		"""Closes the file."""
		if self.__session is None:
			return
		
		if self.handle is None:
			return
		
		await self.__session.send_message(SSH_FXP_CLOSE(self.handle))
		self.handle = None

	
	async def __read(self, offset:int, length:int):
		"""Internal read function."""
		fut = await self.__session.send_message(SSH_FXP_READ(self.handle, offset, length))
		packet, err = await fut
		if err is not None:
			raise err
		
		return packet.data
	
	def seek(self, offset:int, whence:int=0):
		"""Seeks to a position in the file."""
		if whence == 0:
			self.__offset = offset
		elif whence == 1:
			new_offset = self.attrs.size + offset
			if new_offset < 0 or new_offset > self.attrs.size:
				raise Exception('Invalid offset!')
			self.__offset += offset
		elif whence == 2:
			new_offset = self.attrs.size + offset
			if new_offset < 0 or new_offset > self.attrs.size:
				raise Exception('Invalid offset!')
			self.__offset = self.attrs.size + offset
		else:
			raise Exception('Invalid whence!')
	
	def tell(self):
		"""Returns the current position in the file."""
		return self.__offset
	
	async def read(self, n:int=-1):
		"""Reads a chunk of data from the file."""
		if self.__session is None:
			raise Exception('File not opened!')
		
		if self.handle is None:
			raise Exception('File not opened!')
		
		if n == -1:
			n = self.attrs.size - self.__offset
			if n <= 0:
				return b''
		
		data = b''
		while len(data) < n:
			# We read the minimum between the remaining bytes and the maximum chunk size
			bytes_to_read = min(self.max_chunk_size, n - len(data))
			chunk = await self.__read(self.__offset, bytes_to_read)
			if len(chunk) == 0:
				break
			data += chunk
			self.__offset += len(chunk)
		
		return data
	
	async def read_chunked(self, n:int=-1, chunk_size:int=30000):
		"""Reads a chunk of data from the file."""
		try:
			if self.__session is None or self.handle is None:
				raise Exception('File not opened!')

			if n == -1:
				n = self.attrs.size - self.__offset
				if n <= 0:
					yield b'', None
					return

			start_offset = self.__offset
			while (self.__offset - start_offset) < n:
				# We read the minimum between the remaining bytes and the maximum chunk size
				bytes_to_read = min(chunk_size, n - (self.__offset - start_offset))
				chunk = await self.__read(self.__offset, bytes_to_read)
				if len(chunk) == 0:
					break
				self.__offset += len(chunk)
				yield chunk, None

		except Exception as e:
			yield None, e

	async def __write(self, offset:int, data:bytes):
		try:
			"""Writes a chunk of data to the file."""
			if self.__session is None:
				raise Exception('File not opened!')
			
			if self.handle is None:
				raise Exception('File not opened!')
			
			fut = await self.__session.send_message(SSH_FXP_WRITE(self.handle, offset, data))
			packet, err = await fut
			if err is not None:
				raise err
			
			return True, None
		except Exception as e:
			return False, e
		
	def chunks(self, data):
		"""Yield successive max_chunk_size chunks from data."""
		for i in range(0, len(data), self.max_chunk_size):
			yield data[i:i + self.max_chunk_size]

	async def write(self, data:bytes):
		try:
			"""Writes a chunk of data to the file."""
			if self.__session is None:
				raise Exception('File not opened!')

			if self.handle is None:
				raise Exception('File not opened!')

			
			for chunk in self.chunks(data):
				_, err = await self.__write(self.__offset, chunk)
				if err is not None:
					raise err

				self.__offset += len(chunk)

			return True, None
		except Exception as e:
			return None, e
	
	async def close(self):
		"""Closes the file."""
		if self.__session is None:
			return
		
		if self.handle is None:
			return
		
		fut = await self.__session.send_message(SSH_FXP_CLOSE(self.handle))
		packet, err = await fut
		if err is not None:
			raise err
		
		self.handle = None
		self.__session = None
	
	async def stat(self):
		"""Gets the file attributes."""
		if self.__session is None:
			raise Exception('File not opened!')
		
		if self.handle is None:
			raise Exception('File not opened!')
		
		fut = await self.__session.send_message(SSH_FXP_FSTAT(self.handle))
		packet, err = await fut
		if err is not None:
			raise err
		
		return packet.attrs

class SFTPDirectory:
	def __init__(self, path, attrs=None, handle = None, session:SSHSFTPSession=None, longname:str=None, fullpath:str=None):
		self.__session = session
		self.handle = handle
		self.path = path
		self.attrs = attrs
		self.fullpath = Path(fullpath) if fullpath is not None else None
		self.longname = longname
	
	def __str__(self):
		return '<SFTPDirectory path=%s>' % self.path
	
	def to_uni_dict(self):
		return {
			'type': 'dir',
			'name' : str(self.fullpath).split('/')[-1],
			'fullpath' : str(self.fullpath),
			'size' : self.attrs.size,
			'creationtime' : self.attrs.atime_windows,
			'lastaccesstime' : self.attrs.atime_windows,
			'lastwritetime' : self.attrs.mtime_windows,
			'changetime' : self.attrs.mtime_windows,
			'allocationsize' : self.attrs.size,
			'attributes' : self.attrs.to_dict(),
		}
	
	async def open(self, session:SSHSFTPSession):
		"""Opens the directory for listing."""
		try:
			self.__session = session
			if self.handle is None:
				fut = await self.__session.send_message(SSH_FXP_OPENDIR(self.path))
				packet, err = await fut
				if err is not None:
					raise err
				
				self.handle = packet.handle
			if self.fullpath is None:
				self.fullpath, err = await self.__session.realpath(self.path)
				if err is not None:
					raise err
				self.fullpath = Path(self.fullpath)

			return self.handle, None
		except Exception as e:
			return None, e
	
	async def close(self):
		"""Closes the directory."""
		if self.__session is None:
			return
		
		if self.handle is None:
			return
		
		fut = await self.__session.send_message(SSH_FXP_CLOSE(self.handle))
		packet, err = await fut
		self.handle = None
		self.__session = None
	
	async def ls(self):
		"""Used after open() to list the directory contents."""
		while True:
			fut = await self.__session.send_message(SSH_FXP_READDIR(self.handle))
			packet, err = await fut
			if err is not None:
				raise err
			if packet is None:
				break

			for entry in packet.entries:
				yield entry

	async def ls_obj(self):
		"""Used after open() to list the directory contents."""
		try:
			while True:
				fut = await self.__session.send_message(SSH_FXP_READDIR(self.handle))
				packet, err = await fut
				if err is not None:
					raise err
				if packet is None:
					break
				
				for filename, longname, attrs in packet.entries:
					if filename == '.' or filename == '..':
						continue

					fullpath = str(self.fullpath.joinpath(filename).as_posix())
					if attrs.is_dir is True:
						yield SFTPDirectory(fullpath, attrs = attrs, session=self.__session, longname=longname, fullpath=fullpath), None
					else:
						yield SFTPFile(fullpath, mode = None, attrs = attrs, session=self.__session, longname=longname), None
		except Exception as e:
			traceback.print_exc()
			yield None, e

	async def ls_obj_r(self, depth:int = 3, filter_cb=None):
		"""Recursively list the directory contents."""
		if depth == 0:
			return
		async for entry, err in self.ls_obj():
			if err is not None:
				yield entry, err
				break
			if filter_cb is not None:
				tograb = await filter_cb(entry)
				if tograb is False:
					continue
			if entry.attrs.is_dir is True and depth > 1:
				_, err = await entry.open(self.__session)
				if err is not None:
					yield entry, err
					continue
				async for subentry, err in entry.ls_obj_r(depth = depth-1, filter_cb=filter_cb):
					yield subentry, err
				await entry.close()
			else:
				yield entry, None
		
		