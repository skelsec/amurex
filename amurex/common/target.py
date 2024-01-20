import copy
from urllib.parse import urlparse, parse_qs
from typing import List
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget


class SSHTarget(UniTarget):
	def __init__(self, ip:str = None, 
						port:int = 22, 
						hostname:str = None, 
						timeout:int = 5, 
						dc_ip:str =None, 
						domain:str = None, 
						proxies:List[UniProxyTarget] = None,
						protocol:UniProto = UniProto.CLIENT_TCP,
						dns:str = None,
						path:str = None,
						):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns)
		
		self.path:str = path #for holding remote file path

	def to_target_string(self) -> str:
		return 'ssh/%s@%s' % (self.hostname, self.domain)

	def get_copy(self, ip, port, hostname = None):
		t = SSHTarget(
			ip = ip, 
			port = port, 
			hostname = hostname, 
			timeout = self.timeout, 
			dc_ip= self.dc_ip, 
			domain = self.domain, 
			proxies = copy.deepcopy(self.proxies),
			protocol = self.protocol,
			path=self.path
		)

		return t
	
	@staticmethod
	def from_url(connection_url):
		url_e = urlparse(connection_url)
		port = 22
		if url_e.port:
			port = url_e.port
		
		path = None
		if url_e.path not in ['/', '', None]:
			path = url_e.path
		
		unitarget, _ = UniTarget.from_url(connection_url, UniProto.CLIENT_TCP, port)

		target = SSHTarget(
			ip = unitarget.ip,
			port = unitarget.port,
			hostname = unitarget.hostname,
			timeout = unitarget.timeout,
			dc_ip = unitarget.dc_ip,
			domain = unitarget.domain,
			proxies = unitarget.proxies,
			protocol = unitarget.protocol,
			dns = unitarget.dns,
			path = path
		)
		return target

	def __str__(self):
		t = '==== SSHTarget ====\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for x in self.__dict__[k]:
					t += '    %s: %s\r\n' % (k, x)
			else:
				t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
