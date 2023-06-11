from asyauth.common.constants import asyauthProtocol, asyauthSecret, asyauthSubProtocol
from asyauth.common.credentials import UniCredential
from amurex.crypto.keys import SSHKeyAlgo

class SSHCredentialPassword(UniCredential):
    def __init__(self, username, password, domain = None):
        UniCredential.__init__(
			self, 
			secret = password,
			username = username,
			domain = domain,
			stype = asyauthSecret.PASSWORD,
			protocol = asyauthProtocol.PLAIN,
			subprotocol = asyauthSubProtocol.NATIVE)

class SSHCredentialPrivKey(UniCredential):
    def __init__(self, username, privkey, passphrase, domain = None):
        try:
            with open(privkey, 'rb') as f:
                privkey = f.read()
        except:
            pass

        UniCredential.__init__(
			self, 
			secret = privkey,
			username = username,
			domain = domain,
			stype = asyauthSecret.SSHPRIVKEY,
			protocol = asyauthProtocol.PLAIN,
			subprotocol = asyauthSubProtocol.NATIVE)
        self.privkeypass = passphrase

    def build_context(self):
        return SSHKeyAlgo.load_privkey_file_bytes(self.secret, passphrase=self.privkeypass)