from time import time
import jwt

class SymmetricTokenCoder:
	def __init__(self, service, keys, default_ttl=None, encode_alg="HS256", decode_algs=["HS256", "HS384", "HS512"]):
		self.service = service
		self.keys = keys
		self.default_ttl = default_ttl
		self.encode_alg = encode_alg
		self.decode_algs = decode_algs

	def encode(self, payload, ttl=None):
		iat = int(time())
		if ttl is None:
			ttl = self.default_ttl
		exp = iat + ttl
		new_payload = {**payload, "iss": self.service, "aud": self.service, "iat": iat, "exp": exp}
		return jwt.encode(new_payload, self.keys[0], algorithm=self.encode_alg)

	def decode(self, token):
		try:
			return jwt.decode(token, self.keys[0], audience=self.service, issuer=self.service, options=dict(require_exp=True, require_iat=True, verify_iss=(self.service is not None), verify_aud=(self.service is not None)))
		except:
			# TODO wrap the exception in something prettier
			raise
