from .util import rsa_to_jwk
from jwkest.jws import JWS
from time import time

class TokenEncoder:
	def __init__(self, issuer, keys, default_ttl=None, default_aud=None, alg="RS256"):
		self.issuer = issuer
		self.keys = rsa_to_jwk(keys, alg)
		self.default_ttl = default_ttl
		self.default_aud = default_aud

	def __call__(self, payload, ttl=None, aud=None):
		iat = int(time())
		if ttl is None:
			ttl = self.default_ttl
		if aud is None:
			aud = self.default_aud
		exp = iat + ttl
		new_payload = {**payload, "iss": self.issuer, "aud": aud, "iat": iat, "exp": exp}
		return JWS(new_payload).sign_compact([self.keys[0]])
