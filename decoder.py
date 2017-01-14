# Unfortunately, pyjwt does not support JWK.
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from jwkest.jwt import JWT

# Unfortunately, jwkest does not support claim verification.
from jwt.api_jwt import _jwt_global_obj

# Unfortunately, jwkest does not support caching.
import requests
from cachecontrol import CacheControl

# Unfortunately, jwkest's API was designed by a chimpanzee.
from .util import rsa_to_jwk
# On the second thought, chimpanzee would do it better.

class TokenDecoder:
	def __init__(self, audience, issuer, jwks_endpoint=None, keys=None, do_not_verify_signature=False):
		self.audience = audience
		self.issuer = issuer

		self.do_not_verify_signature = do_not_verify_signature

		if keys:
			self._keys = KEYS()
			for key in rsa_to_jwk(keys, alg=None):
				self._keys.append(key)
		else:
			self.jwks_endpoint = jwks_endpoint
			self.sess = requests.session()

	@property
	def keys(self):
		if hasattr(self, "_keys"):
			return self._keys

		keys = KEYS()
		keys.load_dict(self.sess.get(self.jwks_endpoint).json())
		return keys

	def __call__(self, token):
		try:
			if self.do_not_verify_signature:
				payload = JWT().unpack(token).payload()
			else:
				payload = JWS().verify_compact(token, self.keys)
			_jwt_global_obj._validate_claims(payload, audience=self.audience, issuer=self.issuer, options=dict(require_exp=True, require_iat=True, verify_iss=(self.issuer is not None), verify_aud=(self.audience is not None)))
			return payload
		except:
			# TODO wrap the exception in something prettier
			raise
