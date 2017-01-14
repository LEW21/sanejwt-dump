from jwkest.jwk import jwk_wrap, import_rsa_key

def rsa_to_jwk(key, alg):
	# TODO support multiple keys in a single file
	jwk = jwk_wrap(import_rsa_key(key))
	jwk.alg = alg
	jwk.kid = jwk.to_dict()["n"]
	return [jwk]
