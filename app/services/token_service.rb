require 'jwt'

class TokenService
	include Singleton
	
	def initialize
		@rsa_private = OpenSSL::PKey::RSA.new File.read('config/jwt.key'), 
		Rails.application.credentials.rsa_key
		@rsa_public = @rsa_private.public_key
	end

	def validate(token)
		decoded = (JWT.decode token, @rsa_public, true, { algorithm: 'RS512' })[0]

		if Time.now >= Time.at(decoded['exp'])
			raise JWT::ExpiredSignature
		elsif decoded['aud'] != 'unathesis'
			raise JWT::InvalidAudError
		elsif decoded['iss'] != 'unathesis_client'
			raise JWT::InvalidIssuerError
		end

		return decoded
	end

	def encode(payload, expiration=6.hours.from_now.to_i, issuer = 'unathesis_client')
		meta = { iss: issuer, exp: expiration, aud: 'unathesis' }
		payload.reverse_merge! meta
		JWT.encode payload, @rsa_private, 'RS512'
	end
end