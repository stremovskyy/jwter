package jwter

type ValidatorOption func(*TokenValidator)

func WithSecret(secret string) ValidatorOption {
	return func(v *TokenValidator) {
		v.config.Secret = secret
	}
}
