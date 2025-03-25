package jwter

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWTER is the root object that provides the main interface for the library
type JWTER struct {
	generator *TokenGenerator
	validator *TokenValidator
}

// Config represents the complete configuration for the JWTER library
type Config struct {
	Secret         string              // Secret key for signing tokens
	AccessExpires  time.Duration       // Access token expiration time
	RefreshExpires time.Duration       // Refresh token expiration time
	Issuer         string              // Token issuer
	Audience       string              // Token audience
	AuthMethod     string              // Authentication method
	AllowedIssuers map[string][]string // Allowed issuers per user type
}

// New creates a new JWTER instance with the given configuration
func New(config Config) *JWTER {
	tokenConfig := TokenConfig{
		Secret:         config.Secret,
		AccessExpires:  config.AccessExpires,
		RefreshExpires: config.RefreshExpires,
		Issuer:         config.Issuer,
		Audience:       config.Audience,
		AuthMethod:     config.AuthMethod,
	}

	validationConfig := TokenValidationConfig{
		AllowedAudience: config.Audience,
		AllowedIssuers:  config.AllowedIssuers,
	}

	return &JWTER{
		generator: NewTokenGenerator(tokenConfig),
		validator: NewTokenValidator(tokenConfig, validationConfig),
	}
}

// GenerateTokens creates a new pair of access and refresh tokens for the given claims
func (j *JWTER) GenerateTokens(claims UserClaims) (*TokenPair, error) {
	return j.generator.GenerateTokenPair(claims)
}

// ValidateToken validates a JWT token and returns its claims
func (j *JWTER) ValidateToken(token string, expectedUserType string) (*jwt.MapClaims, error) {
	return j.validator.ValidateToken(token, expectedUserType)
}

// ValidateRefreshToken validates a refresh token and returns its claims
func (j *JWTER) ValidateRefreshToken(token string) (jwt.MapClaims, error) {
	return j.generator.ValidateRefreshToken(token)
}

// ExtractUser extracts user details from token claims
func (j *JWTER) ExtractUser(claims jwt.MapClaims) *UserDetails {
	return j.validator.ExtractUserFromClaims(claims)
}

// Middleware creates a Gin middleware for token validation
func (j *JWTER) Middleware(expectedUserType string) gin.HandlerFunc {
	return j.validator.Middleware(expectedUserType)
}
