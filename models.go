package jwter

import (
	"time"
)

// TokenConfig represents the configuration for token generation
type TokenConfig struct {
	Secret         string
	AccessExpires  time.Duration
	RefreshExpires time.Duration
	Issuer         string
	Audience       string
	AuthMethod     string
}

// UserClaims represents the standard claims for a user token
type UserClaims struct {
	UserType         string
	UserID           uint
	UUID             string
	Username         string
	Phone            string
	Permissions      []string
	AdditionalClaims map[string]interface{}
}

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// UserDetails represents the extracted user information from token claims
type UserDetails struct {
	UserID      uint
	UserType    string
	UUID        string
	Username    string
	Phone       string
	Permissions []string
	ServiceID   uint
}
