package jwter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenGenerationAndValidation(t *testing.T) {
	// Create test configuration
	config := Config{
		Secret:         "test-secret",
		AccessExpires:  time.Hour * 1,
		RefreshExpires: time.Hour * 24,
		Issuer:         "test-issuer",
		Audience:       "test-audience",
		AuthMethod:     "test",
		AllowedIssuers: map[string][]string{
			"test-user": {"test-issuer"},
		},
	}

	// Create JWTER instance
	jwt := New(config)

	// Create test claims
	claims := UserClaims{
		UserType:    "test-user",
		UserID:      123,
		UUID:        "test-uuid",
		Username:    "testuser",
		Phone:       "+1234567890",
		Permissions: []string{"read", "write"},
	}

	// Generate token pair
	tokens, err := jwt.GenerateTokens(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)

	// Validate refresh token
	refreshClaims, err := jwt.ValidateRefreshToken(tokens.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "test-user", refreshClaims["user_type"])
	assert.Equal(t, float64(123), refreshClaims["user_id"])
	assert.Equal(t, "test-uuid", refreshClaims["uuid"])
	assert.Equal(t, "refresh_token", refreshClaims["aud"])
}

func TestTokenValidation(t *testing.T) {
	// Create test configuration
	config := Config{
		Secret:         "test-secret",
		AccessExpires:  time.Hour * 1,  // Set access token expiration
		RefreshExpires: time.Hour * 24, // Set refresh token expiration
		Issuer:         "test-issuer",
		Audience:       "test-audience",
		AuthMethod:     "test",
		AllowedIssuers: map[string][]string{
			"test-user": {"test-issuer"},
		},
	}

	// Create JWTER instance
	jwt := New(config)

	// Create test claims
	claims := UserClaims{
		UserType: "test-user",
		UserID:   123,
		UUID:     "test-uuid",
		Username: "testuser",
	}

	// Generate token
	tokens, err := jwt.GenerateTokens(claims)
	assert.NoError(t, err)

	// Validate token immediately after generation
	validatedClaims, err := jwt.ValidateToken(tokens.AccessToken, "test-user")
	assert.NoError(t, err)
	assert.NotNil(t, validatedClaims)
	assert.Equal(t, "test-user", (*validatedClaims)["user_type"])
	assert.Equal(t, float64(123), (*validatedClaims)["user_id"])
	assert.Equal(t, "test-uuid", (*validatedClaims)["uuid"])

	// Test invalid user type
	_, err = jwt.ValidateToken(tokens.AccessToken, "invalid-user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid user type")
}

func TestUserDetailsExtraction(t *testing.T) {
	// Create test configuration
	config := Config{
		Secret:         "test-secret",
		AccessExpires:  time.Hour * 1,  // Set access token expiration
		RefreshExpires: time.Hour * 24, // Set refresh token expiration
		Issuer:         "test-issuer",
		Audience:       "test-audience",
		AuthMethod:     "test",
		AllowedIssuers: map[string][]string{
			"test-user": {"test-issuer"},
		},
	}

	// Create JWTER instance
	jwt := New(config)

	// Create test claims
	claims := UserClaims{
		UserType:    "test-user",
		UserID:      123,
		UUID:        "test-uuid",
		Username:    "testuser",
		Phone:       "+1234567890",
		Permissions: []string{"read", "write"},
	}

	// Generate token
	tokens, err := jwt.GenerateTokens(claims)
	assert.NoError(t, err)

	// Validate token and extract user details
	validatedClaims, err := jwt.ValidateToken(tokens.AccessToken, "test-user")
	assert.NoError(t, err)
	assert.NotNil(t, validatedClaims)

	user := jwt.ExtractUser(*validatedClaims)
	assert.NotNil(t, user)
	assert.Equal(t, uint(123), user.UserID)
	assert.Equal(t, "test-user", user.UserType)
	assert.Equal(t, "test-uuid", user.UUID)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "+1234567890", user.Phone)
	assert.Equal(t, []string{"read", "write"}, user.Permissions)
}

func TestTokenExpiration(t *testing.T) {
	// Create test configuration with very short expiration
	config := Config{
		Secret:         "test-secret",
		AccessExpires:  time.Millisecond * 100, // Very short expiration
		RefreshExpires: time.Hour * 24,
		Issuer:         "test-issuer",
		Audience:       "test-audience",
		AuthMethod:     "test",
		AllowedIssuers: map[string][]string{
			"test-user": {"test-issuer"},
		},
	}

	// Create JWTER instance
	jwt := New(config)

	// Create test claims
	claims := UserClaims{
		UserType: "test-user",
		UserID:   123,
		UUID:     "test-uuid",
		Username: "testuser",
	}

	// Generate token
	tokens, err := jwt.GenerateTokens(claims)
	assert.NoError(t, err)

	// Wait for token to expire
	time.Sleep(time.Millisecond * 150)

	// Try to validate expired token
	_, err = jwt.ValidateToken(tokens.AccessToken, "test-user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has expired")
}
