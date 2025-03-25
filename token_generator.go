package jwter

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenGenerator handles JWT token generation
type TokenGenerator struct {
	config TokenConfig
}

// NewTokenGenerator creates a new TokenGenerator
func NewTokenGenerator(config TokenConfig) *TokenGenerator {
	return &TokenGenerator{
		config: config,
	}
}

// GenerateTokenPair generates an access token and refresh token for a user
func (g *TokenGenerator) GenerateTokenPair(claims UserClaims) (*TokenPair, error) {
	// Generate access token
	accessToken, err := g.generateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := g.generateRefreshToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// generateAccessToken creates the main access token
func (g *TokenGenerator) generateAccessToken(claims UserClaims) (string, error) {
	// Prepare standard claims
	standardClaims := jwt.MapClaims{
		"nbf":         time.Now().Unix(),
		"exp":         time.Now().Add(g.config.AccessExpires).Unix(),
		"user_type":   claims.UserType,
		"iss":         g.config.Issuer,
		"aud":         g.config.Audience,
		"iat":         time.Now().Unix(),
		"user_id":     claims.UserID,
		"uuid":        claims.UUID,
		"user_name":   claims.Username,
		"phone":       claims.Phone,
		"auth_method": g.config.AuthMethod,
	}

	// Add permissions if provided
	if len(claims.Permissions) > 0 {
		standardClaims["permissions"] = claims.Permissions
	}

	// Add any additional claims
	for k, v := range claims.AdditionalClaims {
		standardClaims[k] = v
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, standardClaims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// generateRefreshToken creates a refresh token
func (g *TokenGenerator) generateRefreshToken(claims UserClaims) (string, error) {
	// Prepare refresh token claims
	refreshClaims := jwt.MapClaims{
		"iss":       g.config.Issuer,
		"nbf":       time.Now().Unix(),
		"exp":       time.Now().Add(g.config.RefreshExpires).Unix(),
		"user_type": claims.UserType,
		"user_id":   claims.UserID,
		"uuid":      claims.UUID,
		"aud":       "refresh_token",
		"iat":       time.Now().Unix(),
	}

	// Create refresh token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(g.config.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateRefreshToken validates a refresh token and returns its claims
func (g *TokenGenerator) ValidateRefreshToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(g.config.Secret), nil
		},
	)

	// Check for parsing errors
	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	// Extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Additional audience validation
	aud, ok := claims["aud"].(string)
	if !ok || aud != "refresh_token" {
		return nil, fmt.Errorf("invalid token audience")
	}

	return claims, nil
}
