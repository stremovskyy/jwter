package jwter

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator adds validation methods to TokenGenerator
type TokenValidator struct {
	*TokenGenerator
	validationConfig TokenValidationConfig
}

// TokenValidationConfig provides configuration for token validation
type TokenValidationConfig struct {
	AllowedAudience string
	AllowedIssuers  map[string][]string // Key: user type, Value: allowed issuers
}

// NewTokenValidator creates a new TokenValidator
func NewTokenValidator(config TokenConfig, validationConfig TokenValidationConfig) *TokenValidator {
	return &TokenValidator{
		TokenGenerator:   NewTokenGenerator(config),
		validationConfig: validationConfig,
	}
}

// ValidateToken validates a JWT token
func (v *TokenValidator) ValidateToken(tokenString string, expectedUserType string, options ...ValidatorOption) (*jwt.MapClaims, error) {
	if options != nil {
		for _, option := range options {
			option(v)
		}
	}

	// Parse the token
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(v.config.Secret), nil
		},
	)

	// Check for parsing errors
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token has expired")
		}
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Validate required claims
	if err := v.validateRequiredClaims(claims, expectedUserType); err != nil {
		return nil, err
	}

	return &claims, nil
}

// validateRequiredClaims checks the validity of token claims
func (v *TokenValidator) validateRequiredClaims(claims jwt.MapClaims, expectedUserType string) error {
	// Check for required claims
	requiredClaims := []string{"aud", "iss", "user_id", "user_type"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	// Validate audience
	aud, ok := claims["aud"].(string)
	if !ok || aud != v.config.Audience {
		return errors.New("invalid audience")
	}

	// Validate user type and issuer
	userType, ok := claims["user_type"].(string)
	if !ok || userType != expectedUserType {
		return errors.New("invalid user type")
	}

	// Validate issuer based on user type
	issuer, ok := claims["iss"].(string)
	if !ok {
		return errors.New("invalid issuer")
	}

	// Check if the issuer is allowed for this user type
	allowedIssuers, exists := v.validationConfig.AllowedIssuers[expectedUserType]
	if !exists || !containsString(allowedIssuers, issuer) {
		return errors.New("invalid issuer for user type")
	}

	return nil
}

// ExtractUserFromClaims creates a user object from token claims
func (v *TokenValidator) ExtractUserFromClaims(claims jwt.MapClaims) *UserDetails {
	user := &UserDetails{
		UserID:      uint(claims["user_id"].(float64)),
		UserType:    claims["user_type"].(string),
		UUID:        claims["uuid"].(string),
		Username:    claims["user_name"].(string),
		Phone:       getStringFromClaims(claims, "phone"),
		Permissions: getStringSliceFromClaims(claims, "permissions"),
	}

	// Extract additional optional claims
	if serviceID, ok := claims["service_id"].(float64); ok {
		user.ServiceID = uint(serviceID)
	}

	return user
}

// Middleware creates a Gin middleware for token validation
func (v *TokenValidator) Middleware(expectedUserType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header or query parameter
		tokenString := extractTokenString(c)
		if tokenString == "" {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized, gin.H{
					"error": "No token provided",
				},
			)
			return
		}

		// Validate token
		claims, err := v.ValidateToken(tokenString, expectedUserType)
		if err != nil {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized, gin.H{
					"error": fmt.Sprintf("Token validation failed: %v", err),
				},
			)
			return
		}

		// Extract user details
		user := v.ExtractUserFromClaims(*claims)

		// Set user in context
		c.Set("user", user)
		c.Next()
	}
}

// Helper functions
func extractTokenString(c *gin.Context) string {
	// Check Authorization header first
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return authHeader
	}

	// Fallback to query parameter
	return c.Query("token")
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getStringFromClaims(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getStringSliceFromClaims(claims jwt.MapClaims, key string) []string {
	if val, ok := claims[key].([]string); ok {
		return val
	}
	if val, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(val))
		for _, v := range val {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

func (v *TokenValidator) ParseToken(tokenString string) (*jwt.MapClaims, error) {
	parser := jwt.NewParser()

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("token parsing error: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return &claims, nil
}
