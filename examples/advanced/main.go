package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/jwter"
)

func main() {
	// Create JWTER configuration
	config := jwter.Config{
		Secret:         "your-secret-key",
		AccessExpires:  time.Hour * 1,
		RefreshExpires: time.Hour * 24 * 7,
		Issuer:         "example-app",
		Audience:       "example-users",
		AuthMethod:     "password",
		AllowedIssuers: map[string][]string{
			"user":    {"example-app"},
			"admin":   {"example-app", "admin-service"},
			"service": {"service-registry"},
		},
	}

	// Create JWTER instance
	jwt := jwter.New(config)

	// Create Gin router
	r := gin.Default()

	// Example 1: Regular user login
	r.POST(
		"/login", func(c *gin.Context) {
			claims := jwter.UserClaims{
				UserType:    "user",
				UserID:      123,
				UUID:        "user-uuid",
				Username:    "john_doe",
				Phone:       "+1234567890",
				Permissions: []string{"read", "write"},
			}

			tokens, err := jwt.GenerateTokens(claims)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate tokens"})
				return
			}

			c.JSON(200, tokens)
		},
	)

	// Example 2: Admin user login with additional claims
	r.POST(
		"/admin/login", func(c *gin.Context) {
			claims := jwter.UserClaims{
				UserType:    "admin",
				UserID:      456,
				UUID:        "admin-uuid",
				Username:    "admin_user",
				Phone:       "+1987654321",
				Permissions: []string{"read", "write", "delete", "manage_users"},
				AdditionalClaims: map[string]interface{}{
					"role":         "super_admin",
					"department":   "IT",
					"access_level": 10,
				},
			}

			tokens, err := jwt.GenerateTokens(claims)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate tokens"})
				return
			}

			c.JSON(200, tokens)
		},
	)

	// Example 3: Service-to-service authentication
	r.POST(
		"/service/login", func(c *gin.Context) {
			claims := jwter.UserClaims{
				UserType:    "service",
				UserID:      789,
				UUID:        "service-uuid",
				Username:    "payment-service",
				Permissions: []string{"process_payment", "read_transactions"},
				AdditionalClaims: map[string]interface{}{
					"service_type": "payment",
					"version":      "1.0",
					"environment":  "production",
				},
			}

			tokens, err := jwt.GenerateTokens(claims)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate tokens"})
				return
			}

			c.JSON(200, tokens)
		},
	)

	// Example 4: Protected admin routes with role validation
	r.GET(
		"/admin/dashboard", jwt.Middleware("admin"), func(c *gin.Context) {
			user := c.MustGet("user").(*jwter.UserDetails)
			c.JSON(
				200, gin.H{
					"message": fmt.Sprintf("Welcome to admin dashboard, %s!", user.Username),
					"user":    user,
				},
			)
		},
	)

	// Example 5: Service-to-service protected route
	r.GET(
		"/api/payments", jwt.Middleware("service"), func(c *gin.Context) {
			user := c.MustGet("user").(*jwter.UserDetails)
			c.JSON(
				200, gin.H{
					"message": fmt.Sprintf("Service %s accessed payment API", user.Username),
					"user":    user,
				},
			)
		},
	)

	// Example 6: Token refresh with validation
	r.POST(
		"/refresh", func(c *gin.Context) {
			var req struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			// Validate refresh token
			claims, err := jwt.ValidateRefreshToken(req.RefreshToken)
			if err != nil {
				c.JSON(401, gin.H{"error": "Invalid refresh token"})
				return
			}

			// Create new user claims from refresh token
			userClaims := jwter.UserClaims{
				UserType: claims["user_type"].(string),
				UserID:   uint(claims["user_id"].(float64)),
				UUID:     claims["uuid"].(string),
			}

			// Generate new token pair
			tokens, err := jwt.GenerateTokens(userClaims)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate new tokens"})
				return
			}

			c.JSON(200, tokens)
		},
	)

	// Example 7: Token validation with custom claims extraction
	r.POST(
		"/validate", func(c *gin.Context) {
			var req struct {
				Token        string `json:"token"`
				UserType     string `json:"user_type"`
				ExpectedRole string `json:"expected_role,omitempty"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			// Validate token
			claims, err := jwt.ValidateToken(req.Token, req.UserType)
			if err != nil {
				c.JSON(401, gin.H{"error": fmt.Sprintf("Token validation failed: %v", err)})
				return
			}

			// Extract user details
			user := jwt.ExtractUser(*claims)

			// Check additional claims if needed
			if req.ExpectedRole != "" {
				if role, ok := (*claims)["role"].(string); !ok || role != req.ExpectedRole {
					c.JSON(403, gin.H{"error": "Insufficient permissions"})
					return
				}
			}

			c.JSON(
				200, gin.H{
					"valid":  true,
					"user":   user,
					"claims": claims,
				},
			)
		},
	)

	// Start server
	log.Fatal(r.Run(":8080"))
}
