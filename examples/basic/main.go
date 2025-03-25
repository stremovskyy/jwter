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
			"user": {"example-app"},
		},
	}

	// Create JWTER instance
	jwt := jwter.New(config)

	// Create Gin router
	r := gin.Default()

	// Login endpoint to generate tokens
	r.POST(
		"/login", func(c *gin.Context) {
			// In a real application, you would validate credentials here
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

	// Protected endpoint
	r.GET(
		"/protected", jwt.Middleware("user"), func(c *gin.Context) {
			user := c.MustGet("user").(*jwter.UserDetails)
			c.JSON(
				200, gin.H{
					"message": fmt.Sprintf("Hello %s!", user.Username),
					"user":    user,
				},
			)
		},
	)

	// Refresh token endpoint
	r.POST(
		"/refresh", func(c *gin.Context) {
			var req struct {
				RefreshToken string `json:"refresh_token"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

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

	// Start server
	log.Fatal(r.Run(":8080"))
}
