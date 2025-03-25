# JWTER

A flexible and secure JWT token generation and validation library for Go applications.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Using with Gin Framework](#using-with-gin-framework)
- [Configuration](#configuration)
  - [TokenConfig](#tokenconfig)
  - [TokenValidationConfig](#tokenvalidationconfig)
- [Contributing](#contributing)
- [License](#license)

## Features

- Generate and validate JWT access and refresh tokens
- Configurable token expiration times
- Support for custom claims and permissions
- Built-in middleware for Gin framework
- Type-safe token validation
- Configurable issuer and audience validation
- Support for multiple user types and issuers

## Installation

To install the library, use the following command:

```bash
go get github.com/stremovskyy/jwter
```

## Quick Start

Here's a quick example to get you started with generating and validating JWT tokens:

```go
package main

import (
    "time"
    "github.com/stremovskyy/jwter"
)

func main() {
    // Create token configuration
    config := jwter.TokenConfig{
        Secret:         "your-secret-key",
        AccessExpires:  time.Hour * 1,
        RefreshExpires: time.Hour * 24 * 7,
        Issuer:         "your-issuer",
        Audience:       "your-audience",
        AuthMethod:     "password",
    }

    // Create token generator
    generator := jwter.NewTokenGenerator(config)

    // Create user claims
    claims := jwter.UserClaims{
        UserType:    "user",
        UserID:      123,
        UUID:        "user-uuid",
        Username:    "john_doe",
        Phone:       "+1234567890",
        Permissions: []string{"read", "write"},
    }

    // Generate token pair
    tokens, err := generator.GenerateTokenPair(claims)
    if err != nil {
        panic(err)
    }

    // Use the tokens
    accessToken := tokens.AccessToken
    refreshToken := tokens.RefreshToken
}
```

## Using with Gin Framework

To use JWTER with the Gin framework, follow this example:

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/stremovskyy/jwter"
)

func main() {
    r := gin.Default()

    // Create token validator
    config := jwter.TokenConfig{
        Secret:    "your-secret-key",
        Issuer:    "your-issuer",
        Audience:  "your-audience",
    }

    validationConfig := jwter.TokenValidationConfig{
        AllowedAudience: "your-audience",
        AllowedIssuers: map[string][]string{
            "user": {"your-issuer"},
        },
    }

    validator := jwter.NewTokenValidator(config, validationConfig)

    // Protected route with token validation
    r.GET("/protected", validator.Middleware("user"), func(c *gin.Context) {
        user := c.MustGet("user").(*jwter.UserDetails)
        c.JSON(200, gin.H{"message": "Hello " + user.Username})
    })

    r.Run()
}
```

## Configuration

### TokenConfig

The `TokenConfig` struct is used to configure the token generation settings:

```go
type TokenConfig struct {
    Secret         string        // Secret key for signing tokens
    AccessExpires  time.Duration // Access token expiration time
    RefreshExpires time.Duration // Refresh token expiration time
    Issuer         string        // Token issuer
    Audience       string        // Token audience
    AuthMethod     string        // Authentication method
}
```

### TokenValidationConfig

The `TokenValidationConfig` struct is used to configure the token validation settings:

```go
type TokenValidationConfig struct {
    AllowedAudience string              // Allowed audience for tokens
    AllowedIssuers  map[string][]string // Allowed issuers per user type
}
```

## Contributing

We welcome contributions to the JWTER project. To contribute, please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
