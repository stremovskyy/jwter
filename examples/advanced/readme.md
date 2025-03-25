### Endpoint: `/login`

**Description:** Regular user login.

**Method:** POST

**Request Body:**

```json
{
  "username": "john_doe",
  "password": "your-password"
}
```

**Example:**

```sh
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"username": "john_doe", "password": "your-password"}'
```

### Endpoint: `/admin/login`

**Description:** Admin user login with additional claims.

**Method:** POST

**Request Body:**

```json
{
  "username": "admin_user",
  "password": "your-password"
}
```

**Example:**

```sh
curl -X POST http://localhost:8080/admin/login -H "Content-Type: application/json" -d '{"username": "admin_user", "password": "your-password"}'
```

### Endpoint: `/service/login`

**Description:** Service-to-service authentication.

**Method:** POST

**Request Body:**

```json
{
  "service_name": "payment-service",
  "api_key": "your-api-key"
}
```

**Example:**

```sh
curl -X POST http://localhost:8080/service/login -H "Content-Type: application/json" -d '{"service_name": "payment-service", "api_key": "your-api-key"}'
```

### Endpoint: `/admin/dashboard`

**Description:** Protected admin routes with role validation.

**Method:** GET

**Headers:**

- `Authorization: Bearer <access_token>`

**Example:**

```sh
curl -X GET http://localhost:8080/admin/dashboard -H "Authorization: Bearer <access_token>"
```

### Endpoint: `/api/payments`

**Description:** Service-to-service protected route.

**Method:** GET

**Headers:**

- `Authorization: Bearer <access_token>`

**Example:**

```sh
curl -X GET http://localhost:8080/api/payments -H "Authorization: Bearer <access_token>"
```

### Endpoint: `/refresh`

**Description:** Token refresh with validation.

**Method:** POST

**Request Body:**

```json
{
  "refresh_token": "your-refresh-token"
}
```

**Example:**

```sh
curl -X POST http://localhost:8080/refresh -H "Content-Type: application/json" -d '{"refresh_token": "your-refresh-token"}'
```

### Endpoint: `/validate`

**Description:** Token validation with custom claims extraction.

**Method:** POST

**Request Body:**

```json
{
  "token": "your-token",
  "user_type": "user",
  "expected_role": "optional-expected-role"
}
```

**Example:**

```sh
curl -X POST http://localhost:8080/validate -H "Content-Type: application/json" -d '{"token": "your-token", "user_type": "user", "expected_role": "optional-expected-role"}'
```
