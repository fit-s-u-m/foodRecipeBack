package auth

import (
	"net/http"

	"food-receipe-back/internal/util"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func LoginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Query Hasura to get the user by email
	query := `
	query ($email: String!) {
		users(where: {email: {_eq: $email}}) {
			id
			password_hash
		}
	}`
	variables := map[string]any{"email": req.Email}

	res, err := utils.HasuraRequest(query, variables)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query Hasura"})
		return
	}

	// 2. Extract user info
	usersData, ok := res["data"].(map[string]interface{})["users"].([]interface{})
	if !ok || len(usersData) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	user := usersData[0].(map[string]interface{})
	userID := user["id"].(string)
	passwordHash := user["password_hash"].(string)

	// 3. Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// 4. Generate JWT tokens using your util
	accessToken, refreshToken, err := GenerateTokens(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// 5. Return tokens
	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func RefreshHandler(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	accessToken, refreshToken, err := GenerateTokens(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

type SignupInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func SignupHandler(c *gin.Context) {
	var input SignupInput
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	query := `
	mutation ($username: String!, $email: String!, $password_hash: String!) {
		insert_users_one(object: {
			username: $username,
			email: $email,
			password_hash: $password_hash
		}) {
			id
			username
			email
		}
	}`

	vars := map[string]any{
		"username":      input.Username,
		"email":         input.Email,
		"password_hash": string(hashed),
	}

	resp, err := utils.HasuraRequest(query, vars)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": resp})
}
