package auth

import (
	"fmt"
	"food-receipe-back/internal/util"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(c *gin.Context) {
	var payload HasuraLoginPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body", "code": "bad-request"})
		return
	}

	req := payload.Input.Credential
	fmt.Println("Received login request:", req.Email, req.Password)

	query := `
	query ($email: String!) {
		users(where: {email: {_eq: $email}}) {
			id
			password_hash
		}
	}`
	variables := map[string]any{"email": req.Email}

	res, err := utils.HasuraRequest(query, variables)
	fmt.Println(res, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query Hasura"})
		return
	}

	usersData, ok := res["data"].(map[string]any)["users"].([]any)
	if !ok || len(usersData) == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "invalid-credentials",
		})
		return
	}

	user := usersData[0].(map[string]any)
	userID := user["id"].(string)
	passwordHash := user["password_hash"].(string)

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
			"code":  "invalid-credentials",
		})

		return
	}

	accessToken, refreshToken, err := GenerateTokens(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"userId":       userID,
	})
}
