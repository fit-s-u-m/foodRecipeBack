package auth

import (
	"fmt"
	utils "food-receipe-back/internal/util"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func SignupHandler(c *gin.Context) {
	var hasuraRequest HasuraSignUpPayload
	if err := c.BindJSON(&hasuraRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	var input = hasuraRequest.Input.Credential

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost) // generate password hash
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
	fmt.Println("Signup variables:", vars)

	resp, err := utils.HasuraRequest(query, vars)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	inserted, ok := resp["data"].(map[string]any)["insert_users_one"].(map[string]any)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid Hasura response"})
		return
	}

	c.JSON(http.StatusOK, inserted)
}
