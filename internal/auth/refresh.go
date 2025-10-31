package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RefreshHandler(c *gin.Context) {
	var HasuraRefreshPayload HasuraRefreshPayload
	if err := c.ShouldBindJSON(&HasuraRefreshPayload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	refreshToken := HasuraRefreshPayload.Input.RefreshToken

	claims, err := VerifyRefreshToken(refreshToken)
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
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}
