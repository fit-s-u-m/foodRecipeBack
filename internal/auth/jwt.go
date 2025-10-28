package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var accessSecret = []byte("access-secret-key")
var refreshSecret = []byte("refresh-secret-key")

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// Generate both access and refresh tokens
func GenerateTokens(userID string) (accessToken string, refreshToken string, err error) {
	// Access token (short-lived)
	accessClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // 15 min
		},
	}
	atoken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = atoken.SignedString(accessSecret)
	if err != nil {
		return
	}

	// Refresh token (long-lived)
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
		},
	}
	rtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = rtoken.SignedString(refreshSecret)
	return
}

// Verify access token
func VerifyAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return accessSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}

// Verify refresh token
func VerifyRefreshToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return refreshSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}
