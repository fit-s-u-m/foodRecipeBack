package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) Login(c *gin.Context) {
	resp := make(map[string]string)
	resp["email"] = "fitsumwondessen@gmail.com"
	resp["id"] = "10"
	resp["username"] = "keya"
	resp["accessToken"] = "accessToken"
	resp["refreshToken"] = "refreshToken"
	c.JSON(http.StatusOK, resp)
}
