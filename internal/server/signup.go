package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) Signup(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Sign up"
	c.JSON(http.StatusOK, resp)
}
