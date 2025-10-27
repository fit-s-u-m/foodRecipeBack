package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) Login(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Login"
	c.JSON(http.StatusOK, resp)
}
