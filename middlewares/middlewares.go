package middlewares

import (
	"jwt/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc{
	return func (c *gin.Context){
		clientToken := c.Request.Header.Get("Authoraization")
		if clientToken == ""{
			c.JSON(403, "No Authoriazation header provided")
			c.Abort()
			return
		}
		extractedToken := strings.Split(clientToken, "Bearer")
		if len(extractedToken) == 2{
			clientToken = strings.TrimSpace(extractedToken[1])
		} else {
			c.JSON(400, "Incorrect Fromat of Authorization Token")
			c.Abort()
			return
		}
		jwtWrapper := auth.JwtWrapper{
			SecretKey : "versecrykey",
			Issuer : "AuthService",
		}
		claims, err := jwtWrapper.ValidateToken(clientToken)
			if err != nil{
				c.JSON(401, err.Error())
				c.Abort()
				return
			}
			c.Set("email", claims.Email)
			c.Next()
		}
	}
