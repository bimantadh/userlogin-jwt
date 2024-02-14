package main

import (
	"jwt/controllers"
	"jwt/database"
	// "jwt/middlewares"
	"github.com/gin-gonic/gin"
)
func main(){
	router := gin.Default()
	database.ConnectDatabase()
	router.POST("/login",controllers.Login )
	router.POST("/singup", controllers.Signup)
	router.Run(":8080")
}