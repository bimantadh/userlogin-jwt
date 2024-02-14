package controllers

import (
	"jwt/auth"
	"jwt/database"
	"jwt/handlers"
	"jwt/models"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type LoginPayload struct {
    Email    string `json:"email" binding:"required" gorm:"unique" `
    Password string `json:"password" binding:"required"`
	
}

type LoginResponse struct {
    Token        string `json:"token"`
    RefreshToken string `json:"refreshtoken"`
}

func Signup(c *gin.Context) {
    var user models.User
    err := c.ShouldBindJSON(&user)
    if err != nil {
        log.Print(err)
        c.JSON(400, gin.H{
            "Error": "Invalid Inputs",
        })
        return
    }

    var existingUser models.User
    result := database.GlobalDB.Where("email =?", user.Email).First(&existingUser)
    if result.Error == nil {
        c.JSON(409, gin.H{
            "Error": "Email already in use",
        })
        return
    } else if result.Error != gorm.ErrRecordNotFound {

		log.Println(result.Error)
        c.JSON(500, gin.H{
            "Error": "Error checking email availability",
        })
        return
    }

    err = handlers.HashPassword(&user, user.Password)
    if err != nil {
        log.Println(err.Error())
        c.JSON(500, gin.H{
            "Error": "Error Hashing Password",
        })
        return
    }

    err = handlers.CreateUserRecord(&user)
    if err != nil {
        log.Println(err)
        c.JSON(500, gin.H{
            "Error": "Error Creating User",
        })
        return
    }

    c.JSON(200, gin.H{
        "Message": "Successfully Registered",
    })
}

func Login (c *gin.Context){
	var payload LoginPayload
	var user models.User
	err := c.ShouldBindJSON(&payload)
	if err != nil {
		c.JSON(400, gin.H{
			"Error": "Invalid Inputs",
		})
		c.Abort()
		return
	}
	result := database.GlobalDB.Where("email =?", payload.Email).First(&user)
	if result.Error == gorm.ErrRecordNotFound {
		c.JSON(401, gin.H{
			"Error" : "Invalid User Credentials",
		})
		c.Abort()
		return

	}
	err = handlers.CheckPassword(&user , payload.Password)
	if err != nil{
		log.Println(err)
		c.JSON(401, gin.H{
			"Error" : "Invalid User Credentials",
		})
		c.Abort()
		return 
	}
	jwtWrapper := auth.JwtWrapper{
		SecretKey: "verysecretkey",
		Issuer: "AuthService",
		ExpirationMinutes: 1,
		ExpirationHours: 12,

	}
	signedToken, err := jwtWrapper.GenerateToken(user.Email)
	if err !=nil{
		log.Println(err)
		c.JSON(500, gin.H{
			"Error": "Error Signing Token",
			
		})
		c.Abort()
  		return
	}
	tokenResponse :=LoginResponse{
		Token: signedToken,
		RefreshToken : signedToken,
	}
	c.JSON(200, tokenResponse)
}