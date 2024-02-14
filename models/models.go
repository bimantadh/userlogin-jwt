package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID       int    `gorm:"primaryKey"`
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required" gorm:"unique"`
	Password string `json:"password" binding:"required"`
}

