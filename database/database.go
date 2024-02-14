package database

import (
	"jwt/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var GlobalDB *gorm.DB

func ConnectDatabase() {
	dsn := "host=localhost user=postgres password=root dbname=test port=5432 sslmode=disable"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to database")
	}
	database.AutoMigrate(models.User{})

	GlobalDB = database
}
