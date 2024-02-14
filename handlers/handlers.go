package handlers

import (
    "jwt/database"
    "jwt/models"

    "golang.org/x/crypto/bcrypt"
)

func CreateUserRecord(user *models.User) error {
    result := database.GlobalDB.Create(&user)
    if result.Error != nil {
        return result.Error
    }
    return nil
}

func HashPassword(user *models.User, password string) error {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    if err != nil {
        return err
    }

    user.Password = string(bytes)
    return nil
}

func CheckPassword(user *models.User, providedPassword string) error {
    err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
    if err != nil {
        return err
    }
    return nil
}
