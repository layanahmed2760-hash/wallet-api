package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Username string `json:"username" gorm:"unique;not null"`
	Password string `json:"-" gorm:"not null"`
	Role     string `json:"role" gorm:"default:user"`
}

type Wallet struct {
	ID      uint  `json:"id" gorm:"primaryKey"`
	UserID  uint  `json:"userId" gorm:"unique;not null"` // one wallet per user
	Balance int64 `json:"balance"`                       // stored in cents
}

type Transaction struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	WalletID        uint      `json:"walletId" gorm:"not null"`
	Type            string    `json:"type" gorm:"not null"` // deposit, withdraw, transfer_in, transfer_out
	Amount          int64     `json:"amount"`
	Category        string    `json:"category"`
	Note            string    `json:"note"`
	RelatedWalletID *uint     `json:"relatedWalletId"` // nullable, only set for transfers
	CreatedAt       time.Time `json:"createdAt"`
}

var db *gorm.DB
var jwtSecret = []byte("my-super-secret-key")

func main() {
	dsn := "host=localhost user=postgres password=123456 dbname=wallet_app port=5432 sslmode=disable"

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}

	db.AutoMigrate(&User{}, &Wallet{}, &Transaction{})

	router := gin.Default()

	router.POST("/signup", signup)
	router.POST("/login", login)

	walletGroup := router.Group("/wallet")
walletGroup.Use(authMiddleware())
{
	walletGroup.GET("", getWallet)
	walletGroup.POST("/deposit", deposit)
}

	router.Run(":8080")
}
func signup(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if input.Username == "" || input.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	newUser := User{
		Username: input.Username,
		Password: string(hashedPassword),
		Role:     "user",
	}

	if result := db.Create(&newUser); result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Every new user automatically gets a wallet, starting at 0 balance
	newWallet := Wallet{
		UserID:  newUser.ID,
		Balance: 0,
	}
	db.Create(&newWallet)

	c.JSON(http.StatusCreated, newUser)
}

func login(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var user User
	if result := db.Where("username = ?", input.Username).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	claims := jwt.MapClaims{
		"userID":   user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("userID", claims["userID"])
		c.Set("role", claims["role"])
		c.Next()
	}
}
func getWallet(c *gin.Context) {
	userIDFloat := c.MustGet("userID").(float64)
	userID := uint(userIDFloat)

	var wallet Wallet
	if result := db.Where("user_id = ?", userID).First(&wallet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
		return
	}

	c.JSON(http.StatusOK, wallet)
}
func deposit(c *gin.Context) {
	userIDFloat := c.MustGet("userID").(float64)
	userID := uint(userIDFloat)

	var input struct {
		Amount int64  `json:"amount"`
		Note   string `json:"note"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if input.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount must be positive"})
		return
	}

	var wallet Wallet
	if result := db.Where("user_id = ?", userID).First(&wallet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
		return
	}

	wallet.Balance += input.Amount
	db.Save(&wallet)

	transaction := Transaction{
		WalletID: wallet.ID,
		Type:     "deposit",
		Amount:   input.Amount,
		Note:     input.Note,
	}
	db.Create(&transaction)

	c.JSON(http.StatusOK, wallet)
}