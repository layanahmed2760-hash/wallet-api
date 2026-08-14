package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "wallet-api/docs"
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

// @title Wallet & Expense Tracker API
// @version 1.0
// @description A secure wallet API with deposits, withdrawals, transfers, and transaction history
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

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
		walletGroup.POST("/withdraw", withdraw)
		walletGroup.POST("/transfer", transfer)
	}

	transactionsGroup := router.Group("/transactions")
	transactionsGroup.Use(authMiddleware())
	{
		transactionsGroup.GET("", getTransactions)
		transactionsGroup.GET("/summary", getTransactionsSummary)
	}

	adminGroup := router.Group("/admin")
	adminGroup.Use(authMiddleware(), requireRole("admin"))
	{
		adminGroup.GET("/wallets/:userId", adminGetWallet)
		adminGroup.GET("/transactions", adminGetAllTransactions)
	}

	// Swagger route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.Run(":8080")
}

// signup godoc
// @Summary Create a new user account
// @Description Creates a new user and automatically provisions a wallet with a 0 balance
// @Tags auth
// @Accept json
// @Produce json
// @Param input body object true "username and password"
// @Success 201 {object} User
// @Failure 400 {object} map[string]string
// @Router /signup [post]
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

// login godoc
// @Summary Log in and receive a JWT
// @Description Validates credentials and returns a signed JWT valid for 24 hours
// @Tags auth
// @Accept json
// @Produce json
// @Param input body object true "username and password"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
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

// getWallet godoc
// @Summary Get current user's wallet
// @Description Returns the balance and details of the authenticated user's wallet
// @Tags wallet
// @Produce json
// @Success 200 {object} Wallet
// @Failure 404 {object} map[string]string
// @Router /wallet [get]
// @Security BearerAuth
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

// deposit godoc
// @Summary Deposit money into wallet
// @Description Adds funds to the authenticated user's wallet and logs a deposit transaction
// @Tags wallet
// @Accept json
// @Produce json
// @Param input body object true "amount (in cents) and note"
// @Success 200 {object} Wallet
// @Failure 400 {object} map[string]string
// @Router /wallet/deposit [post]
// @Security BearerAuth
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

// withdraw godoc
// @Summary Withdraw money from wallet
// @Description Removes funds from the authenticated user's wallet if sufficient balance exists. Uses a DB transaction with row locking to prevent overdrafts from concurrent requests.
// @Tags wallet
// @Accept json
// @Produce json
// @Param input body object true "amount (in cents) and note"
// @Success 200 {object} Wallet
// @Failure 400 {object} map[string]string
// @Router /wallet/withdraw [post]
// @Security BearerAuth
func withdraw(c *gin.Context) {
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

	var updatedWallet Wallet

	err := db.Transaction(func(tx *gorm.DB) error {
		var wallet Wallet
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("user_id = ?", userID).First(&wallet).Error; err != nil {
			return fmt.Errorf("wallet not found")
		}

		if wallet.Balance-input.Amount < 0 {
			return fmt.Errorf("insufficient funds")
		}

		wallet.Balance -= input.Amount
		if err := tx.Save(&wallet).Error; err != nil {
			return err
		}

		transaction := Transaction{
			WalletID: wallet.ID,
			Type:     "withdraw",
			Amount:   input.Amount,
			Note:     input.Note,
		}
		if err := tx.Create(&transaction).Error; err != nil {
			return err
		}

		updatedWallet = wallet
		return nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, updatedWallet)
}

// transfer godoc
// @Summary Transfer money to another user
// @Description Moves funds from the authenticated user's wallet to another user's wallet inside a single DB transaction with row locking on both wallets. Either all steps succeed or all roll back.
// @Tags wallet
// @Accept json
// @Produce json
// @Param input body object true "toUsername, amount (in cents), and note"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /wallet/transfer [post]
// @Security BearerAuth
func transfer(c *gin.Context) {
	userIDFloat := c.MustGet("userID").(float64)
	senderUserID := uint(userIDFloat)

	var input struct {
		ToUsername string `json:"toUsername"`
		Amount     int64  `json:"amount"`
		Note       string `json:"note"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if input.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount must be positive"})
		return
	}

	var receiverUser User
	if result := db.Where("username = ?", input.ToUsername).First(&receiverUser); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Recipient user not found"})
		return
	}

	if receiverUser.ID == senderUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot transfer to yourself"})
		return
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		var senderWallet Wallet
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("user_id = ?", senderUserID).First(&senderWallet).Error; err != nil {
			return fmt.Errorf("sender wallet not found")
		}

		if senderWallet.Balance < input.Amount {
			return fmt.Errorf("insufficient funds")
		}

		var receiverWallet Wallet
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("user_id = ?", receiverUser.ID).First(&receiverWallet).Error; err != nil {
			return fmt.Errorf("recipient wallet not found")
		}

		senderWallet.Balance -= input.Amount
		if err := tx.Save(&senderWallet).Error; err != nil {
			return err
		}

		receiverWallet.Balance += input.Amount
		if err := tx.Save(&receiverWallet).Error; err != nil {
			return err
		}

		outTransaction := Transaction{
			WalletID:        senderWallet.ID,
			Type:            "transfer_out",
			Amount:          input.Amount,
			Note:            input.Note,
			RelatedWalletID: &receiverWallet.ID,
		}
		if err := tx.Create(&outTransaction).Error; err != nil {
			return err
		}

		inTransaction := Transaction{
			WalletID:        receiverWallet.ID,
			Type:            "transfer_in",
			Amount:          input.Amount,
			Note:            input.Note,
			RelatedWalletID: &senderWallet.ID,
		}
		if err := tx.Create(&inTransaction).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Transfer successful"})
}

// getTransactions godoc
// @Summary List transaction history
// @Description Returns the authenticated user's transactions, with optional category/date filters and pagination
// @Tags transactions
// @Produce json
// @Param category query string false "Filter by category"
// @Param from query string false "Filter from date (RFC3339)"
// @Param to query string false "Filter to date (RFC3339)"
// @Param page query int false "Page number (default 1)"
// @Param limit query int false "Results per page (default 10)"
// @Success 200 {array} Transaction
// @Router /transactions [get]
// @Security BearerAuth
func getTransactions(c *gin.Context) {
	userIDFloat := c.MustGet("userID").(float64)
	userID := uint(userIDFloat)

	var wallet Wallet
	if result := db.Where("user_id = ?", userID).First(&wallet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
		return
	}

	query := db.Where("wallet_id = ?", wallet.ID)

	// Optional category filter
	category := c.Query("category")
	if category != "" {
		query = query.Where("category = ?", category)
	}

	// Optional date range filter
	from := c.Query("from")
	to := c.Query("to")
	if from != "" {
		query = query.Where("created_at >= ?", from)
	}
	if to != "" {
		query = query.Where("created_at <= ?", to)
	}

	// Pagination
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 {
		limit = 10
	}
	offset := (page - 1) * limit

	var transactions []Transaction
	query.Order("created_at desc").Limit(limit).Offset(offset).Find(&transactions)

	c.JSON(http.StatusOK, transactions)
}

// getTransactionsSummary godoc
// @Summary Get category totals for the current month
// @Description Returns total spending/income grouped by category for the current calendar month
// @Tags transactions
// @Produce json
// @Success 200 {array} object
// @Router /transactions/summary [get]
// @Security BearerAuth
func getTransactionsSummary(c *gin.Context) {
	userIDFloat := c.MustGet("userID").(float64)
	userID := uint(userIDFloat)

	var wallet Wallet
	if result := db.Where("user_id = ?", userID).First(&wallet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
		return
	}

	type CategorySummary struct {
		Category string `json:"category"`
		Total    int64  `json:"total"`
	}

	var summary []CategorySummary

	startOfMonth := time.Now().AddDate(0, 0, -time.Now().Day()+1)
	startOfMonth = time.Date(startOfMonth.Year(), startOfMonth.Month(), startOfMonth.Day(), 0, 0, 0, 0, time.UTC)

	db.Model(&Transaction{}).
		Select("category, SUM(amount) as total").
		Where("wallet_id = ? AND created_at >= ?", wallet.ID, startOfMonth).
		Group("category").
		Scan(&summary)

	c.JSON(http.StatusOK, summary)
}

// adminGetWallet godoc
// @Summary Get any user's wallet (admin only)
// @Description Returns a wallet by user ID. Requires the admin role.
// @Tags admin
// @Produce json
// @Param userId path int true "User ID"
// @Success 200 {object} Wallet
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /admin/wallets/{userId} [get]
// @Security BearerAuth
func adminGetWallet(c *gin.Context) {
	userIDParam, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var wallet Wallet
	if result := db.Where("user_id = ?", userIDParam).First(&wallet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
		return
	}

	c.JSON(http.StatusOK, wallet)
}

// adminGetAllTransactions godoc
// @Summary List all transactions across every wallet (admin only)
// @Description Returns every transaction in the system. Requires the admin role.
// @Tags admin
// @Produce json
// @Success 200 {array} Transaction
// @Failure 403 {object} map[string]string
// @Router /admin/transactions [get]
// @Security BearerAuth
func adminGetAllTransactions(c *gin.Context) {
	var transactions []Transaction
	db.Order("created_at desc").Find(&transactions)
	c.JSON(http.StatusOK, transactions)
}

func requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole := c.MustGet("role").(string)

		if userRole != role {
			c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to perform this action"})
			c.Abort()
			return
		}

		c.Next()
	}
}