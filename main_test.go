package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestRouter() (*gin.Engine, *gorm.DB) {
	testDB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("failed to connect to test database")
	}

	sqlDB, err := testDB.DB()
	if err != nil {
		panic("failed to get underlying sql.DB")
	}
	sqlDB.SetMaxOpenConns(1) // force all goroutines to share one connection

	testDB.AutoMigrate(&User{}, &Wallet{}, &Transaction{})
	db = testDB

	gin.SetMode(gin.TestMode)
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

	return router, testDB
}

func TestConcurrentWithdrawals_OnlyOneSucceeds(t *testing.T) {
	router, _ := setupTestRouter()

	// Sign up a user
	signupBody := map[string]interface{}{
		"username": "concurrencytest",
		"password": "pass123",
	}
	jsonBody, _ := json.Marshal(signupBody)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Log in to get a token
	loginBody := map[string]interface{}{
		"username": "concurrencytest",
		"password": "pass123",
	}
	jsonBody2, _ := json.Marshal(loginBody)
	req2, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	var loginResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w2.Body.Bytes(), &loginResp)
	token := loginResp.Token

	// Deposit exactly 1000 cents — just enough for ONE withdrawal of 1000
	depositBody := map[string]interface{}{
		"amount": 1000,
		"note":   "initial funds",
	}
	jsonBody3, _ := json.Marshal(depositBody)
	req3, _ := http.NewRequest("POST", "/wallet/deposit", bytes.NewBuffer(jsonBody3))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	// Now fire TWO withdrawal requests of 1000 each, at the same time
	var wg sync.WaitGroup
	results := make([]int, 2)

	withdrawBody := map[string]interface{}{
		"amount": 1000,
		"note":   "concurrent withdrawal",
	}
	jsonBody4, _ := json.Marshal(withdrawBody)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			req, _ := http.NewRequest("POST", "/wallet/withdraw", bytes.NewBuffer(jsonBody4))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			results[index] = w.Code
		}(i)
	}

	wg.Wait()

	successCount := 0
	failCount := 0
	for _, code := range results {
		if code == http.StatusOK {
			successCount++
		} else {
			failCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful withdrawal, got %d", successCount)
	}
	if failCount != 1 {
		t.Errorf("expected exactly 1 failed withdrawal, got %d", failCount)
	}
}