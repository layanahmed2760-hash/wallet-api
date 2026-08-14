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
func TestWithdraw_Validation(t *testing.T) {
	router, _ := setupTestRouter()

	// Sign up and log in
	signupBody := map[string]interface{}{"username": "validationtest", "password": "pass123"}
	jsonBody, _ := json.Marshal(signupBody)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	loginBody := map[string]interface{}{"username": "validationtest", "password": "pass123"}
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

	// Deposit 1000 cents to work with
	depositBody := map[string]interface{}{"amount": 1000, "note": "setup"}
	jsonBody3, _ := json.Marshal(depositBody)
	req3, _ := http.NewRequest("POST", "/wallet/deposit", bytes.NewBuffer(jsonBody3))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	// The table: each row is one test case
	testCases := []struct {
		name           string
		amount         int64
		expectedStatus int
	}{
		{"negative amount", -100, http.StatusBadRequest},
		{"zero amount", 0, http.StatusBadRequest},
		{"amount exceeds balance", 999999, http.StatusBadRequest},
		{"valid amount within balance", 500, http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]interface{}{"amount": tc.amount, "note": "test"}
			jsonBody, _ := json.Marshal(body)

			req, _ := http.NewRequest("POST", "/wallet/withdraw", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("case %q: expected status %d, got %d", tc.name, tc.expectedStatus, w.Code)
			}
		})
	}
}
func TestTransfer_Validation(t *testing.T) {
	router, _ := setupTestRouter()

	// Create sender
	signupBody := map[string]interface{}{"username": "sender1", "password": "pass123"}
	jsonBody, _ := json.Marshal(signupBody)
	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Create receiver
	signupBody2 := map[string]interface{}{"username": "receiver1", "password": "pass123"}
	jsonBody2, _ := json.Marshal(signupBody2)
	req2, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonBody2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	// Log in as sender
	loginBody := map[string]interface{}{"username": "sender1", "password": "pass123"}
	jsonBody3, _ := json.Marshal(loginBody)
	req3, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody3))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	var loginResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w3.Body.Bytes(), &loginResp)
	token := loginResp.Token

	// Deposit 1000 into sender's wallet
	depositBody := map[string]interface{}{"amount": 1000, "note": "setup"}
	jsonBody4, _ := json.Marshal(depositBody)
	req4, _ := http.NewRequest("POST", "/wallet/deposit", bytes.NewBuffer(jsonBody4))
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("Authorization", "Bearer "+token)
	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, req4)

	testCases := []struct {
		name           string
		toUsername     string
		amount         int64
		expectedStatus int
	}{
		{"transfer to nonexistent user", "ghostuser", 100, http.StatusNotFound},
		{"transfer to self", "sender1", 100, http.StatusBadRequest},
		{"transfer more than balance", "receiver1", 999999, http.StatusBadRequest},
		{"valid transfer", "receiver1", 500, http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]interface{}{"toUsername": tc.toUsername, "amount": tc.amount, "note": "test"}
			jsonBody, _ := json.Marshal(body)

			req, _ := http.NewRequest("POST", "/wallet/transfer", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("case %q: expected status %d, got %d", tc.name, tc.expectedStatus, w.Code)
			}
		})
	}
}