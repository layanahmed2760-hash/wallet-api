package main

import (
	"time"

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
	Balance int64 `json:"balance"`                        // stored in cents
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

func main() {
	dsn := "host=localhost user=postgres password=123456 dbname=wallet_app port=5432 sslmode=disable"

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}

	db.AutoMigrate(&User{}, &Wallet{}, &Transaction{})
}