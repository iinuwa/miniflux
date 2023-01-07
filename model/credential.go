package model

import (
	"encoding/binary"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Credential represents a WebAuthn credential.
type Credential struct {
	ID          int64
	UserID      int64
	Credential  webauthn.Credential
	Description string
	LastUsedAt  *time.Time
	CreatedAt   time.Time
}

// NewCredential initializes a new Credential.
func NewCredential(userID int64, description string, credential *webauthn.Credential) *Credential {
	return &Credential{
		UserID:      userID,
		Description: description,
		Credential:  *credential,
	}
}

// Credentials represents a collection of Credential.
type Credentials []*Credential

type UserCredentials struct {
	UserID      int64
	Username    string
	Credentials []webauthn.Credential
}

// User ID according to the Relying Party
func (u UserCredentials) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.PutVarint(b, u.UserID)
	return b
}

// User Name according to the Relying Party
func (u UserCredentials) WebAuthnName() string {
	return u.Username
}

// Display Name of the user
func (u UserCredentials) WebAuthnDisplayName() string {
	return u.Username
}

// User's icon url
func (u UserCredentials) WebAuthnIcon() string {
	return ""
}

// Credentials owned by the user
func (u UserCredentials) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

type CredentalChallengeVerifyResponse struct {
	Error     *string `json:"error"`
	ReturnUrl string  `json:"returnUrl"`
}
