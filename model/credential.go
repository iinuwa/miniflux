package model

import (
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
		UserID:     userID,
		Credential: *credential,
	}
}

// Credentials represents a collection of Credential.
type Credentials []*Credential
