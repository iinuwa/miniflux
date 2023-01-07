package storage // import miniflux.app/storage

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"miniflux.app/errors"
	"miniflux.app/model"
)

// Credentials returns all WebAuthn credentials that belongs to the given user.
func (s *Storage) Credentials(userID int64) (model.Credentials, error) {
	query := `
		SELECT
			id, user_id, description, last_used_at, created_at, credential_id, public_key, authenticator_aaguid, authenticator_sign_count, authenticator_clone_warning
		FROM
			credentials
		WHERE
			user_id=$1
		ORDER BY description ASC
	`
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf(`store: unable to fetch Credentials: %v`, err)
	}
	defer rows.Close()

	credentials := make(model.Credentials, 0)
	for rows.Next() {
		var credential model.Credential
		var authenticator webauthn.Authenticator
		var webauthn_cred webauthn.Credential

		if err := rows.Scan(
			&credential.ID,
			&credential.UserID,
			&credential.Description,
			&credential.LastUsedAt,
			&credential.CreatedAt,
			&webauthn_cred.ID,
			&webauthn_cred.PublicKey,
			&authenticator.AAGUID,
			&authenticator.SignCount,
			&authenticator.CloneWarning,
		); err != nil {
			return nil, fmt.Errorf(`store: unable to fetch Credential row: %v`, err)
		}
		webauthn_cred.Authenticator = authenticator
		credential.Credential = webauthn_cred

		credentials = append(credentials, &credential)
	}

	return credentials, nil
}

// CredentialExists checks if a credential with the same description exists.
func (s *Storage) CredentialExists(userID int64, description string) bool {
	var result bool
	query := `SELECT true FROM credentials WHERE user_id=$1 AND lower(description)=lower($2) LIMIT 1`
	s.db.QueryRow(query, userID, description).Scan(&result)
	return result
}

// CreateCredential inserts a new credential.
func (s *Storage) CreateCredential(credential *model.Credential) error {
	query := `
		INSERT INTO credentials
			(user_id, credential_id, public_key, authenticator_aaguid, authenticator_sign_count, authenticator_clone_warning, description)
		VALUES
			($1, $2, $3, $4, $5, $6, $7)
		RETURNING
			id, created_at
	`
	err := s.db.QueryRow(
		query,
		credential.UserID,
		credential.Credential.ID,
		credential.Credential.PublicKey,
		credential.Credential.Authenticator.AAGUID,
		credential.Credential.Authenticator.SignCount,
		credential.Credential.Authenticator.CloneWarning,
		credential.Description,
	).Scan(
		&credential.ID,
		&credential.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(`store: unable to create credential: %v`, err)
	}

	return nil
}

// RemoveCredential deletes a Credential.
func (s *Storage) RemoveCredential(userID, credentialID int64) error {
	query := `DELETE FROM credentials WHERE id = $1 AND user_id = $2`
	_, err := s.db.Exec(query, credentialID, userID)
	if err != nil {
		return fmt.Errorf(`store: unable to remove this Credential: %v`, err)
	}

	return nil
}

func (s *Storage) UserCredentialsByUsername(username string) (*model.UserCredentials, error) {
	user, err := s.UserByUsername(username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.NewLocalizedError("error.bad_credentials")
	}
	return s.fetchUserCredentials(user)
}

func (s *Storage) UserCredentialsByID(userID int64) (*model.UserCredentials, error) {
	user, err := s.UserByID(userID)
	if err != nil {
		return nil, err
	}
	return s.fetchUserCredentials(user)
}

// SetCredentialUsedTimestamp updates the last used date of a credential.
func (s *Storage) SetCredentialUsedTimestamp(userID int64, credentialID []byte) error {
	query := `UPDATE credentials SET last_used_at=now() WHERE user_id=$1 and credential_id=$2`
	_, err := s.db.Exec(query, userID, credentialID)
	if err != nil {
		return fmt.Errorf(`store: unable to update last used date for credential: %v`, err)
	}

	return nil
}

func (s *Storage) fetchUserCredentials(user *model.User) (*model.UserCredentials, error) {
	creds, err := s.Credentials(user.ID)
	if err != nil {
		return nil, err
	}
	credentials := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		credentials[i] = c.Credential
	}

	userCredentials := &model.UserCredentials{
		UserID:      user.ID,
		Username:    user.Username,
		Credentials: credentials,
	}

	return userCredentials, nil

}
