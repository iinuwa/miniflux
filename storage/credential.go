package storage // import miniflux.app/storage

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
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
