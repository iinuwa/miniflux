// Copyright 2017 Frédéric Guillot. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package form // import "miniflux.app/ui/form"

import (
	json_parser "encoding/json"
	"net/http"
	"net/url"

	"miniflux.app/config"
	"miniflux.app/errors"
	"miniflux.app/logger"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnRegistrationOptions struct {
	Attestation            protocol.ConveyancePreference
	AuthenticatorSelection protocol.AuthenticatorSelection
}

// CredentialForm represents the credential registration form.
type CredentialForm struct {
	Description string `json:"description"`
	PublicKey   string `json:"publicKey"`
}

// Validate makes sure the form values are valid.
func (w CredentialForm) Validate() error {
	if w.PublicKey == "" || w.Description == "" {
		return errors.NewLocalizedError("error.fields_mandatory")
	}

	return nil
}

// NewCredentialForm returns a new CredentialForm.
func NewCredentialForm(r *http.Request) (*CredentialForm, error) {
	var credentialForm CredentialForm
	if err := json_parser.NewDecoder(r.Body).Decode(&credentialForm); err != nil {
		return &credentialForm, err
	}
	return &credentialForm, nil
}

func NewCredentialOptions() (*webauthn.WebAuthn, error) {
	u, err := url.Parse(config.Opts.BaseURL())
	logger.Info(config.Opts.BaseURL())
	if err != nil {
		return nil, err
	}
	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Miniflux",                          // Display Name for your site
		RPID:          u.Hostname(),                        // TODO: Create new option?
		RPOrigins:     []string{u.Scheme + "://" + u.Host}, // The origin URLs allowed for WebAuthn requests
		RPIcon:        "",                                  // Optional icon URL for your site
	})
	return web, err

}
