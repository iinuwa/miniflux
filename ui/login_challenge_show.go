package ui // import "miniflux.app/ui"

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"miniflux.app/http/request"
	"miniflux.app/http/response/html"
	"miniflux.app/logger"
	"miniflux.app/model"
	"miniflux.app/ui/form"
	"miniflux.app/ui/session"
	"miniflux.app/ui/view"
)

func (h *handler) showLoginChallengePage(w http.ResponseWriter, r *http.Request) {
	clientIP := request.ClientIP(r)
	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)

	if r.Method == "GET" {
		html.OK(w, r, view.Render("login_credential"))
		return
	}

	web, err := form.NewCredentialOptions()
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		html.ServerError(w, r, err)
		return
	}

	challengeForm := form.NewCredentialChallengeForm(r)
	err = challengeForm.Validate()
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		html.ServerError(w, r, err)
		return
	}

	user, err := h.store.UserCredentialsByUsername(challengeForm.Username)
	if err != nil {
		logger.Error("[UI:BeginChallenge] [ClientIP=%s] %v", clientIP, err)
		// Create a bogus user to prevent spamming to find valid username
		credentials := make([]webauthn.Credential, 1)
		credentials[0] = *NewDummyCredential(challengeForm.Username)
		user = &model.UserCredentials{
			UserID:      0,
			Credentials: credentials,
		}
	}
	// This will fail when the user tries to submit the credential, but we
	// shouldn't give attackers an oracle before submitting a credential.
	if len(user.Credentials) == 0 {
		user.Credentials = append(user.Credentials, *NewDummyCredential(challengeForm.Username))
	}

	options, sessionData, err := web.BeginLogin(user)
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		html.ServerError(w, r, err)
		return
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		logger.Error("[UI:BeginLogin] [ClientIP=%s] %v", clientIP, err)
		view.Set("errorMessage", "error.bad_credentials")
		html.OK(w, r, view.Render("login_credential"))
		return
	}
	optionsJson := string(optionsBytes[:])
	optionsJsonEscaped := strings.ReplaceAll(optionsJson, `"`, "&quot;")
	sess.SetWebAuthnSessionData(sessionData)

	view.Set("form", challengeForm)
	view.Set("assertionOptionsJson", optionsJsonEscaped)
	html.OK(w, r, view.Render("login_credential"))
}

func NewDummyCredential(username string) *webauthn.Credential {
	// Thin attempt to hide credentials from users.
	h := sha256.New()
	id_digest := h.Sum([]byte(username + "_dummy_key_id"))
	public_key_digest := sha256.New().Sum([]byte(username + "_dummy_public_key"))
	return &webauthn.Credential{
		ID:        id_digest,
		PublicKey: public_key_digest,
	}
}
