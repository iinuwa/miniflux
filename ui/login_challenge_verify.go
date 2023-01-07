package ui // import "miniflux.app/ui"

import (
	json_parser "encoding/json"
	"net/http"
	"net/url"
	"strings"

	"miniflux.app/config"
	"miniflux.app/http/cookie"
	"miniflux.app/http/request"
	"miniflux.app/http/response/html"
	"miniflux.app/http/response/json"
	"miniflux.app/http/route"
	"miniflux.app/logger"
	"miniflux.app/model"
	"miniflux.app/ui/form"
	"miniflux.app/ui/session"
	"miniflux.app/ui/view"

	"github.com/go-webauthn/webauthn/protocol"
)

func (h *handler) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	clientIP := request.ClientIP(r)
	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)
	view.Set("errorMessage", "error.bad_credentials")

	web, err := form.NewCredentialOptions()
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		html.ServerError(w, r, err)
		return
	}

	challengeForm, err := form.NewCredentialChallengeVerifyForm(r)
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		html.BadRequest(w, r, err)
		return
	}

	userCreds, err := h.store.UserCredentialsByUsername(challengeForm.Username)
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		logger.Error("[UI:VerifyChallenge] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("login_credential"))
		return
	}
	if userCreds == nil {
		sess.SetWebAuthnSessionData(nil)
		logger.Error("[UI:VerifyChallenge] [ClientIP=%s] User not found: %v", clientIP, challengeForm.Username)
		html.OK(w, r, view.Render(("login_credential")))
		return
	}

	state := request.WebAuthnState(r)
	attestationData, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(challengeForm.PublicKeyCredential))
	if err != nil {
		sess.SetWebAuthnSessionData(nil)
		logger.Error("[UI:VerifyChallenge] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("login_credential"))
		return
	}

	cred, err := web.ValidateLogin(userCreds, state, attestationData)
	if err != nil {
		// TODO: Extract to common function
		sess.SetWebAuthnSessionData(nil)
		logger.Error("[UI:VerifyChallenge] [ClientIP=%s] %v", clientIP, err)
		options, sessionData, err := web.BeginLogin(userCreds)
		if err != nil {
			logger.Error("[UI:VerifyChallenge] [ClientIP=%s] %v", clientIP, err)
			html.OK(w, r, view.Render("login_credential"))
			return
		}

		optionsBytes, err := json_parser.Marshal(options)
		if err != nil {
			logger.Error("[UI:BeginLogin] [ClientIP=%s] %v", clientIP, err)
			html.OK(w, r, view.Render("login_credential"))
			return
		}
		optionsJson := string(optionsBytes[:])
		optionsJsonEscaped := strings.ReplaceAll(optionsJson, `"`, "&quot;")
		sess.SetWebAuthnSessionData(sessionData)

		view.Set("assertionOptionsJson", optionsJsonEscaped)
		html.OK(w, r, view.Render("login_credential"))
		return
	}
	sessionToken, userID, err := h.store.CreateUserSessionFromUsername(challengeForm.Username, r.UserAgent(), clientIP)
	if err != nil {
		html.ServerError(w, r, err)
		return
	}
	logger.Info("[UI:VerifyChallenge] username=%s just logged in", challengeForm.Username)
	h.store.SetLastLogin(userID)
	h.store.SetCredentialUsedTimestamp(userID, cred.ID)

	user, err := h.store.UserByID(userID)
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	sess.SetLanguage(user.Language)
	sess.SetTheme(user.Theme)

	http.SetCookie(w, cookie.New(
		cookie.CookieUserSessionID,
		sessionToken,
		config.Opts.HTTPS,
		config.Opts.BasePath(),
	))

	u, err := url.JoinPath(config.Opts.BaseURL(), route.Path(h.router, user.DefaultHomePage))
	if err != nil {
		json.ServerError(w, r, err)
		return

	}
	json.OK(w, r, model.CredentalChallengeVerifyResponse{
		Error:     nil,
		ReturnUrl: u,
	})
}
