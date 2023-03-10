package ui // import "miniflux.app/ui"

import (
	"encoding/json"
	"net/http"
	"strings"

	"miniflux.app/http/request"
	"miniflux.app/http/response/html"
	"miniflux.app/logger"
	"miniflux.app/ui/form"
	"miniflux.app/ui/session"
	"miniflux.app/ui/view"
)

func (h *handler) showCreateCredentialPage(w http.ResponseWriter, r *http.Request) {
	clientIP := request.ClientIP(r)
	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)

	userCreds, err := h.store.UserCredentialsByID(request.UserID(r))
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	user, err := h.store.UserByID(request.UserID(r))
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	web, err := form.NewCredentialOptions()
	if err != nil {
		logger.Error("[UI:BeginRegistration] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("create_credential"))
		return
	}

	options, sessionData, err := web.BeginRegistration(userCreds)
	if err != nil {
		logger.Error("[UI:BeginRegistration] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	optionsBytes, err := json.Marshal(options)
	if err != nil {
		logger.Error("[UI:BeginRegistration] [ClientIP=%s] %v", clientIP, err)
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	optionsJson := string(optionsBytes[:])
	optionsJsonEscaped := strings.ReplaceAll(optionsJson, `"`, "&quot;")
	sess.SetWebAuthnSessionData(sessionData)

	view.Set("registrationOptionsJson", optionsJsonEscaped)
	view.Set("form", &form.CredentialForm{})
	view.Set("menu", "settings")
	view.Set("user", user)
	view.Set("countUnread", h.store.CountUnreadEntries(userCreds.UserID))
	view.Set("countErrorFeeds", h.store.CountUserFeedsWithErrors(userCreds.UserID))

	html.OK(w, r, view.Render("create_credential"))
}

type RegistrationOptions struct {
	Challenge       string
	RPID            string
	RPDisplayName   string
	RPIcon          string
	UserID          int64
	UserName        string
	UserDisplayName string
}
