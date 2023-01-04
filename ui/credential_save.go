package ui // import "miniflux.app/ui"

import (
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"miniflux.app/http/request"
	"miniflux.app/http/response/html"
	"miniflux.app/http/route"
	"miniflux.app/logger"
	"miniflux.app/model"
	"miniflux.app/ui/form"
	"miniflux.app/ui/session"
	"miniflux.app/ui/view"
)

func (h *handler) saveCredential(w http.ResponseWriter, r *http.Request) {
	logger.Info("GOT IT!")
	user, err := h.store.UserByID(request.UserID(r))
	if err != nil {
		html.ServerError(w, r, err)
		return
	}

	sess := session.New(h.store, request.SessionID(r))
	view := view.New(h.tpl, r, sess)
	// view.Set("form", credentialForm)
	view.Set("menu", "settings")
	view.Set("user", user)
	view.Set("countUnread", h.store.CountUnreadEntries(user.ID))
	view.Set("countErrorFeeds", h.store.CountUserFeedsWithErrors(user.ID))
	logger.Info("GOT session")

	credentialForm, err := form.NewCredentialForm(r)
	if err != nil {
		view.Set("errorMessage", err.Error())
		html.OK(w, r, view.Render("create_credential"))
		return
	}

	if err := credentialForm.Validate(); err != nil {
		view.Set("errorMessage", err.Error())
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	logger.Info("GOT credential form!")
	logger.Info("%v | %v", credentialForm.Description, credentialForm.PublicKey)

	web, err := form.NewCredentialOptions()
	if err != nil {
		view.Set("errorMessage", err.Error())
		html.OK(w, r, view.Render("create_credential"))
		return
	}

	if h.store.CredentialExists(user.ID, credentialForm.Description) {
		view.Set("errorMessage", "error.credential_already_exists")
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	state := request.WebAuthnState(r)
	logger.Info("Got State! %v", state)
	credCreationData, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(credentialForm.PublicKey))
	if err != nil {
		logger.Error(err.Error())
		view.Set("errorMessage", "error.credential_creation_failed")
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	logger.Info("parsed! %v", credCreationData)

	logger.Info("Origins: %v", web.Config.RPOrigins)
	cred, err := web.CreateCredential(user, state, credCreationData)
	if err != nil {
		logger.Error(err.Error())
		view.Set("errorMessage", "error.credential_creation_failed")
		html.OK(w, r, view.Render("create_credential"))
		return
	}
	logger.Info("%v", cred)

	credential := model.NewCredential(user.ID, credentialForm.Description, cred)
	if err = h.store.CreateCredential(credential); err != nil {
		logger.Error("[UI:SaveCredential] %v", err)
		view.Set("errorMessage", "error.unable_to_create_credential")
		html.OK(w, r, view.Render("create_credential"))
		return
	}

	html.Redirect(w, r, route.Path(h.router, "credentials"))
}
