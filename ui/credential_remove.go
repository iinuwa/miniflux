// Copyright 2020 Frédéric Guillot. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package ui // import "miniflux.app/ui"

import (
	"net/http"

	"miniflux.app/http/request"
	"miniflux.app/http/response/html"
	"miniflux.app/http/route"
	"miniflux.app/logger"
)

func (h *handler) removeCredential(w http.ResponseWriter, r *http.Request) {
	keyID := request.RouteInt64Param(r, "credentialID")
	err := h.store.RemoveCredential(request.UserID(r), keyID)
	if err != nil {
		logger.Error("[UI:RemoveCredential] %v", err)
	}

	html.Redirect(w, r, route.Path(h.router, "credentials"))
}
