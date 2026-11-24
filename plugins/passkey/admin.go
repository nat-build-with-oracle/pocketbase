package passkey

// The dashboard (/_/) part, on when Config.AdminButton is true:
//
//	GET /_/               the dashboard's index.html with one more <script src> (admin.js)
//	GET /_/pb-passkey.js  that script: "Sign in with passkey" under the login form, and a
//	                      "Passkeys" button once signed in
//	GET /_/passkeys       a small page in the dashboard's own style to add and remove passkeys
//
// The dashboard itself is not modified: its index.html is read from the embedded build and served
// with the script added. The script is a file on this origin, not inline, so the dashboard keeps
// its Content-Security-Policy (script-src 'self'). The routes are more specific than PocketBase's
// /_/{path...}, so they win without touching its router; every other /_/ file is still PocketBase's.

import (
	_ "embed"
	"errors"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/ui"
)

//go:embed admin.js
var adminJS []byte

const adminScript = `<script type="module" src="./pb-passkey.js"></script>`

// adminCSP is PocketBase's defaultCSP (apis/serve.go), which its /_/ route sets: our index.html
// answers in its place and must not loosen it. TestAdminCSPMatchesPocketBase fails when upstream
// changes it.
const adminCSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' http://127.0.0.1:* https://tile.openstreetmap.org data: blob:; connect-src 'self' http://127.0.0.1:* https://nominatim.openstreetmap.org; script-src 'self' http://127.0.0.1:*; frame-ancestors 'none'"

var cssLink = regexp.MustCompile(`<link[^>]+rel="stylesheet"[^>]*>`)

func (p *plugin) prepareAdmin() error {
	if ui.DistDirFS == nil { // built with no_ui: no dashboard to extend
		return errors.New("PocketBase built without the dashboard")
	}
	index, err := adminIndex(ui.DistDirFS)
	if err != nil {
		return err
	}
	p.adminIndex = index
	return nil
}

// adminIndex is the dashboard's index.html with the script added before </head>.
func adminIndex(dist fs.FS) ([]byte, error) {
	b, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		return nil, err
	}
	s := string(b)
	i := strings.LastIndex(s, "</head>")
	if i < 0 {
		return nil, fs.ErrInvalid
	}
	return []byte(s[:i] + "  " + adminScript + "\n" + s[i:]), nil
}

// managePage is the "Passkeys" page: the dashboard's own stylesheet, an empty body the script fills.
func managePage(index []byte) []byte {
	css := strings.Join(cssLink.FindAllString(string(index), -1), "\n  ")
	return []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Passkeys - PocketBase</title>
  <base href="./">
  ` + css + `
  ` + adminScript + `
</head>
<body><div id="pb-passkey-manage" class="page-wrapper"></div></body>
</html>
`)
}

func (p *plugin) bindAdmin(r *router.Router[*core.RequestEvent]) {
	serve := func(contentType string, body []byte) func(e *core.RequestEvent) error {
		return func(e *core.RequestEvent) error {
			h := e.Response.Header()
			h.Set("Content-Security-Policy", adminCSP)
			h.Set("Cache-Control", "no-cache") // a redeploy must reach open tabs on reload
			return e.Blob(http.StatusOK, contentType, body)
		}
	}
	r.GET("/_/{$}", serve("text/html; charset=utf-8", p.adminIndex))
	r.GET("/_/pb-passkey.js", serve("text/javascript; charset=utf-8", adminJS))
	r.GET("/_/passkeys", serve("text/html; charset=utf-8", managePage(p.adminIndex)))
}
