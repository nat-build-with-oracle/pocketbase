package passkey

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/ui"
)

func TestAdminIndexAddsOneScript(t *testing.T) {
	b, err := adminIndex(ui.DistDirFS)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Count(s, adminScript) != 1 || strings.Index(s, adminScript) > strings.Index(s, "</head>") {
		t.Fatalf("script not added once inside <head>:\n%s", s)
	}
	if !strings.Contains(s, `src="./assets/index-`) || strings.Contains(s, "<script>") {
		t.Fatalf("the admin's own scripts changed, or an inline script crept in:\n%s", s)
	}
}

// The two routes beside PocketBase's own /_/{path...} (as apis.Serve registers it): ours answer
// for / and the script, PocketBase still for every other file.
func TestAdminPasskeyRoutes(t *testing.T) {
	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Cleanup)
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	r.GET("/_/{path...}", apis.Static(ui.DistDirFS, false))
	index, err := adminIndex(ui.DistDirFS)
	if err != nil {
		t.Fatal(err)
	}
	p := newPlugin(Config{AdminButton: true})
	p.adminIndex = index
	p.bindAdmin(r)
	h, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}

	w := get("/_/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), adminScript) || w.Header().Get("Content-Security-Policy") != adminCSP {
		t.Fatalf("/_/: %d csp=%q\n%s", w.Code, w.Header().Get("Content-Security-Policy"), w.Body.String())
	}
	if !strings.Contains(adminCSP, "script-src 'self' http://127.0.0.1:*;") {
		t.Fatalf("CSP loosened: %s", adminCSP)
	}
	w = get("/_/pb-passkey.js")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") || !strings.Contains(w.Body.String(), "only=_superusers") {
		t.Fatalf("script: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w = get("/_/passkeys"); w.Code != 200 || !strings.Contains(w.Body.String(), "pb-passkey-manage") || w.Header().Get("Content-Security-Policy") != adminCSP {
		t.Fatalf("/_/passkeys: %d", w.Code)
	}
	if w = get("/_/libs/uplot/uplot.css"); w.Code != 200 || strings.Contains(w.Body.String(), adminScript) {
		t.Fatalf("PocketBase's own files: %d", w.Code)
	}
}

func TestPasskeyAdminSuperusersOnly(t *testing.T) {
	env := newPKEnv(t, testRPID, testOrigin)
	login := func(k *softKey) (int, map[string]any) {
		code, b := env.do("POST", "/api/passkey/login/begin", "", nil)
		if code != 200 {
			t.Fatalf("login/begin %d %v", code, b)
		}
		return env.do("POST", "/api/passkey/login/finish?only=_superusers&sid="+b["sid"].(string), "",
			k.get(t, b["options"].(map[string]any), testOrigin, k.handle))
	}

	su, suTok := env.record("_superusers", "admin@example.com", "")
	ks := newSoftKey(t)
	env.register(suTok, ks, testOrigin)
	code, b := login(ks)
	if r, _ := b["record"].(map[string]any); code != 200 || r["id"] != su.Id || r["collectionName"] != "_superusers" {
		t.Fatalf("superuser on the dashboard: %d %v", code, b)
	}

	_, userTok := env.record("users", "user@example.com", "")
	ku := newSoftKey(t)
	env.register(userTok, ku, testOrigin)
	code, b = login(ku)
	if code != 403 || b["token"] != nil {
		t.Fatalf("users record on the dashboard: %d %v", code, b)
	}
	_, l := env.do("GET", "/api/passkey", userTok, nil)
	if it := l["items"].([]any); it[0].(map[string]any)["last_used"] != "" {
		t.Fatalf("a refused sign-in moved last_used: %v", l)
	}
	// without only=, the same passkey signs the users record in
	if code, _ := env.login(ku, testOrigin, ku.handle); code != 200 {
		t.Fatalf("users record without only=: %d", code)
	}
}

// The plugin copies PocketBase's dashboard CSP; this fails when upstream changes it, so a merge of
// upstream never leaves the dashboard with a stale (looser or broken) policy.
func TestAdminCSPMatchesPocketBase(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pbSourceDir(t), "apis", "serve.go"))
	if err != nil {
		t.Skip("PocketBase source not found:", err)
	}
	if !strings.Contains(string(src), `const defaultCSP = "`+adminCSP+`"`) {
		t.Fatalf("apis/serve.go defaultCSP changed: update adminCSP in admin.go")
	}
}

// pbSourceDir is the PocketBase module this plugin builds against (the module cache copy).
func pbSourceDir(t *testing.T) string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/pocketbase/pocketbase").Output()
	if err != nil {
		t.Skip("go list:", err)
	}
	return strings.TrimSpace(string(out))
}

func TestManagePage(t *testing.T) {
	index, err := adminIndex(ui.DistDirFS)
	if err != nil {
		t.Fatal(err)
	}
	page := string(managePage(index))
	if !strings.Contains(page, adminScript) || !strings.Contains(page, `href="./assets/index-`) || !strings.Contains(page, `id="pb-passkey-manage"`) {
		t.Fatalf("manage page:\n%s", page)
	}
}
