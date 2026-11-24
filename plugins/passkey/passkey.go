// Package passkey adds passkey (WebAuthn) sign-in to PocketBase: Touch ID, Face ID, Windows Hello,
// an Android fingerprint, or a hardware security key.
//
// It is a plugin, like jsvm or migratecmd: nothing in PocketBase's core changes. Register it once
// in your main.go:
//
//	app := pocketbase.New()
//	passkey.MustRegister(app, passkey.Config{
//		RPID:        "pb.example.com",
//		Origins:     []string{"https://pb.example.com"},
//		AdminButton: true, // "Sign in with passkey" on the dashboard's login page (/_/)
//	})
//
// Routes:
//
//	POST   /api/passkey/register/begin                signed-in record          -> {sid, options}
//	POST   /api/passkey/register/finish?sid=&name=    signed-in record          body: the credential
//	POST   /api/passkey/login/begin                   anyone                    -> {sid, options}
//	POST   /api/passkey/login/finish?sid=[&only=col]  anyone                    body: the assertion -> {token, record}
//	GET    /api/passkey                               signed-in record          its passkeys
//	DELETE /api/passkey/{id}                          signed-in record          remove one of its passkeys
//	GET    /api/passkey/where                         anyone                    {origin}: where passkeys work
//
// Design:
//   - Only records of Config.AuthCollections (default: _superusers) may add or use a passkey.
//   - Login is discoverable: login/begin names no account and lists no credentials; the
//     authenticator picks the passkey and returns its user handle ("<collection>:<record id>").
//     The signature is accepted only with a credential stored for that same record, so one
//     account's passkey never signs another in.
//   - User verification is required on both ceremonies: a key that only taps, with no
//     fingerprint, face or PIN, is refused.
//   - A passkey is another way in, not a replacement: the password keeps working.
//   - login/finish answers exactly like auth-with-password ({token, record}), so a client keeps
//     one sign-in path. Challenges live in memory for 5 minutes and are used once.
//   - Credentials are stored in a system collection (default "_passkeys") with no API rules:
//     every change goes through the routes above, where the owner is always the signed-in record.
//
// WebAuthn needs a secure context: https with a valid certificate for RPID, or http://localhost.
// With no RPID and the server bound to a loopback address, the plugin uses "localhost" and
// http://localhost:<port> by itself, which is enough to try it on your own machine.
package passkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
)

// Config of the plugin. Every field is optional.
type Config struct {
	// RPID is the WebAuthn relying-party id: the host name users open, with no scheme or port
	// ("pb.example.com"). Passkeys made for one RPID do not work on another.
	RPID string

	// Origins are the full origins pages may run the ceremonies from ("https://pb.example.com",
	// "https://pb.example.com:8443"). The first one is reported by GET /api/passkey/where.
	Origins []string

	// RPDisplayName is shown by some authenticators. Default: the app name from the settings.
	RPDisplayName string

	// AuthCollections are the auth collections whose records may use passkeys.
	// Default: []string{"_superusers"}.
	AuthCollections []string

	// CollectionName stores the credentials. Default: "_passkeys".
	CollectionName string

	// MaxPerRecord caps the passkeys of one record. Default: 10.
	MaxPerRecord int

	// AdminButton adds "Sign in with passkey" under the dashboard's login form (/_/).
	// It signs in superusers only.
	AdminButton bool
}

const (
	sessionTTL = 5 * time.Minute // the browser prompt waits as long (WebAuthn default timeout)
	maxOpen    = 200             // challenges waiting at once
)

// MustRegister registers the plugin and panics on a bad Config.
func MustRegister(app core.App, config Config) {
	if err := Register(app, config); err != nil {
		panic(err)
	}
}

// Register registers the plugin: it makes sure the credentials collection exists after bootstrap
// and binds the routes when the server starts.
func Register(app core.App, config Config) error {
	p := newPlugin(config)
	if p.cfg.AdminButton {
		if err := p.prepareAdmin(); err != nil {
			app.Logger().Warn("passkey: dashboard button off", "error", err)
			p.cfg.AdminButton = false
		}
	}

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return p.ensureCollection(e.App)
	})

	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		rpID, origins := p.cfg.RPID, p.cfg.Origins
		if rpID == "" && len(origins) == 0 {
			rpID, origins = localDefaults(se.Server.Addr)
		}
		name := p.cfg.RPDisplayName
		if name == "" {
			name = se.App.Settings().Meta.AppName
		}
		if err := p.configure(rpID, origins, name); err != nil {
			return err
		}
		p.bind(se.Router)
		if p.cfg.AdminButton {
			p.bindAdmin(se.Router)
		}
		return se.Next()
	})
	return nil
}

// localDefaults: a server bound to a loopback address with no RPID gets passkeys for
// http://localhost:<port>. Browsers treat http://localhost as a secure context and accept
// "localhost" as the RP id; an IP address such as 127.0.0.1 is never a valid RP id, so open the
// page at localhost. Anything bound elsewhere stays unconfigured (every ceremony answers 503).
func localDefaults(addr string) (rpID string, origins []string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", nil
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return "", nil
	}
	return "localhost", []string{"http://localhost:" + port}
}

type session struct {
	data    webauthn.SessionData
	login   bool
	ownerID string // register only: who began it
	expires time.Time
}

type plugin struct {
	cfg        Config
	wa         *webauthn.WebAuthn // nil = not configured
	mu         sync.Mutex
	open       map[string]session
	now        func() time.Time
	adminIndex []byte
}

func newPlugin(config Config) *plugin {
	if len(config.AuthCollections) == 0 {
		config.AuthCollections = []string{core.CollectionNameSuperusers}
	}
	if config.CollectionName == "" {
		config.CollectionName = "_passkeys"
	}
	if config.MaxPerRecord <= 0 {
		config.MaxPerRecord = 10
	}
	return &plugin{cfg: config, open: map[string]session{}, now: time.Now}
}

func (p *plugin) configure(rpID string, origins []string, displayName string) error {
	var list []string
	for _, o := range origins {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			list = append(list, o)
		}
	}
	if rpID == "" || len(list) == 0 {
		p.wa = nil
		return nil
	}
	if displayName == "" {
		displayName = "PocketBase"
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: displayName, RPOrigins: list})
	if err != nil {
		return err
	}
	p.wa = wa
	return nil
}

// ensureCollection creates the credentials collection when it is missing. System: the dashboard
// cannot rename or delete it. No API rules: only superusers see it there, read-only in practice.
func (p *plugin) ensureCollection(app core.App) error {
	if _, err := app.FindCollectionByNameOrId(p.cfg.CollectionName); err == nil {
		return nil
	}
	c := core.NewBaseCollection(p.cfg.CollectionName)
	c.System = true
	c.Fields.Add(
		&core.TextField{Name: "owner_col", Required: true, Max: 255},
		&core.TextField{Name: "owner_id", Required: true, Max: 255},
		&core.TextField{Name: "cred_id", Required: true, Max: 1400}, // base64url of the credential id
		&core.TextField{Name: "name", Max: 100},
		&core.JSONField{Name: "credential", Required: true, MaxSize: 64 << 10},
		&core.DateField{Name: "last_used"},
		&core.AutodateField{Name: "created", OnCreate: true},
	)
	c.AddIndex("idx_"+p.cfg.CollectionName+"_cred", true, "cred_id", "")
	c.AddIndex("idx_"+p.cfg.CollectionName+"_owner", false, "owner_col, owner_id", "")
	return app.Save(c)
}

func (p *plugin) bind(r *router.Router[*core.RequestEvent]) {
	g := r.Group("/api/passkey")
	g.POST("/register/begin", p.registerBegin)
	g.POST("/register/finish", p.registerFinish)
	g.POST("/login/begin", p.loginBegin)
	g.POST("/login/finish", p.loginFinish)
	// Where passkeys work: a page opened at another address (plain http, an IP) can send the
	// user there instead of hiding the option. It is the origin every challenge names anyway.
	g.GET("/where", func(e *core.RequestEvent) error {
		origin := ""
		if p.wa != nil && len(p.wa.Config.RPOrigins) > 0 {
			origin = p.wa.Config.RPOrigins[0]
		}
		return e.JSON(http.StatusOK, map[string]any{"origin": origin})
	})
	g.GET("", p.list)
	g.DELETE("/{id}", p.remove)
}

// --- the user the library sees ---------------------------------------------------------------

type user struct {
	rec   *core.Record
	creds []webauthn.Credential
}

func handleOf(rec *core.Record) string { return rec.Collection().Name + ":" + rec.Id }

func (u *user) WebAuthnID() []byte                         { return []byte(handleOf(u.rec)) }
func (u *user) WebAuthnName() string                       { return u.rec.Email() }
func (u *user) WebAuthnDisplayName() string                { return u.rec.Email() }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (p *plugin) rows(app core.App, rec *core.Record) ([]*core.Record, error) {
	return app.FindRecordsByFilter(p.cfg.CollectionName, "owner_col = {:c} && owner_id = {:i}", "created", 0, 0,
		dbx.Params{"c": rec.Collection().Name, "i": rec.Id})
}

func (p *plugin) loadUser(app core.App, rec *core.Record) (*user, error) {
	rows, err := p.rows(app, rec)
	if err != nil {
		return nil, err
	}
	u := &user{rec: rec}
	for _, row := range rows {
		var c webauthn.Credential
		if err := row.UnmarshalJSONField("credential", &c); err == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, nil
}

var b64 = base64.RawURLEncoding

// --- challenges ------------------------------------------------------------------------------

func (p *plugin) put(s session) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, v := range p.open {
		if now.After(v.expires) {
			delete(p.open, k)
		}
	}
	if len(p.open) >= maxOpen {
		return "", false
	}
	sid := security.RandomString(32)
	s.expires = now.Add(sessionTTL)
	s.data.Expires = s.expires
	p.open[sid] = s
	return sid, true
}

// take removes the challenge whatever happens next: one try per challenge.
func (p *plugin) take(sid string, login bool) (session, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.open[sid]
	delete(p.open, sid)
	if !ok || s.login != login || p.now().After(s.expires) {
		return session{}, false
	}
	return s, true
}

// --- handlers --------------------------------------------------------------------------------

func (p *plugin) ready(e *core.RequestEvent) error {
	if p.wa == nil {
		return e.Error(http.StatusServiceUnavailable, "Passkeys are not configured on this server.", nil)
	}
	return nil
}

func (p *plugin) owner(e *core.RequestEvent) (*core.Record, error) {
	if e.Auth == nil || !slices.Contains(p.cfg.AuthCollections, e.Auth.Collection().Name) {
		return nil, e.ForbiddenError("Sign in first with an account that may use passkeys.", nil)
	}
	return e.Auth, nil
}

func (p *plugin) registerBegin(e *core.RequestEvent) error {
	if err := p.ready(e); err != nil {
		return err
	}
	rec, err := p.owner(e)
	if err != nil {
		return err
	}
	u, err := p.loadUser(e.App, rec)
	if err != nil {
		return err
	}
	if len(u.creds) >= p.cfg.MaxPerRecord {
		return e.BadRequestError("Too many passkeys: remove one first.", nil)
	}
	var exclude []protocol.CredentialDescriptor
	for i := range u.creds {
		exclude = append(exclude, u.creds[i].Descriptor())
	}
	// No attachment: platform (Touch ID, Face ID) and cross-platform (a hardware key) both welcome.
	opts, data, err := p.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		return e.InternalServerError("Could not begin.", err)
	}
	sid, ok := p.put(session{data: *data, ownerID: handleOf(rec)})
	if !ok {
		return e.TooManyRequestsError("Too many passkey requests at once, try again in a minute.", nil)
	}
	return e.JSON(http.StatusOK, map[string]any{"sid": sid, "options": opts})
}

func (p *plugin) registerFinish(e *core.RequestEvent) error {
	if err := p.ready(e); err != nil {
		return err
	}
	rec, err := p.owner(e)
	if err != nil {
		return err
	}
	s, ok := p.take(e.Request.URL.Query().Get("sid"), false)
	if !ok || s.ownerID != handleOf(rec) {
		return e.BadRequestError("The request expired, start again.", nil)
	}
	u, err := p.loadUser(e.App, rec)
	if err != nil {
		return err
	}
	cred, err := p.wa.FinishRegistration(u, s.data, e.Request)
	if err != nil {
		return e.BadRequestError("The passkey was not accepted.", err)
	}
	col, err := e.App.FindCollectionByNameOrId(p.cfg.CollectionName)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(e.Request.URL.Query().Get("name"))
	if r := []rune(name); len(r) > 100 {
		name = string(r[:100])
	}
	if name == "" {
		name = "passkey"
	}
	row := core.NewRecord(col)
	row.Set("owner_col", rec.Collection().Name)
	row.Set("owner_id", rec.Id)
	row.Set("cred_id", b64.EncodeToString(cred.ID))
	row.Set("name", name)
	row.Set("credential", cred)
	if err := e.App.Save(row); err != nil {
		return e.BadRequestError("Could not save the passkey (already added?).", err)
	}
	return e.JSON(http.StatusOK, view(row))
}

func (p *plugin) loginBegin(e *core.RequestEvent) error {
	if err := p.ready(e); err != nil {
		return err
	}
	opts, data, err := p.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return e.InternalServerError("Could not begin.", err)
	}
	sid, ok := p.put(session{data: *data, login: true})
	if !ok {
		return e.TooManyRequestsError("Too many passkey requests at once, try again in a minute.", nil)
	}
	return e.JSON(http.StatusOK, map[string]any{"sid": sid, "options": opts})
}

// ErrWrongCollection is the 403 of login/finish?only=<collection> when the passkey is good but
// belongs to a record of another collection.
var ErrWrongCollection = errors.New("this passkey belongs to an account of another collection")

func (p *plugin) loginFinish(e *core.RequestEvent) error {
	if err := p.ready(e); err != nil {
		return err
	}
	// One answer for every failure: it says nothing about which accounts or passkeys exist.
	fail := func(err error) error { return e.UnauthorizedError("Passkey sign-in failed.", err) }
	s, ok := p.take(e.Request.URL.Query().Get("sid"), true)
	if !ok {
		return fail(nil)
	}
	var row *core.Record
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		colName, id, ok := strings.Cut(string(userHandle), ":")
		if !ok || !slices.Contains(p.cfg.AuthCollections, colName) {
			return nil, protocol.ErrBadRequest.WithDetails("unknown user handle")
		}
		rec, err := e.App.FindRecordById(colName, id)
		if err != nil {
			return nil, err
		}
		// the stored row of this credential must belong to the record the handle names
		row, err = e.App.FindFirstRecordByFilter(p.cfg.CollectionName, "cred_id = {:c} && owner_col = {:o} && owner_id = {:i}",
			dbx.Params{"c": b64.EncodeToString(rawID), "o": colName, "i": id})
		if err != nil {
			return nil, err
		}
		return p.loadUser(e.App, rec)
	}
	// read the body once and put it back: RecordAuthResponse reads the request info again
	raw, err := io.ReadAll(e.Request.Body)
	if err != nil {
		return fail(err)
	}
	e.Request.Body = io.NopCloser(bytes.NewReader(raw))
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return fail(err)
	}
	u, cred, err := p.wa.ValidatePasskeyLogin(handler, s.data, parsed)
	if err != nil || row == nil {
		return fail(err)
	}
	rec := u.(*user).rec
	// ?only=_superusers (the dashboard button): the signature was good, so the person holds this
	// passkey and may hear that it is the wrong kind. Refused before last_used moves.
	if only := e.Request.URL.Query().Get("only"); only != "" && only != rec.Collection().Name {
		return e.ForbiddenError("This passkey belongs to an account of another collection.", ErrWrongCollection)
	}
	row.Set("credential", cred) // new sign count and flags
	row.Set("last_used", time.Now().UTC())
	if err := e.App.Save(row); err != nil {
		return err
	}
	return apis.RecordAuthResponse(e, rec, "passkey", nil)
}

func view(r *core.Record) map[string]any {
	return map[string]any{"id": r.Id, "name": r.GetString("name"), "created": r.GetString("created"), "last_used": r.GetString("last_used")}
}

func (p *plugin) list(e *core.RequestEvent) error {
	rec, err := p.owner(e)
	if err != nil {
		return err
	}
	rows, err := p.rows(e.App, rec)
	if err != nil {
		return err
	}
	out := []map[string]any{}
	for _, r := range rows {
		out = append(out, view(r))
	}
	return e.JSON(http.StatusOK, map[string]any{"configured": p.wa != nil, "items": out})
}

func (p *plugin) remove(e *core.RequestEvent) error {
	rec, err := p.owner(e)
	if err != nil {
		return err
	}
	row, err := e.App.FindFirstRecordByFilter(p.cfg.CollectionName, "id = {:id} && owner_col = {:o} && owner_id = {:i}",
		dbx.Params{"id": e.Request.PathValue("id"), "o": rec.Collection().Name, "i": rec.Id})
	if err != nil {
		return e.NotFoundError("No such passkey of yours.", nil)
	}
	if err := e.App.Delete(row); err != nil {
		return err
	}
	return e.NoContent(http.StatusNoContent)
}
