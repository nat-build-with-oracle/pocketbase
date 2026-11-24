// A PocketBase with passkey sign-in. Run it on your own machine:
//
//	go run ./examples/base serve            # http://127.0.0.1:8090 -> open http://localhost:8090/_/
//
// Behind https (a reverse proxy, tailscale serve, ...):
//
//	PB_PASSKEY_RP_ID=pb.example.com PB_PASSKEY_ORIGINS=https://pb.example.com go run ./examples/base serve
package main

import (
	"log"
	"os"
	"strings"

	"github.com/nat-build-with-oracle/pocketbase/plugins/passkey"
	"github.com/pocketbase/pocketbase"
)

func main() {
	app := pocketbase.New()

	var origins []string
	for _, o := range strings.Split(os.Getenv("PB_PASSKEY_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	passkey.MustRegister(app, passkey.Config{
		RPID:        os.Getenv("PB_PASSKEY_RP_ID"), // empty + loopback bind = localhost
		Origins:     origins,
		AdminButton: true,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
