package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"

	"license-server/internal"

	_ "modernc.org/sqlite"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	genKeys := flag.Bool("genkeys", false, "generate License RSA key pair + TLS self-signed cert, then exit")
	keyBits := flag.Int("keybits", 2048, "RSA key bits for License signing (for -genkeys)")
	flag.Parse()

	if *genKeys {
		if err := os.MkdirAll("keys", 0700); err != nil {
			log.Fatalf("create keys dir: %v", err)
		}
		if err := os.MkdirAll("certs", 0700); err != nil {
			log.Fatalf("create certs dir: %v", err)
		}
		if err := internal.GenerateKeyPair(*keyBits, "keys/private.pem", "keys/public.pem"); err != nil {
			log.Fatalf("generate license keys: %v", err)
		}
		log.Println("License keys generated: keys/private.pem, keys/public.pem")

		if err := internal.GenerateTLSCert("certs/server.crt", "certs/server.key"); err != nil {
			log.Fatalf("generate TLS cert: %v", err)
		}
		log.Println("TLS cert generated: certs/server.crt, certs/server.key")
		return
	}

	cfg, err := internal.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	keyMgr, err := internal.NewKeyManager(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}

	audit, err := internal.NewAuditStore(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer audit.Close()

	srv := internal.NewServer(cfg, keyMgr, audit)

	tlsServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("License server starting on https://0.0.0.0%s (db: %s)", cfg.ListenAddr, cfg.DBDriver)
	if err := tlsServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
