package main

import (
	"log"
	"net/http"
	"os"

	"github.com/grapeid/blind-revocation-registry/internal/api"
	"github.com/grapeid/blind-revocation-registry/internal/signer"
	"github.com/grapeid/blind-revocation-registry/internal/store"
)

func main() {
	dataDir := os.Getenv("BRR_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8093"
	}
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	st, err := store.Open(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()

	id, err := signer.LoadOrCreate(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[brr] service AID=%s", id.AID)

	srv := api.New(st, id)
	addr := host + ":" + port
	log.Printf("[brr] listening on http://%s", addr)
	log.Printf("[brr] enroll: POST /registry/enroll")
	log.Printf("[brr] event:  POST /registry/{prefix}/event")
	log.Printf("[brr] verify:  GET /registry/{prefix}/bulk-proof")
	if err := http.ListenAndServe(addr, srv.Router()); err != nil {
		log.Fatal(err)
	}
}