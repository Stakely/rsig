package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"rsig/internal/signer"
	"rsig/internal/validator"
	"strings"
)

func signController(mux *http.ServeMux, keys map[string]*validator.ValidatorKey) {
	mux.HandleFunc("/sign/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		pubHex := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/sign/"), "/")
		if pubHex == "" {
			http.Error(w, "missing public key in URL", http.StatusBadRequest)
			return
		}
		pubHex = strings.ToLower(strings.TrimPrefix(pubHex, "0x"))

		vKey, ok := keys[pubHex]
		if !ok {
			http.Error(w, "unknown validator public key", http.StatusNotFound)
			return
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB cap
		if err != nil {
			http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req signer.Eth2SigningRequestBody
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		if req.Type != signer.ArtifactAttestation {
			http.Error(w, "only ATTESTATION supported", http.StatusBadRequest)
			return
		}
		if req.Attestation == nil {
			http.Error(w, "attestation must be specified", http.StatusBadRequest)
			return
		}

		if req.ForkInfo == nil {
			http.Error(w, "fork_info must be specified", http.StatusBadRequest)
			return
		}

		sigHex, err := signer.SignAttestation(req, *vKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("error: %v", err), http.StatusBadRequest)
		}

		resp := map[string]string{
			"signature": sigHex,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
