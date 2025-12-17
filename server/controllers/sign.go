package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"rsig/internal/config"
	"rsig/internal/signer"
	"rsig/internal/slashing"
	"rsig/internal/validator"
	"strings"
)

func signController(mux *http.ServeMux, keys map[string]*validator.ValidatorKey, sp *slashing.SlashingProtection, cfg config.Config) {
	mux.HandleFunc(cfg.HTTP.ApiPrefix+"/sign/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		path := strings.Trim(r.URL.Path, "/")
		parts := strings.Split(path, "/")
		pubHex := parts[len(parts)-1]
		pubHex = strings.ToLower(strings.TrimPrefix(pubHex, "0x"))
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

		if req.Type != signer.ArtifactAttestation && req.Type != signer.ArtifactBlockV2 && req.Type != signer.AggregationSlot && req.Type != signer.AggregateAndProof && req.Type != signer.VoluntaryExit && req.Type != signer.RandaoReveal && req.Type != signer.SyncCommitteeMessage && req.Type != signer.SyncCommitteeSelectionProof && req.Type != signer.SyncCommitteeContributionAndProofType && req.Type != signer.ArtifactDeposit && req.Type != signer.ValidatorRegistration && req.Type != signer.AggregateAndProofV2 {
			http.Error(w, "type not supported", http.StatusBadRequest)
			return
		}

		if req.Type != signer.ArtifactDeposit && req.Type != signer.ValidatorRegistration && req.ForkInfo == nil {
			http.Error(w, "fork_info must be specified", http.StatusBadRequest)
			return
		}

		cs, err := signer.LoadChainSpecs(cfg.NETWORK.Chain, cfg.NETWORK.ConfigSpec)

		var sigHex string
		switch req.Type {
		case signer.ArtifactAttestation:
			sigHex, err = signer.SignAttestation(req, *vKey, sp, cs)
		case signer.ArtifactBlockV2:
			sigHex, err = signer.SignBlock(req, *vKey, sp, cs)
		case signer.AggregationSlot:
			sigHex, err = signer.SignAggregationSlot(req, *vKey, cs)
		case signer.AggregateAndProof:
			sigHex, err = signer.SignAggregateAndProof(req, *vKey, cs)
		case signer.VoluntaryExit:
			sigHex, err = signer.SignVoluntaryExit(req, *vKey, cs)
		case signer.RandaoReveal:
			sigHex, err = signer.SignRandaoReveal(req, *vKey, cs)
		case signer.SyncCommitteeMessage:
			sigHex, err = signer.SignSyncCommitteeMessage(req, *vKey, cs)
		case signer.SyncCommitteeSelectionProof:
			sigHex, err = signer.SignSyncCommitteeSelectionProof(req, *vKey, cs)
		case signer.SyncCommitteeContributionAndProofType:
			sigHex, err = signer.SignSyncCommitteeContributionAndProof(req, *vKey, cs)
		case signer.ArtifactDeposit:
			sigHex, err = signer.SignDeposit(req, *vKey, cs)
		case signer.ValidatorRegistration:
			sigHex, err = signer.SignValidatorRegistration(req, *vKey, cs)
		case signer.AggregateAndProofV2:
			sigHex, err = signer.SignAggregateAndProof(req, *vKey, cs)
		default:
			http.Error(w, fmt.Sprintf("unsupported artifact type: %s", req.Type), http.StatusBadRequest)
			return
		}

		if err != nil {
			http.Error(w, fmt.Sprintf("error: %v", err), http.StatusBadRequest)
			return
		}

		resp := map[string]string{"signature": sigHex}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
