package controllers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignSyncCommitteeSelectionProof(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x86c47d7aafd8f14a051d870197427e8c0ba6e3e98e36511eba92773f63e5f4662920f353138c3681aac126ff08b072da033ef105d5c29c723376c279c5d88551671a8d4984343b984ac4a218236cd5914ecf929c9079a31f61bb09351e1b19d6"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_SELECTION_PROOF",
	  "signingRoot": "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "sync_aggregator_selection_data": {
	    "slot": "0",
	    "subcommittee_index": "0"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	var out struct {
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	signature := out.Signature
	if expectedSignature != signature {
		t.Fatalf("signature mismatch:\n received:  %s\n expected: %s", signature, expectedSignature)
	}

}

func TestSignSyncCommitteeSelectionProof_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x86c47d7aafd8f14a051d870197427e8c0ba6e3e98e36511eba92773f63e5f4662920f353138c3681aac126ff08b072da033ef105d5c29c723376c279c5d88551671a8d4984343b984ac4a218236cd5914ecf929c9079a31f61bb09351e1b19d6"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_SELECTION_PROOF",
	  "signingRoot": "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "sync_aggregator_selection_data": {
	    "slot": "0",
	    "subcommittee_index": "0"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	var out struct {
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	signature := out.Signature
	if expectedSignature != signature {
		t.Fatalf("signature mismatch:\n received:  %s\n expected: %s", signature, expectedSignature)
	}

	// 2nd request works
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	signature = out.Signature
	if expectedSignature != signature {
		t.Fatalf("signature mismatch:\n received:  %s\n expected: %s", signature, expectedSignature)
	}

}

func TestSignSyncCommitteeSelectionProof_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_SELECTION_PROOF",
	  "signingRoot": "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "sync_aggregator_selection_data": {
	    "slot": "0",
	    "subcommittee_index": "0"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	if !bytes.Contains(bytes.ToLower(b), []byte("unknown validator public key")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignSyncCommitteeSelectionProof_WithMissingInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_SELECTION_PROOF",
	  "signingRoot": "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	if !bytes.Contains(bytes.ToLower(b), []byte("sync_aggregator_selection_data must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignSyncCommitteeSelectionProof_WithMissingForkInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_SELECTION_PROOF",
	  "signingRoot": "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
	  "sync_aggregator_selection_data": {
	    "slot": "0",
	    "subcommittee_index": "0"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	if !bytes.Contains(bytes.ToLower(b), []byte("fork_info must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignSyncCommitteeSelectionProof_WithInvalidSigningRoot(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_MESSAGE",
	  "signingRoot": "0x26f60df2817ea5b52eed1fefebbad746ef64c6249fc05c90c9e0f520cc75bb95",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "sync_committee_message": {
	    "beacon_block_root": "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	    "slot": "0"
	  }
	}`)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/sign/"+pubkey, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected status %d; body=%s", resp.StatusCode, string(b))
	}

	if !bytes.Contains(bytes.ToLower(b), []byte("provided signing_root != computed signing_root")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}
