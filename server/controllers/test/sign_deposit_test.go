package controllers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignVDeposit(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x99c4a60e30bdfe77a87645925822bd0e4a162565dfb6398278823bca1281e7fc38bfbd9732dd17291b3bfe9dc7b455db173107e89367a4929802e7d540d1cff2d370f1cf29628dcf385e66e4987b7e8b8dc020c8b64d34ffeffc4bc0f5b689c9"

	payload := []byte(`{
	  "type": "DEPOSIT",
	  "signingRoot": "0x3a49cdd70862ee95fed10e7494a8caa16af1be2f53612fc74dad27260bb2d711",
	  "deposit": {
	    "pubkey": "0x8f82597c919c056571a05dfe83e6a7d32acf9ad8931be04d11384e95468cd68b40129864ae12745f774654bbac09b057",
	    "withdrawal_credentials": "0x39722cbbf8b91a4b9045c5e6175f1001eac32f7fcd5eccda5c6e62fc4e638508",
	    "amount": "32",
	    "genesis_fork_version": "0x00000001"
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

func TestSignDeposit_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x99c4a60e30bdfe77a87645925822bd0e4a162565dfb6398278823bca1281e7fc38bfbd9732dd17291b3bfe9dc7b455db173107e89367a4929802e7d540d1cff2d370f1cf29628dcf385e66e4987b7e8b8dc020c8b64d34ffeffc4bc0f5b689c9"

	payload := []byte(`{
	  "type": "DEPOSIT",
	  "signingRoot": "0x3a49cdd70862ee95fed10e7494a8caa16af1be2f53612fc74dad27260bb2d711",
	  "deposit": {
	    "pubkey": "0x8f82597c919c056571a05dfe83e6a7d32acf9ad8931be04d11384e95468cd68b40129864ae12745f774654bbac09b057",
	    "withdrawal_credentials": "0x39722cbbf8b91a4b9045c5e6175f1001eac32f7fcd5eccda5c6e62fc4e638508",
	    "amount": "32",
	    "genesis_fork_version": "0x00000001"
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

func TestSignDeposit_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "VOLUNTARY_EXIT",
	  "signingRoot": "0x38e9f1cfe7926ce5366b633b7fc7113129025737394002d2637faaeefc56913d",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "voluntary_exit": {
	    "epoch": "119",
	    "validator_index": "0"
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

func TestSignDeposit_WithMissingInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "DEPOSIT",
	  "signingRoot": "0x3a49cdd70862ee95fed10e7494a8caa16af1be2f53612fc74dad27260bb2d711"
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

	if !bytes.Contains(bytes.ToLower(b), []byte("deposit must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignDeposit_WithInvalidSigningRoot(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "DEPOSIT",
	  "signingRoot": "0x1a49cdd70862ee95fed10e7494a8caa16af1be2f53612fc74dad27260bb2d711",
	  "deposit": {
	    "pubkey": "0x8f82597c919c056571a05dfe83e6a7d32acf9ad8931be04d11384e95468cd68b40129864ae12745f774654bbac09b057",
	    "withdrawal_credentials": "0x39722cbbf8b91a4b9045c5e6175f1001eac32f7fcd5eccda5c6e62fc4e638508",
	    "amount": "32",
	    "genesis_fork_version": "0x00000001"
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
