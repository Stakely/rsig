package controllers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignSyncCommitteeContributionProof(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0xaf946e3cabcb91ef1945a91a7aaf7d724db6757d89d1af27044cee839b3d9457b82118e02f086c403a086719502a73690f7d1cc8f3036efcb77c14309813c035a2900e091de31251d3cbf777b8e38afd3d52592ff0809062cb5c86bbdb5fd6da"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "contribution_and_proof": {
	    "aggregator_index": "11",
	    "selection_proof": "0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
	    "contribution": {
	      "slot": "0",
	      "beacon_block_root": "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	      "subcommittee_index": "1",
	      "aggregation_bits": "0x24000000000000000000000000000000",
	      "signature": "0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"
	    }
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

func TestSignSyncCommitteeContributionProof_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0xaf946e3cabcb91ef1945a91a7aaf7d724db6757d89d1af27044cee839b3d9457b82118e02f086c403a086719502a73690f7d1cc8f3036efcb77c14309813c035a2900e091de31251d3cbf777b8e38afd3d52592ff0809062cb5c86bbdb5fd6da"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "contribution_and_proof": {
	    "aggregator_index": "11",
	    "selection_proof": "0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
	    "contribution": {
	      "slot": "0",
	      "beacon_block_root": "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	      "subcommittee_index": "1",
	      "aggregation_bits": "0x24000000000000000000000000000000",
	      "signature": "0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"
	    }
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

func TestSignSyncCommitteeContributionProof_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "contribution_and_proof": {
	    "aggregator_index": "11",
	    "selection_proof": "0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
	    "contribution": {
	      "slot": "0",
	      "beacon_block_root": "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	      "subcommittee_index": "1",
	      "aggregation_bits": "0x24000000000000000000000000000000",
	      "signature": "0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"
	    }
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

func TestSignSyncCommitteeContributionProof_WithMissingInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
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

	if !bytes.Contains(bytes.ToLower(b), []byte("contribution_and_proof must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignSyncCommitteeContributionProof_WithMissingForkInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
	  "contribution_and_proof": {
	    "aggregator_index": "11",
	    "selection_proof": "0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
	    "contribution": {
	      "slot": "0",
	      "beacon_block_root": "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
	      "subcommittee_index": "1",
	      "aggregation_bits": "0x24000000000000000000000000000000",
	      "signature": "0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"
	    }
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
