package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x93c4e7dc9ced08c17809b4889cc8b55cefe97346f1deee51f39534485710974617cd491855dec1a0f6c42c5a05c1f56b19093f740fd3d1e840f5bf031b786d6b599526e06dd8fca96c6fdf46ca412cc4a2502809ff68cb90b2539732a9aef50c"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
  "fork_info": {
    "fork": {
      "previous_version": "0x00000001",
      "current_version": "0x00000001",
      "epoch": "1"
    },
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "beacon_block": {
    "version": "CAPELLA",
    "block_header": {
      "slot": "0",
      "proposer_index": "4666673844721362956",
      "parent_root": "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
      "state_root": "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
      "body_root": "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"
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

	ctx := context.Background()
	truncateTable(ctx, "signed_blocks")
}

func TestSignBlock_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x93c4e7dc9ced08c17809b4889cc8b55cefe97346f1deee51f39534485710974617cd491855dec1a0f6c42c5a05c1f56b19093f740fd3d1e840f5bf031b786d6b599526e06dd8fca96c6fdf46ca412cc4a2502809ff68cb90b2539732a9aef50c"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
  "fork_info": {
    "fork": {
      "previous_version": "0x00000001",
      "current_version": "0x00000001",
      "epoch": "1"
    },
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "beacon_block": {
    "version": "CAPELLA",
    "block_header": {
      "slot": "0",
      "proposer_index": "4666673844721362956",
      "parent_root": "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
      "state_root": "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
      "body_root": "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"
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

	// 2nd request fail
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if !bytes.Contains(bytes.ToLower(b), []byte("slashing protection: block already signed for this")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
	ctx := context.Background()
	truncateTable(ctx, "signed_blocks")
}

func TestSignBlock_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
  "fork_info": {
    "fork": {
      "previous_version": "0x00000001",
      "current_version": "0x00000001",
      "epoch": "1"
    },
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "beacon_block": {
    "version": "CAPELLA",
    "block_header": {
      "slot": "0",
      "proposer_index": "4666673844721362956",
      "parent_root": "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
      "state_root": "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
      "body_root": "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"
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

func TestSignBlock_WithMissingBlockInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
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

	if !bytes.Contains(bytes.ToLower(b), []byte("beacon_block must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignBlock_WithMissingForkInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
  "beacon_block": {
    "version": "CAPELLA",
    "block_header": {
      "slot": "0",
      "proposer_index": "4666673844721362956",
      "parent_root": "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
      "state_root": "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
      "body_root": "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"
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

func TestSignBlock_WithInvalidSigningRoot(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
  "type": "BLOCK_V2",
  "signingRoot": "0xba2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
  "fork_info": {
    "fork": {
      "previous_version": "0x00000001",
      "current_version": "0x00000001",
      "epoch": "1"
    },
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "beacon_block": {
    "version": "CAPELLA",
    "block_header": {
      "slot": "0",
      "proposer_index": "4666673844721362956",
      "parent_root": "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
      "state_root": "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
      "body_root": "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"
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

	if !bytes.Contains(bytes.ToLower(b), []byte("provided signing_root != computed signing_root")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}
