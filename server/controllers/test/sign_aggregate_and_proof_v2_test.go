package controllers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignAggregateAndProofV2(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x99b28a4c4e52399cebc76efbd26d2e92f192cc5e9e1ae1248df96775aabc576ee522fe502cf6e18095a79995824b54fa07c2724118073ed954b80334570e3d2f6503c5ec6aef75f81932d9f9fcc7bc21b39d0859bc3162069cdd4f4f72a4a8af"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x31242163ebaf3578b523e9cfd256c7965b73ad0da9ab00b3c8ae02ff722d6a26",
	  "fork_info": {
		"fork": {
		  "previous_version": "0x00000001",
		  "current_version": "0x00000001",
		  "epoch": "1"
		},
		"genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
		"version": "FULU",
		"data": {
		  "aggregator_index": "1",
		  "aggregate": {
			"aggregation_bits": "0x0000000000000000000000000000000000000000000101",
			"data": {
			  "slot": "0",
			  "index": "0",
			  "beacon_block_root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
			  "source": {
				"epoch": "0",
				"root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "target": {
				"epoch": "0",
				"root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
			  }
			},
			"signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
			"committee_bits": "0x0000000000000001"
		  },
		  "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProofV2_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0x99b28a4c4e52399cebc76efbd26d2e92f192cc5e9e1ae1248df96775aabc576ee522fe502cf6e18095a79995824b54fa07c2724118073ed954b80334570e3d2f6503c5ec6aef75f81932d9f9fcc7bc21b39d0859bc3162069cdd4f4f72a4a8af"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x31242163ebaf3578b523e9cfd256c7965b73ad0da9ab00b3c8ae02ff722d6a26",
	  "fork_info": {
		"fork": {
		  "previous_version": "0x00000001",
		  "current_version": "0x00000001",
		  "epoch": "1"
		},
		"genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
		"version": "FULU",
		"data": {
		  "aggregator_index": "1",
		  "aggregate": {
			"aggregation_bits": "0x0000000000000000000000000000000000000000000101",
			"data": {
			  "slot": "0",
			  "index": "0",
			  "beacon_block_root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
			  "source": {
				"epoch": "0",
				"root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "target": {
				"epoch": "0",
				"root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
			  }
			},
			"signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
			"committee_bits": "0x0000000000000001"
		  },
		  "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProofV2_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x31242163ebaf3578b523e9cfd256c7965b73ad0da9ab00b3c8ae02ff722d6a26",
	  "fork_info": {
		"fork": {
		  "previous_version": "0x00000001",
		  "current_version": "0x00000001",
		  "epoch": "1"
		},
		"genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
		"version": "FULU",
		"data": {
		  "aggregator_index": "1",
		  "aggregate": {
			"aggregation_bits": "0x0000000000000000000000000000000000000000000101",
			"data": {
			  "slot": "0",
			  "index": "0",
			  "beacon_block_root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
			  "source": {
				"epoch": "0",
				"root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "target": {
				"epoch": "0",
				"root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
			  }
			},
			"signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
			"committee_bits": "0x0000000000000001"
		  },
		  "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProofV2_WithMissingInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x31242163ebaf3578b523e9cfd256c7965b73ad0da9ab00b3c8ae02ff722d6a26",
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

	if !bytes.Contains(bytes.ToLower(b), []byte("aggregate_and_proof must be specified")) {
		t.Fatalf("expected error message in body; got: %s", string(b))
	}
}

func TestSignAggregateAndProofV2_WithMissingForkInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x31242163ebaf3578b523e9cfd256c7965b73ad0da9ab00b3c8ae02ff722d6a26",
	  "aggregate_and_proof": {
		"version": "FULU",
		"data": {
		  "aggregator_index": "1",
		  "aggregate": {
			"aggregation_bits": "0x0000000000000000000000000000000000000000000101",
			"data": {
			  "slot": "0",
			  "index": "0",
			  "beacon_block_root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
			  "source": {
				"epoch": "0",
				"root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "target": {
				"epoch": "0",
				"root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
			  }
			},
			"signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
			"committee_bits": "0x0000000000000001"
		  },
		  "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProofV2_WithInvalidSigningRoot(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF_V2",
	  "signingRoot": "0x247535806f76143fe4798427b2a79b85340c1a029a9e08581995b60e4e45c9e0",
	  "fork_info": {
		"fork": {
		  "previous_version": "0x00000001",
		  "current_version": "0x00000001",
		  "epoch": "1"
		},
		"genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
		"version": "FULU",
		"data": {
		  "aggregator_index": "1",
		  "aggregate": {
			"aggregation_bits": "0x0000000000000000000000000000000000000000000101",
			"data": {
			  "slot": "0",
			  "index": "0",
			  "beacon_block_root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
			  "source": {
				"epoch": "0",
				"root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			  },
			  "target": {
				"epoch": "0",
				"root": "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
			  }
			},
			"signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
			"committee_bits": "0x0000000000000001"
		  },
		  "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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
