package controllers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestSignAggregateAndProof(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0xa0c023b807962b25971216e733f77336c997eff6db65de42c748856049981535f3ab3fa9be7a67d02172d518b0af464c12b3dbe9f70aa1733f0e7c76cfeb59329c86c3fedaab59c479ad8250cd29f3c3a141564c3fe261f9161b6c63a5d33db4"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
	    "aggregator_index": "1",
	    "aggregate": {
	      "aggregation_bits": "0x00000101",
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
	      "signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
	    },
	    "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProof_WithAlreadySignedBlock(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"
	expectedSignature := "0xa0c023b807962b25971216e733f77336c997eff6db65de42c748856049981535f3ab3fa9be7a67d02172d518b0af464c12b3dbe9f70aa1733f0e7c76cfeb59329c86c3fedaab59c479ad8250cd29f3c3a141564c3fe261f9161b6c63a5d33db4"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
	    "aggregator_index": "1",
	    "aggregate": {
	      "aggregation_bits": "0x00000101",
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
	      "signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
	    },
	    "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProof_WithUnknownValidatorPubkey(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x33f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
	    "aggregator_index": "1",
	    "aggregate": {
	      "aggregation_bits": "0x00000101",
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
	      "signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
	    },
	    "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProof_WithMissingInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
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

func TestSignAggregateAndProof_WithMissingForkInfo(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
	  "aggregate_and_proof": {
	    "aggregator_index": "1",
	    "aggregate": {
	      "aggregation_bits": "0x00000101",
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
	      "signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
	    },
	    "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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

func TestSignAggregateAndProof_WithInvalidSigningRoot(t *testing.T) {
	ts := buildTestApi(t)
	pubkey := "0x85f6ca2ddc3981058bbe6c8ee489bda3c0d1cfd26aab7fe7ebd40d903e98c52d3589b9a2d8c4ffc305d53819f30c5f37"

	payload := []byte(`{
	  "type": "AGGREGATE_AND_PROOF",
	  "signingRoot": "0x44777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
	  "fork_info": {
	    "fork": {
	      "previous_version": "0x00000001",
	      "current_version": "0x00000001",
	      "epoch": "1"
	    },
	    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
	  },
	  "aggregate_and_proof": {
	    "aggregator_index": "1",
	    "aggregate": {
	      "aggregation_bits": "0x00000101",
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
	      "signature": "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
	    },
	    "selection_proof": "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
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
