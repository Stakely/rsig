package controllers_test

import (
	"io"
	"net/http"
	"testing"
)

func TestHealthz(t *testing.T) {
	ts := buildTestApi(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200; got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("want empty body; got %q", string(body))
	}

	defer ts.Close()
}
