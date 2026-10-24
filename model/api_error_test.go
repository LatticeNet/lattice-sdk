package model

import (
	"encoding/json"
	"testing"
)

// A refusal that names a field carries it; one that does not keeps the
// shape every older client reads (design 32 R6).
func TestAPIErrorFieldIsAdditive(t *testing.T) {
	raw, err := json.Marshal(APIErrorResponse{Error: APIError{Code: APIErrorBadRequest, Message: "m", RequestID: "req_1", Field: "targets.exclude[1]"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"error":{"code":"bad_request","message":"m","request_id":"req_1","field":"targets.exclude[1]"}}` {
		t.Fatalf("with a field = %s", raw)
	}
	raw, err = json.Marshal(APIErrorResponse{Error: APIError{Code: APIErrorVersionConflict, Message: "m", RequestID: "req_1"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"error":{"code":"version_conflict","message":"m","request_id":"req_1"}}` {
		t.Fatalf("without a field = %s", raw)
	}
}
