package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The two "since" fields are optional by construction: a record written before
// they existed carries neither, and a consumer must not be shown year 0001
// where the control plane simply does not know. A non-zero value has to
// survive the round trip unchanged, since the server derives status_since
// from it.
func TestNodeSinceFieldsAreOmittedWhenZeroAndRoundTripOtherwise(t *testing.T) {
	raw, err := json.Marshal(Node{ID: "n1", Online: true, Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"online_since", "disabled_at"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("zero %s reached the wire: %s", field, raw)
		}
	}

	at := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	raw, err = json.Marshal(Node{ID: "n1", Online: true, OnlineSince: at, Disabled: true, DisabledAt: at})
	if err != nil {
		t.Fatal(err)
	}
	var back Node
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.OnlineSince.Equal(at) || !back.DisabledAt.Equal(at) {
		t.Fatalf("since fields did not round trip: online_since=%s disabled_at=%s", back.OnlineSince, back.DisabledAt)
	}
}
