package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The provider-trusted second factor is off unless a record says otherwise:
// a record written before the field existed, and one that leaves it unset,
// both read as false and keep the local authenticator step.
func TestOIDCProviderSkipLocalTOTPWireShape(t *testing.T) {
	raw, err := json.Marshal(OIDCProvider{ID: "g", Issuer: "https://accounts.google.com", ClientID: "cid", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "skip_local_totp") {
		t.Fatalf("an unset skip_local_totp must stay off the wire: %s", raw)
	}

	raw, err = json.Marshal(OIDCProvider{ID: "g", Issuer: "https://accounts.google.com", ClientID: "cid", Enabled: true, SkipLocalTOTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"skip_local_totp":true`) {
		t.Fatalf("skip_local_totp=true must be encoded: %s", raw)
	}
	var back OIDCProvider
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.SkipLocalTOTP {
		t.Fatal("skip_local_totp=true did not survive a round trip")
	}

	var legacy OIDCProvider
	if err := json.Unmarshal([]byte(`{"id":"g","issuer":"https://accounts.google.com","client_id":"cid","enabled":true}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.SkipLocalTOTP {
		t.Fatal("a record without skip_local_totp must read as false")
	}
}

// A link carries its second-factor confirmation only once one happened: an
// unconfirmed link has no second_factor_at and no epoch on the wire, and a
// confirmed one keeps both through a round trip.
func TestOIDCIdentitySecondFactorWireShape(t *testing.T) {
	raw, err := json.Marshal(OIDCIdentity{ProviderID: "g", Subject: "sub", UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"second_factor_at", "second_factor_epoch"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("an unconfirmed link must not carry %s: %s", key, raw)
		}
	}

	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	raw, err = json.Marshal(OIDCIdentity{ProviderID: "g", Subject: "sub", UserID: "u", SecondFactorAt: at, SecondFactorEpoch: 3})
	if err != nil {
		t.Fatal(err)
	}
	var back OIDCIdentity
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.SecondFactorAt.Equal(at) || back.SecondFactorEpoch != 3 {
		t.Fatalf("confirmation lost in a round trip: %+v from %s", back, raw)
	}
}
