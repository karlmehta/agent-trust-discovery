package trustmodel

import (
	"encoding/json"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func obs(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

func TestBehaviorEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		obs     *domain.SignalObservation
		wantRaw int
		wantLow bool
	}{
		{"nil", nil, 0, false},
		{"high", obs(`{"score":86}`), 86, false},
		{"low", obs(`{"score":40}`), 40, true},
		{"boundary", obs(`{"score":70}`), 70, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Behavior{}.Evaluate(nil, domain.Agent{}, c.obs)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if r.Raw != c.wantRaw {
				t.Errorf("raw = %d, want %d", r.Raw, c.wantRaw)
			}
			hasLow := contains(r.RiskCodes, "BEHAVIOR_TRUSTSCORE_LOW")
			if hasLow != c.wantLow {
				t.Errorf("low risk = %v, want %v", hasLow, c.wantLow)
			}
		})
	}
}

func TestScoreValidateRange(t *testing.T) {
	if err := (Behavior{}).Validate(json.RawMessage(`{"score":101}`)); err == nil {
		t.Error("expected out-of-range validation error")
	}
	if err := (Safety{}).Validate(json.RawMessage(`{"score":50}`)); err != nil {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestSolvencyEvaluate(t *testing.T) {
	cases := []struct {
		val     string
		wantRaw int
	}{
		{`{"verified":true,"level":"EV"}`, 100},
		{`{"verified":true,"level":"OV"}`, 75},
		{`{"verified":true,"level":"DV"}`, 40},
		{`{"verified":false,"level":"DV"}`, 0},
	}
	for _, c := range cases {
		r, err := Solvency{}.Evaluate(nil, domain.Agent{}, obs(c.val))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if r.Raw != c.wantRaw {
			t.Errorf("%s: raw = %d, want %d", c.val, r.Raw, c.wantRaw)
		}
	}
}

func TestSolvencyValidateLevel(t *testing.T) {
	if err := (Solvency{}).Validate(json.RawMessage(`{"verified":true,"level":"XX"}`)); err == nil {
		t.Error("expected invalid-level error")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
