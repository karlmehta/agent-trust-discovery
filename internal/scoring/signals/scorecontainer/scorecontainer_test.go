package scorecontainer

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
)

func obs(v string) *domain.SignalObservation {
	return &domain.SignalObservation{Value: json.RawMessage(v)}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestMetadataAndAbsence(t *testing.T) {
	s := New("trustmodel.safety.score", domain.DimensionSafety, DefaultLowThreshold)
	if s.ID() != "trustmodel.safety.score" {
		t.Errorf("id = %q", s.ID())
	}
	if s.Dimension() != domain.DimensionSafety {
		t.Errorf("dimension = %q", s.Dimension())
	}
	if s.Derived() {
		t.Error("Derived() = true, want false")
	}
	if s.AbsenceInformative() {
		t.Error("AbsenceInformative() = true, want false (absence is not informative)")
	}
}

func TestEvaluate(t *testing.T) {
	s := New("trustmodel.safety.score", domain.DimensionSafety, DefaultLowThreshold)

	// nil obs -> 0 + vendor-scoped UNKNOWN
	r, _ := s.Evaluate(context.TODO(), domain.Agent{}, nil)
	if r.Raw != 0 || !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_UNKNOWN") {
		t.Errorf("nil: raw=%d codes=%v", r.Raw, r.RiskCodes)
	}

	// clean high score -> no codes
	r, _ = s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":86}`))
	if r.Raw != 86 || len(r.RiskCodes) != 0 {
		t.Errorf("high: raw=%d codes=%v", r.Raw, r.RiskCodes)
	}

	// below threshold -> vendor-scoped backstop
	r, _ = s.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":40}`))
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("low: codes=%v", r.RiskCodes)
	}

	// provider codes pass through with prefix filter; explanation surfaced
	r, _ = s.Evaluate(context.TODO(), domain.Agent{},
		obs(`{"score":30,"riskCodes":["SAFETY_PROMPT_INJECTION","BEHAVIOR_STALE"],"explanation":"2/40 jailbroke"}`))
	if !contains(r.RiskCodes, "SAFETY_PROMPT_INJECTION") {
		t.Errorf("provider code dropped: %v", r.RiskCodes)
	}
	if contains(r.RiskCodes, "BEHAVIOR_STALE") {
		t.Errorf("wrong-dimension code kept: %v", r.RiskCodes)
	}
	if r.Explanation != "2/40 jailbroke" {
		t.Errorf("explanation = %q", r.Explanation)
	}
}

// The backstop and UNKNOWN codes are scoped to the id's vendor segment, so two
// providers in the same dimension produce distinguishable codes.
func TestVendorScopedCodes(t *testing.T) {
	tm := New("trustmodel.safety.score", domain.DimensionSafety, 70)
	ag := New("agentgraph.safety.score", domain.DimensionSafety, 70)

	rt, _ := tm.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	ra, _ := ag.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":10}`))
	if !contains(rt.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("trustmodel backstop missing: %v", rt.RiskCodes)
	}
	if !contains(ra.RiskCodes, "SAFETY_AGENTGRAPH_SCORE_LOW") {
		t.Errorf("agentgraph backstop missing: %v", ra.RiskCodes)
	}
}

func TestValidate(t *testing.T) {
	s := New("trustmodel.behavior.score", domain.DimensionBehavior, DefaultLowThreshold)
	if err := s.Validate(json.RawMessage(`{"score":50}`)); err != nil {
		t.Errorf("valid rejected: %v", err)
	}
	if err := s.Validate(json.RawMessage(`{"score":101}`)); err == nil {
		t.Error("expected out-of-range error")
	}
	if err := s.Validate(json.RawMessage(`{"score":50,"riskCodes":["bad-code"]}`)); err == nil {
		t.Error("expected malformed risk-code error")
	}
	codes := make([]string, maxRiskCodes+1)
	for i := range codes {
		codes[i] = "BEHAVIOR_X"
	}
	body, _ := json.Marshal(scoreValue{Score: 50, RiskCodes: codes})
	if err := s.Validate(body); err == nil {
		t.Error("expected count-cap error")
	}
}

func TestThresholdConfigurable(t *testing.T) {
	strict := New("trustmodel.safety.score", domain.DimensionSafety, 90)
	r, _ := strict.Evaluate(context.TODO(), domain.Agent{}, obs(`{"score":85}`))
	if !contains(r.RiskCodes, "SAFETY_TRUSTMODEL_SCORE_LOW") {
		t.Errorf("threshold 90: score 85 should trip backstop, got %v", r.RiskCodes)
	}
	if New("x.y.z", domain.DimensionSafety, -5).threshold != DefaultLowThreshold {
		t.Error("threshold <= 0 should fall back to DefaultLowThreshold")
	}
}
