// Package trustmodel provides ANS Trust Index signals backed by TrustModel.
//
// The Linux Foundation Agent Name Service (ANS) ships an agent-trust-discovery
// engine whose five-dimension model leaves solvency, behavior, and safety EMPTY
// in v1 (no signals registered; dimensionWeight 0 — see config/default-profile.yaml).
// These three signals fill exactly those dimensions from TrustModel's independent
// evaluation, turning ANS's identity layer into a full trust layer.
//
// This package is meant to live inside the agent-trust-discovery module at
// internal/scoring/signals/trustmodel/ (Go's internal/ visibility rule requires
// it to be within the module) and be registered in internal/server.Build — see
// REGISTER.md. Observation values are produced by the TrustModel hydrator
// (../hydrator), which POSTs them to /v1/internal/observations/import.
package trustmodel

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// Signals returns the TrustModel Trust Index signals to register with the engine.
func Signals() []port.Signal {
	return []port.Signal{Behavior{}, Safety{}, Solvency{}}
}

// scoreValue is the raw observation shape for the behavior and safety signals:
// TrustModel's independent 0..100 score for that dimension.
type scoreValue struct {
	Score int `json:"score"` // 0..100
}

func decodeScore(id string, value json.RawMessage) (scoreValue, error) {
	var v scoreValue
	if err := json.Unmarshal(value, &v); err != nil {
		return scoreValue{}, fmt.Errorf("%s: invalid value: %w", id, err)
	}
	if v.Score < 0 || v.Score > 100 {
		return scoreValue{}, fmt.Errorf("%s: score must be in [0,100], got %d", id, v.Score)
	}
	return v, nil
}

// ── Behavior ────────────────────────────────────────────────────────────────

// Behavior scores how the agent actually behaves, from TrustModel's live
// multi-dimension TrustScore. Fills the (empty in v1) behavior dimension.
type Behavior struct{}

func (Behavior) ID() domain.SignalID         { return "trustscore.behavior" }
func (Behavior) Dimension() domain.Dimension { return domain.DimensionBehavior }
func (Behavior) Derived() bool               { return false }

func (Behavior) Validate(value json.RawMessage) error {
	_, err := decodeScore("trustscore.behavior", value)
	return err
}

func (Behavior) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: "no TrustModel behavior score observed",
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{"BEHAVIOR_TRUSTSCORE_UNKNOWN"},
		}, nil
	}
	v, err := decodeScore("trustscore.behavior", obs.Value)
	if err != nil {
		return port.SignalResult{}, err
	}
	var risks []string
	if v.Score < 70 {
		risks = []string{"BEHAVIOR_TRUSTSCORE_LOW"}
	}
	return port.SignalResult{
		Raw:         v.Score,
		Explanation: fmt.Sprintf("TrustModel behavior score %d/100", v.Score),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}

// ── Safety ──────────────────────────────────────────────────────────────────

// Safety scores resistance to misuse (red-team + guardrail evidence) from
// TrustModel. Fills the (empty in v1) safety dimension.
type Safety struct{}

func (Safety) ID() domain.SignalID         { return "trustscore.safety" }
func (Safety) Dimension() domain.Dimension { return domain.DimensionSafety }
func (Safety) Derived() bool               { return false }

func (Safety) Validate(value json.RawMessage) error {
	_, err := decodeScore("trustscore.safety", value)
	return err
}

func (Safety) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: "no TrustModel safety score observed",
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{"SAFETY_TRUSTSCORE_UNKNOWN"},
		}, nil
	}
	v, err := decodeScore("trustscore.safety", obs.Value)
	if err != nil {
		return port.SignalResult{}, err
	}
	var risks []string
	if v.Score < 70 {
		risks = []string{"SAFETY_TRUSTSCORE_LOW"}
	}
	return port.SignalResult{
		Raw:         v.Score,
		Explanation: fmt.Sprintf("TrustModel safety score %d/100", v.Score),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}

// ── Solvency ────────────────────────────────────────────────────────────────

// solvencyValue is the observation shape for the solvency signal: whether the
// operating organization is identity-verified, and at what AgentCert level.
type solvencyValue struct {
	Verified bool   `json:"verified"`
	Level    string `json:"level"` // DV | OV | EV
}

// Solvency scores whether a backed, accountable operator stands behind the
// agent, from TrustModel's OV/EV organization & legal-entity verification.
// Fills the (empty in v1) solvency dimension.
type Solvency struct{}

func (Solvency) ID() domain.SignalID         { return "trustscore.solvency" }
func (Solvency) Dimension() domain.Dimension { return domain.DimensionSolvency }
func (Solvency) Derived() bool               { return false }

func (Solvency) Validate(value json.RawMessage) error {
	var v solvencyValue
	if err := json.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("trustscore.solvency: invalid value: %w", err)
	}
	switch v.Level {
	case "DV", "OV", "EV":
		return nil
	default:
		return fmt.Errorf("trustscore.solvency: level must be DV|OV|EV, got %q", v.Level)
	}
}

func (Solvency) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: "no TrustModel operator verification observed",
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{"SOLVENCY_OPERATOR_UNKNOWN"},
		}, nil
	}
	var v solvencyValue
	if err := json.Unmarshal(obs.Value, &v); err != nil {
		return port.SignalResult{}, err
	}
	raw := 0
	switch {
	case !v.Verified:
		raw = 0
	case v.Level == "EV":
		raw = 100
	case v.Level == "OV":
		raw = 75
	case v.Level == "DV":
		raw = 40
	}
	var risks []string
	if !v.Verified {
		risks = []string{"SOLVENCY_OPERATOR_UNVERIFIED"}
	}
	return port.SignalResult{
		Raw:         raw,
		Explanation: fmt.Sprintf("operator verified=%t level=%s", v.Verified, v.Level),
		Attestation: domain.AttestationUnattested,
		RiskCodes:   risks,
	}, nil
}
