// Package scorecontainer is the neutral, reusable score container for
// provider-fed Trust Index dimensions (solvency, behavior, safety, and any
// future dimension whose evidence a provider hydrates rather than the engine
// computing it from public DNS/certs).
//
// It exists so no single vendor "owns" the container shape. A provider registers
// a dimension score by instantiating New(id, dimension, threshold) — it does not
// re-implement validation, risk-code handling, or the low-score backstop, and it
// does not add anything to core. Multiple providers can each register their own
// vendor.dimension.name signal against the same container:
//
//	scorecontainer.New("trustmodel.safety.score",  domain.DimensionSafety,   70)
//	scorecontainer.New("agentgraph.safety.score",  domain.DimensionSafety,   70)
//	scorecontainer.New("acme.behavior.score",      domain.DimensionBehavior, 60)
//
// The observation value is a generic 0..100 score plus provider-asserted,
// dimension-scoped risk codes and an optional explanation:
//
//	{ "score": 0, "riskCodes": ["SAFETY_..."], "explanation": "…" }
//
// Provenance/attestation (an evidence URL, a signed receipt, a ledger anchor,
// an Ed25519/JWS blob) rides the observation's provenance envelope, not this
// value, so the score stays opinion-free and any evidence model composes.
package scorecontainer

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

// DefaultLowThreshold is the score below which the generic
// {DIMENSION}_<VENDOR>_SCORE_LOW backstop risk code is emitted. It is a
// per-signal field (see New) so it can be tuned in configuration rather than
// baked in as a magic constant.
const DefaultLowThreshold = 70

// maxRiskCodes caps how many provider risk codes one observation may carry, so
// a hostile or buggy hydrator can't balloon the evaluation payload.
const maxRiskCodes = 16

// riskCodeRe is the risk-code shape (§7.3): uppercase, digits, underscores.
var riskCodeRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

// scoreValue is the observation shape decoded from the import. It is internal:
// providers emit JSON of this shape from their hydrator; they do not construct
// the Go struct. A bare {"score": N} is valid — you then get only the backstop,
// so a minimal hydrator still works.
type scoreValue struct {
	Score       int      `json:"score"`                 // 0..100
	RiskCodes   []string `json:"riskCodes,omitempty"`   // provider-asserted, {DIMENSION}_-prefixed
	Explanation string   `json:"explanation,omitempty"` // optional; surfaced in the API response
}

// ScoreSignal is a generic provider-score signal for one dimension. Construct
// with New. It implements port.Signal and port.AbsenceAware.
type ScoreSignal struct {
	id        domain.SignalID
	dimension domain.Dimension
	vendor    string
	threshold int
}

// New builds a ScoreSignal for a vendor.dimension.name id. The id's vendor
// segment prefixes the generic backstop code (e.g. "trustmodel" ->
// SAFETY_TRUSTMODEL_SCORE_LOW). threshold <= 0 falls back to DefaultLowThreshold.
func New(id domain.SignalID, dim domain.Dimension, threshold int) ScoreSignal {
	if threshold <= 0 {
		threshold = DefaultLowThreshold
	}
	vendor := strings.ToUpper(vendorSegment(string(id)))
	return ScoreSignal{id: id, dimension: dim, vendor: vendor, threshold: threshold}
}

// vendorSegment returns the first dot-segment of a vendor.dimension.name id,
// or the whole id if it carries no dot.
func vendorSegment(id string) string {
	if i := strings.IndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

func (s ScoreSignal) ID() domain.SignalID         { return s.id }
func (s ScoreSignal) Dimension() domain.Dimension { return s.dimension }
func (s ScoreSignal) Derived() bool               { return false }

// AbsenceInformative reports false: a missing observation for a provider-fed
// dimension means no provider has covered the agent yet, not that it scored
// badly. The engine excludes the signal from the roll-up when absent rather than
// scoring it 0 (issue #13).
func (s ScoreSignal) AbsenceInformative() bool { return false }

// prefix is the required {DIMENSION}_ prefix for this signal's risk codes, e.g.
// "SAFETY_". Provider codes without it are dropped in Evaluate so a signal can't
// leak a code into a dimension it doesn't own.
func (s ScoreSignal) prefix() string {
	return strings.ToUpper(string(s.dimension)) + "_"
}

// Validate enforces the container schema before the observation is persisted:
// score in range, each risk code well-formed, and the count capped.
func (s ScoreSignal) Validate(value json.RawMessage) error {
	var v scoreValue
	if err := json.Unmarshal(value, &v); err != nil {
		return fmt.Errorf("%s: invalid value: %w", s.id, err)
	}
	if v.Score < 0 || v.Score > 100 {
		return fmt.Errorf("%s: score must be in [0,100], got %d", s.id, v.Score)
	}
	if len(v.RiskCodes) > maxRiskCodes {
		return fmt.Errorf("%s: too many riskCodes (%d > %d)", s.id, len(v.RiskCodes), maxRiskCodes)
	}
	for _, c := range v.RiskCodes {
		if !riskCodeRe.MatchString(c) {
			return fmt.Errorf("%s: risk code %q must match %s", s.id, c, riskCodeRe.String())
		}
	}
	return nil
}

// Evaluate maps the container onto a SignalResult: Raw is the score; RiskCodes
// are the provider's dimension-scoped codes (codes prefixed for another
// dimension are dropped) plus the normalized {DIMENSION}_<VENDOR>_SCORE_LOW
// backstop when the score is below the configured threshold. The provider's
// explanation is surfaced.
func (s ScoreSignal) Evaluate(_ context.Context, _ domain.Agent, obs *domain.SignalObservation) (port.SignalResult, error) {
	prefix := s.prefix()
	if obs == nil {
		return port.SignalResult{
			Raw:         0,
			Explanation: fmt.Sprintf("no %s observation recorded for %s", s.dimension, s.id),
			Attestation: domain.AttestationUnattested,
			RiskCodes:   []string{prefix + s.vendor + "_UNKNOWN"},
		}, nil
	}
	var v scoreValue
	if err := json.Unmarshal(obs.Value, &v); err != nil {
		return port.SignalResult{}, fmt.Errorf("%s: %w", s.id, err)
	}

	codes := make([]string, 0, len(v.RiskCodes)+1)
	for _, c := range v.RiskCodes {
		if strings.HasPrefix(c, prefix) {
			codes = append(codes, c)
		}
	}
	if v.Score < s.threshold {
		codes = append(codes, prefix+s.vendor+"_SCORE_LOW")
	}

	explanation := v.Explanation
	if explanation == "" {
		explanation = fmt.Sprintf("%s score %d/100", s.id, v.Score)
	}
	return port.SignalResult{
		Raw:         v.Score,
		Explanation: explanation,
		Attestation: domain.AttestationUnattested,
		RiskCodes:   codes,
	}, nil
}
