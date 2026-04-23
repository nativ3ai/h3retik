package telemetry

import "time"

type ArtifactRef struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Source  string `json:"source"`
	Preview string `json:"preview"`
	ID      string `json:"id"`
}

type Event struct {
	Timestamp      time.Time         `json:"timestamp"`
	RunID          string            `json:"run_id"`
	Mode           string            `json:"mode"`
	Lane           string            `json:"lane"`
	ActionID       string            `json:"action_id"`
	TargetRef      string            `json:"target_ref"`
	Command        string            `json:"command"`
	Status         string            `json:"status"`
	Confidence     int               `json:"confidence"`
	OpsecDelta     int               `json:"opsec_delta"`
	PwnDelta       int               `json:"pwn_delta"`
	Artifacts      []ArtifactRef     `json:"artifacts"`
	EvidenceRefs   []string          `json:"evidence_refs"`
	CorrelationIDs []string          `json:"correlation_ids"`
	Meta           map[string]string `json:"meta"`
}

type Scores struct {
	Opsec int `json:"opsec"`
	Pwned int `json:"pwned"`
}

type Unlock struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Unlocked    bool   `json:"unlocked"`
}

type NodeState struct {
	NodeID      string `json:"node_id"`
	State       string `json:"state"`
	Confidence  int    `json:"confidence"`
	LastAction  string `json:"last_action"`
	LastUpdated string `json:"last_updated"`
}

type FindingView struct {
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Lane           string `json:"lane"`
	Confidence     int    `json:"confidence"`
	Exploitability int    `json:"exploitability"`
}

type LootView struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Lane       string `json:"lane"`
	Confidence int    `json:"confidence"`
	Actionable bool   `json:"actionable"`
}

type RunState struct {
	Phase      string               `json:"phase"`
	NextBest   string               `json:"next_best"`
	Scores     Scores               `json:"scores"`
	Unlocks    []Unlock             `json:"unlocks"`
	NodeStates map[string]NodeState `json:"node_states"`
	Findings   []FindingView        `json:"findings"`
	Loot       []LootView           `json:"loot"`
}
