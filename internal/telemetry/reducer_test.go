package telemetry

import (
	"testing"
	"time"
)

func TestReduceBuildsScoresAndNodes(t *testing.T) {
	now := time.Now().UTC()
	events := []Event{
		{Timestamp: now.Add(-2 * time.Minute), Lane: "surface", ActionID: "scan", Status: "ok", Confidence: 60, OpsecDelta: 4, PwnDelta: 8},
		{Timestamp: now.Add(-1 * time.Minute), Lane: "access", ActionID: "cred-fit", Status: "ok", Confidence: 82, OpsecDelta: 8, PwnDelta: 22,
			Artifacts: []ArtifactRef{{Kind: "credential", Name: "auth hit"}},
		},
	}
	state := Reduce(events)
	if state.Scores.Pwned <= 0 {
		t.Fatalf("expected pwn score > 0, got %d", state.Scores.Pwned)
	}
	if state.Scores.Opsec >= 100 {
		t.Fatalf("expected opsec to reduce from 100, got %d", state.Scores.Opsec)
	}
	if ns := state.NodeStates["auth"]; ns.State == "OPEN" {
		t.Fatalf("expected auth node to progress, got %s", ns.State)
	}
	if len(state.Loot) == 0 {
		t.Fatalf("expected loot view entries")
	}
}

func TestReduceDefaultsWhenNoEvents(t *testing.T) {
	state := Reduce(nil)
	if state.Phase != "recon" {
		t.Fatalf("expected recon phase, got %s", state.Phase)
	}
	if len(state.NodeStates) == 0 {
		t.Fatalf("expected default node states")
	}
}
