package telemetry

import (
	"sort"
	"strings"
	"time"
)

func Reduce(events []Event) RunState {
	state := RunState{
		Phase:      "recon",
		NextBest:   "Run initial surface mapping.",
		Scores:     Scores{Opsec: 100, Pwned: 0},
		Unlocks:    defaultUnlocks(),
		NodeStates: map[string]NodeState{},
		Findings:   []FindingView{},
		Loot:       []LootView{},
	}
	if len(events) == 0 {
		state.NodeStates = defaultNodeStates()
		return state
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	laneScore := map[string]int{}
	latestByNode := map[string]NodeState{}
	findingViews := []FindingView{}
	lootViews := []LootView{}
	opsec := 100
	pwn := 0

	for _, event := range events {
		lane := normalizeLane(event.Lane)
		if lane == "" {
			lane = inferLane(event)
		}
		laneScore[lane] += max(event.PwnDelta, 0)
		opsec -= max(event.OpsecDelta, 0)
		pwn += max(event.PwnDelta, 0)

		nodeID := laneToNode(lane)
		if nodeID == "" {
			nodeID = "surface"
		}
		ns := latestByNode[nodeID]
		ns.NodeID = nodeID
		ns.State = nodeStateForEvent(event)
		ns.Confidence = max(ns.Confidence, clamp(event.Confidence, 0, 100))
		ns.LastAction = valueOr(strings.TrimSpace(event.ActionID), strings.TrimSpace(event.Command))
		ns.LastUpdated = event.Timestamp.UTC().Format(time.RFC3339)
		latestByNode[nodeID] = ns

		for _, art := range event.Artifacts {
			confidence := clamp(max(event.Confidence, confidenceFromArtifact(art)), 0, 100)
			lootViews = append(lootViews, LootView{
				Kind:       strings.TrimSpace(art.Kind),
				Name:       valueOr(strings.TrimSpace(art.Name), valueOr(strings.TrimSpace(art.ID), "artifact")),
				Lane:       lane,
				Confidence: confidence,
				Actionable: actionableArtifact(art),
			})
		}

		if sev := strings.TrimSpace(event.Meta["severity"]); sev != "" {
			findingViews = append(findingViews, FindingView{
				Title:          valueOr(strings.TrimSpace(event.Meta["title"]), valueOr(strings.TrimSpace(event.ActionID), "finding")),
				Severity:       sev,
				Lane:           lane,
				Confidence:     clamp(max(event.Confidence, 40), 0, 100),
				Exploitability: clamp(exploitabilityScore(sev, lane), 0, 100),
			})
		}
	}

	state.Scores.Opsec = clamp(opsec, 0, 100)
	state.Scores.Pwned = clamp(pwn, 0, 100)
	state.NodeStates = defaultNodeStates()
	for key, val := range latestByNode {
		state.NodeStates[key] = val
	}

	state.Phase = inferPhaseFromLaneScores(laneScore)
	state.NextBest = inferNextBest(state)
	state.Unlocks = unlocksFromNodeState(state.NodeStates)
	state.Findings = dedupeFindings(findingViews)
	state.Loot = dedupeLoot(lootViews)
	return state
}

func defaultUnlocks() []Unlock {
	return []Unlock{
		{Key: "surface-map", Label: "Surface Map", Description: "Enumerate exposed surface and endpoint graph.", Unlocked: false},
		{Key: "foothold", Label: "Foothold", Description: "Establish first verified access path.", Unlocked: false},
		{Key: "auth-pivot", Label: "Auth Pivot", Description: "Use credentials/tokens for authenticated paths.", Unlocked: false},
		{Key: "objective-control", Label: "Objective Control", Description: "Execute objective-level actions with evidence.", Unlocked: false},
	}
}

func defaultNodeStates() map[string]NodeState {
	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]NodeState{
		"surface":   {NodeID: "surface", State: "OPEN", Confidence: 0, LastUpdated: now},
		"auth":      {NodeID: "auth", State: "OPEN", Confidence: 0, LastUpdated: now},
		"api":       {NodeID: "api", State: "OPEN", Confidence: 0, LastUpdated: now},
		"db":        {NodeID: "db", State: "OPEN", Confidence: 0, LastUpdated: now},
		"files":     {NodeID: "files", State: "OPEN", Confidence: 0, LastUpdated: now},
		"impact":    {NodeID: "impact", State: "OPEN", Confidence: 0, LastUpdated: now},
		"objective": {NodeID: "objective", State: "OPEN", Confidence: 0, LastUpdated: now},
	}
}

func laneToNode(lane string) string {
	switch normalizeLane(lane) {
	case "recon", "surface", "web-adv":
		return "surface"
	case "exploit", "access", "ad", "k8s", "crack":
		return "auth"
	case "privilege":
		return "db"
	case "objective":
		return "objective"
	default:
		return "surface"
	}
}

func inferLane(event Event) string {
	meta := strings.ToLower(strings.TrimSpace(event.ActionID + " " + event.Command + " " + event.Lane))
	switch {
	case strings.Contains(meta, "nmap") || strings.Contains(meta, "whatweb") || strings.Contains(meta, "recon"):
		return "recon"
	case strings.Contains(meta, "ffuf") || strings.Contains(meta, "surface") || strings.Contains(meta, "nikto"):
		return "surface"
	case strings.Contains(meta, "xss") || strings.Contains(meta, "sqli") || strings.Contains(meta, "exploit") || strings.Contains(meta, "sqlmap"):
		return "exploit"
	case strings.Contains(meta, "token") || strings.Contains(meta, "credential") || strings.Contains(meta, "auth") || strings.Contains(meta, "hydra"):
		return "access"
	case strings.Contains(meta, "privesc") || strings.Contains(meta, "sudo"):
		return "privilege"
	case strings.Contains(meta, "tamper") || strings.Contains(meta, "exfil") || strings.Contains(meta, "objective"):
		return "objective"
	default:
		return "surface"
	}
}

func nodeStateForEvent(event Event) string {
	status := strings.ToLower(strings.TrimSpace(event.Status))
	if status == "error" || status == "failed" || status == "fail" {
		return "OPEN"
	}
	if event.PwnDelta >= 20 || strings.Contains(strings.ToLower(event.ActionID), "objective") {
		return "PWNED"
	}
	if event.PwnDelta >= 8 || event.Confidence >= 70 {
		return "VERIFIED"
	}
	return "PARTIAL"
}

func inferPhaseFromLaneScores(scores map[string]int) string {
	if scores["objective"] > 0 {
		return "objective"
	}
	if scores["privilege"] > 0 || scores["access"] > 0 {
		return "access"
	}
	if scores["exploit"] > 0 {
		return "exploit"
	}
	if scores["surface"] > 0 || scores["web-adv"] > 0 {
		return "surface"
	}
	return "recon"
}

func inferNextBest(state RunState) string {
	if ns, ok := state.NodeStates["objective"]; ok && strings.EqualFold(ns.State, "PWNED") {
		return "Objective achieved. Snapshot run and report evidence."
	}
	if ns, ok := state.NodeStates["auth"]; ok && !strings.EqualFold(ns.State, "PWNED") {
		return "Prioritize credential-fit and auth boundary validation."
	}
	if ns, ok := state.NodeStates["surface"]; ok && strings.EqualFold(ns.State, "OPEN") {
		return "Expand surface map before exploit attempts."
	}
	if state.Scores.Opsec < 35 {
		return "Reduce noisy actions and switch to low-trace validation."
	}
	return "Advance one lane with highest confidence evidence."
}

func unlocksFromNodeState(nodes map[string]NodeState) []Unlock {
	unlocks := defaultUnlocks()
	for idx := range unlocks {
		switch unlocks[idx].Key {
		case "surface-map":
			unlocks[idx].Unlocked = nodeUnlocked(nodes["surface"])
		case "foothold":
			unlocks[idx].Unlocked = nodeUnlocked(nodes["auth"])
		case "auth-pivot":
			unlocks[idx].Unlocked = nodeUnlocked(nodes["api"]) || nodeUnlocked(nodes["db"])
		case "objective-control":
			unlocks[idx].Unlocked = nodeUnlocked(nodes["objective"])
		}
	}
	return unlocks
}

func nodeUnlocked(ns NodeState) bool {
	return strings.EqualFold(ns.State, "VERIFIED") || strings.EqualFold(ns.State, "PWNED")
}

func dedupeFindings(items []FindingView) []FindingView {
	if len(items) == 0 {
		return items
	}
	seen := map[string]FindingView{}
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.Title + "|" + item.Severity + "|" + item.Lane))
		if key == "" {
			continue
		}
		if old, ok := seen[key]; ok {
			if item.Confidence > old.Confidence {
				seen[key] = item
			}
			continue
		}
		seen[key] = item
	}
	out := make([]FindingView, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			return out[i].Confidence > out[j].Confidence
		}
		return severityWeight(out[i].Severity) > severityWeight(out[j].Severity)
	})
	return out
}

func dedupeLoot(items []LootView) []LootView {
	if len(items) == 0 {
		return items
	}
	seen := map[string]LootView{}
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.Kind + "|" + item.Name + "|" + item.Lane))
		if key == "" {
			continue
		}
		if old, ok := seen[key]; ok {
			if item.Confidence > old.Confidence {
				seen[key] = item
			}
			continue
		}
		seen[key] = item
	}
	out := make([]LootView, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Actionable == out[j].Actionable {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Actionable
	})
	return out
}

func confidenceFromArtifact(art ArtifactRef) int {
	meta := strings.ToLower(strings.TrimSpace(art.Kind + " " + art.Name + " " + art.Preview))
	score := 45
	if strings.Contains(meta, "credential") || strings.Contains(meta, "token") || strings.Contains(meta, "jwt") {
		score += 20
	}
	if strings.Contains(meta, "database") || strings.Contains(meta, "backup") {
		score += 12
	}
	if strings.Contains(meta, "endpoint") || strings.Contains(meta, "api") {
		score += 10
	}
	return clamp(score, 0, 100)
}

func actionableArtifact(art ArtifactRef) bool {
	meta := strings.ToLower(strings.TrimSpace(art.Kind + " " + art.Name + " " + art.Source))
	signals := []string{"credential", "token", "jwt", "endpoint", "session", "db", "database", "file"}
	for _, signal := range signals {
		if strings.Contains(meta, signal) {
			return true
		}
	}
	return false
}

func exploitabilityScore(severity, lane string) int {
	score := severityWeight(severity) * 18
	switch normalizeLane(lane) {
	case "exploit", "access", "privilege", "objective":
		score += 20
	}
	return clamp(score, 0, 100)
}

func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func normalizeLane(lane string) string {
	lane = strings.ToLower(strings.TrimSpace(lane))
	lane = strings.ReplaceAll(lane, "_", "-")
	return lane
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func clamp(v, low, high int) int {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
