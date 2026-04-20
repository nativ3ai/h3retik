package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func readJSONLLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestPersistModuleResultWritesArtifactLootAndFinding(t *testing.T) {
	root := t.TempDir()
	action := controlAction{
		Label:    "[MODULE] Nuclei Focused Sweep",
		Command:  "docker exec h3retik-kali bash -lc 'nuclei -u http://target.example -silent'",
		ModuleID: "exploit-nuclei-focused",
		Evidence: attackModuleEvidence{
			LootKind:        "artifact",
			LootName:        "nuclei focused sweep",
			FindingSeverity: "high",
			FindingTitle:    "Template-based vulnerability candidates identified",
			FindingImpact:   "Known-pattern indicators detected.",
			Phase:           "exploit",
		},
	}

	relPath, err := persistModuleResult(root, action, "match: CVE-2024-0001")
	if err != nil {
		t.Fatalf("persistModuleResult failed: %v", err)
	}
	if relPath == "" {
		t.Fatalf("expected non-empty artifact relative path")
	}
	if _, err := os.Stat(filepath.Join(root, relPath)); err != nil {
		t.Fatalf("artifact missing at %s: %v", filepath.Join(root, relPath), err)
	}

	lootLines := readJSONLLines(t, filepath.Join(root, "telemetry", "loot.jsonl"))
	if len(lootLines) != 1 {
		t.Fatalf("expected 1 loot entry, got %d", len(lootLines))
	}
	var loot lootEntry
	if err := json.Unmarshal([]byte(lootLines[0]), &loot); err != nil {
		t.Fatalf("unmarshal loot: %v", err)
	}
	if loot.Kind != "artifact" || loot.Name != "nuclei focused sweep" {
		t.Fatalf("unexpected loot mapping: %+v", loot)
	}

	findingLines := readJSONLLines(t, filepath.Join(root, "telemetry", "findings.jsonl"))
	if len(findingLines) != 1 {
		t.Fatalf("expected 1 finding entry, got %d", len(findingLines))
	}
	var finding findingEntry
	if err := json.Unmarshal([]byte(findingLines[0]), &finding); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if finding.Severity != "high" || finding.Phase != "exploit" {
		t.Fatalf("unexpected finding mapping: %+v", finding)
	}
}

func TestPersistModuleResultLootOnlyWhenNoFindingTitle(t *testing.T) {
	root := t.TempDir()
	action := controlAction{
		Label:    "[MODULE] HTTPX Probe",
		Command:  "docker exec h3retik-kali bash -lc 'httpx -u http://target.example'",
		ModuleID: "recon-httpx",
		Evidence: attackModuleEvidence{
			LootKind: "artifact",
			LootName: "httpx output",
		},
	}

	if _, err := persistModuleResult(root, action, "http 200"); err != nil {
		t.Fatalf("persistModuleResult failed: %v", err)
	}
	lootLines := readJSONLLines(t, filepath.Join(root, "telemetry", "loot.jsonl"))
	if len(lootLines) != 1 {
		t.Fatalf("expected 1 loot entry, got %d", len(lootLines))
	}
	if _, err := os.Stat(filepath.Join(root, "telemetry", "findings.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("expected no finding file, got err=%v", err)
	}
}

func TestValidateModuleInputValueOptionalTyping(t *testing.T) {
	rawText, err := validateModuleInputValue(attackModuleInput{Key: "notes"}, "alpha-1")
	if err != nil || rawText != "alpha-1" {
		t.Fatalf("text validation failed, value=%q err=%v", rawText, err)
	}

	if _, err := validateModuleInputValue(attackModuleInput{Key: "threads", InputType: "int", Min: intPtr(1), Max: intPtr(8)}, "20"); err == nil {
		t.Fatalf("expected bounded int validation to fail")
	}

	selected, err := validateModuleInputValue(attackModuleInput{Key: "timing", InputType: "select", Options: []string{"T2", "T3", "T4"}}, "t3")
	if err != nil || selected != "T3" {
		t.Fatalf("select validation failed, value=%q err=%v", selected, err)
	}
}

func intPtr(v int) *int {
	return &v
}

func TestExploitFireActionsUseKaliForHeavyWebScanners(t *testing.T) {
	m := initialModel(t.TempDir())
	m.state.TargetURL = "http://target.example"
	m.fireMode = "exploit"
	m.exploitFireGroupIdx = 1 // Surface

	actions := m.exploitFireActions()
	modeByLabelPrefix := map[string]string{}
	for _, action := range actions {
		modeByLabelPrefix[action.Label] = action.Mode
	}

	assertKali := []string{
		"[WEB] Nuclei Sweep",
		"[WEB] Nikto Audit",
		"[WEB] FFUF Common Paths",
		"[WEB] Gobuster Dir",
	}
	findMode := func(prefix string) (string, bool) {
		for label, mode := range modeByLabelPrefix {
			if strings.HasPrefix(label, prefix) {
				return mode, true
			}
		}
		return "", false
	}
	for _, labelPrefix := range assertKali {
		mode, ok := findMode(labelPrefix)
		if !ok {
			t.Fatalf("missing expected action prefix %q", labelPrefix)
		}
		if mode != "kali" {
			t.Fatalf("expected %q to run in kali mode, got %q", labelPrefix, mode)
		}
	}
}

func TestFindingFollowupUsesKnownPipeline(t *testing.T) {
	f := findingEntry{
		Severity: "high",
		Title:    "Potential SQL_INJECTION indicator",
		Evidence: "sql injection signal matched",
		Impact:   "Critical exploitability likely",
		Endpoint: "/api/example",
	}
	action := findingFollowupAction(f, "http://target.example", nil, nil, nil)
	if !strings.Contains(action.Command, "--pipeline ") {
		t.Fatalf("expected follow-up to be pipeline-based, got %q", action.Command)
	}
	pipeline := strings.TrimSpace(action.Command[strings.LastIndex(action.Command, "--pipeline ")+len("--pipeline "):])
	valid := []string{"surface-map", "api-probe", "initial-exploit", "vuln-sweep", "web-enum", "full-escalation", "full-chain"}
	if !slices.Contains(valid, pipeline) {
		t.Fatalf("unexpected follow-up pipeline %q in command %q", pipeline, action.Command)
	}
}

func TestRebaseEndpointForKaliUsesDockerTargetForLocalHost(t *testing.T) {
	state := stateFile{
		TargetURL:    "http://target.example:8080",
		DockerTarget: "http://runtime-target:9090",
	}
	got := rebaseEndpointForKali("http://target.example:8080/api/items", state)
	if got != "http://runtime-target:9090/api/items" {
		t.Fatalf("unexpected rebased endpoint: %s", got)
	}
}

func TestExploitGraphNodeActionEndpointTargetsDockerFromKali(t *testing.T) {
	state := stateFile{
		TargetURL:    "http://target.example:8080",
		DockerTarget: "http://runtime-target:9090",
	}
	node := attackGraphNode{
		ID:    "api-endpoint-1",
		Kind:  "endpoint",
		Label: "/api/items",
		Ref:   "http://target.example:8080/api/items",
	}
	action := exploitGraphNodeAction(node, state, t.TempDir())
	if action.Mode != "kali" {
		t.Fatalf("expected kali mode, got %q", action.Mode)
	}
	if !strings.Contains(action.KaliShell, "http://runtime-target:9090/api/items") {
		t.Fatalf("expected docker target in kali shell, got %q", action.KaliShell)
	}
}

func TestBuildArchEditActionUsesInteractiveBuffer(t *testing.T) {
	root := t.TempDir()
	m := initialModel(root)
	m.state.TargetURL = "http://target.example:8080"
	m.state.DockerTarget = "http://runtime-target:9090"
	m.archEditEnabled = true
	m.archEditMethod = "PATCH"
	m.archEditEndpoint = "http://runtime-target:9090/api/items/1"
	m.archEditPayload = `{"name":"edited-from-test"}`
	m.archEditUseToken = false
	node := attackGraphNode{ID: "record-1", Kind: "record", Ref: "http://runtime-target:9090/api/items/1"}
	base := controlAction{Mode: "kali", Label: "Map Modify Action", KaliShell: "curl -sS -X PUT http://runtime-target:9090/api/items/1 --data '{}'"}

	edited, ok := m.buildArchEditAction(node, base)
	if !ok {
		t.Fatalf("expected edited action to be generated")
	}
	if edited.Mode != "kali" {
		t.Fatalf("expected kali mode, got %q", edited.Mode)
	}
	if !strings.Contains(edited.KaliShell, "for m in 'PATCH'") {
		t.Fatalf("expected PATCH method selection in edited command, got %q", edited.KaliShell)
	}
	if !strings.Contains(edited.KaliShell, "payload='{\"name\":\"edited-from-test\"}'") {
		t.Fatalf("expected custom payload in edited command, got %q", edited.KaliShell)
	}
}

func TestCycleArchGraphActionUpdatesSelectedAction(t *testing.T) {
	root := t.TempDir()
	m := initialModel(root)
	m.state.TargetURL = "http://target.example:8080"
	m.state.DockerTarget = "http://runtime-target:9090"
	m.loot = []lootEntry{
		{Kind: "collection", Name: "items", Source: "/api/items", Preview: `{"status":"success","data":[{"id":1,"name":"alpha"},{"id":2,"name":"beta"}]}`},
	}
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		t.Fatalf("expected graph nodes")
	}
	targetIdx := -1
	for idx, node := range nodes {
		if node.Kind == "collection" {
			targetIdx = idx
			break
		}
	}
	if targetIdx < 0 {
		t.Fatalf("collection node not found")
	}
	m.archGraphIdx = targetIdx
	m.archGraphActionIdx = 0
	actions := m.archGraphActionsForNode(nodes[targetIdx])
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 actions for collection node, got %d", len(actions))
	}
	m.cycleArchGraphAction(1)
	if m.archGraphActionIdx != 1 {
		t.Fatalf("expected action index 1, got %d", m.archGraphActionIdx)
	}
}

func TestExploitGraphNodeActionCollectionUsesHTTPInspect(t *testing.T) {
	state := stateFile{
		TargetURL:    "http://target.example:8080",
		DockerTarget: "http://runtime-target:9090",
	}
	node := attackGraphNode{
		ID:    "collection-items",
		Kind:  "collection",
		Label: "COLLECTION /api/items",
		Ref:   "/api/items",
	}
	action := exploitGraphNodeAction(node, state, t.TempDir())
	if action.Mode != "kali" {
		t.Fatalf("expected kali mode, got %q", action.Mode)
	}
	if !strings.Contains(action.KaliShell, "curl -sS -i") {
		t.Fatalf("expected HTTP inspect command, got %q", action.KaliShell)
	}
	if strings.Contains(action.KaliShell, "jq .") {
		t.Fatalf("expected no jq dependency in map command, got %q", action.KaliShell)
	}
}

func TestPreviewArchSelectedActionBuildsPreviewOutput(t *testing.T) {
	root := t.TempDir()
	m := initialModel(root)
	m.width = 160
	m.state.TargetURL = "http://target.example:8080"
	m.state.DockerTarget = "http://runtime-target:9090"
	m.loot = []lootEntry{
		{Kind: "collection", Name: "items", Source: "/api/items", Preview: `{"status":"success","data":[{"id":1,"name":"alpha"}]}`},
	}
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		t.Fatalf("expected graph nodes")
	}
	targetIdx := -1
	for idx, node := range nodes {
		if node.Kind == "collection" {
			targetIdx = idx
			break
		}
	}
	if targetIdx < 0 {
		t.Fatalf("collection node not found")
	}
	m.archGraphIdx = targetIdx
	m.archGraphActionIdx = 0

	m.previewArchSelectedAction()

	if !strings.Contains(strings.ToLower(m.archGraphStatus), "preview") {
		t.Fatalf("expected preview status, got %q", m.archGraphStatus)
	}
	if !strings.Contains(strings.ToLower(m.archGraphOutput), "command preview") {
		t.Fatalf("expected command preview output, got %q", m.archGraphOutput)
	}
}

func TestRenderJSONBodyStructuredObjectDataArray(t *testing.T) {
	body := `{"status":"success","data":[{"id":1,"name":"apple","price":1.99},{"id":2,"name":"orange","price":2.99}]}`
	rendered := renderJSONBodyStructured(body, 120)
	if !strings.Contains(rendered, "row[0] id=1 name=apple") {
		t.Fatalf("expected first row render, got %q", rendered)
	}
	if !strings.Contains(rendered, "row[1] id=2 name=orange") {
		t.Fatalf("expected second row render, got %q", rendered)
	}
}

func TestArchGraphRecordEditActionsFromListOutput(t *testing.T) {
	m := initialModel(t.TempDir())
	m.state.TargetURL = "http://target.example:8080"
	m.state.DockerTarget = "http://runtime-target:9090"
	node := attackGraphNode{ID: "collection-items", Kind: "collection", Ref: "/api/items", Label: "COLLECTION /api/items"}
	m.archGraphLastNodeID = node.ID
	m.archGraphLastResult = strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Content-Type: application/json",
		"",
		`{"status":"success","data":[{"id":1,"name":"apple","price":1.99},{"id":2,"name":"orange","price":2.99}]}`,
	}, "\n")

	actions := m.archGraphRecordEditActions(node)
	if len(actions) < 2 {
		t.Fatalf("expected dynamic edit actions from list output, got %d", len(actions))
	}
	first := actions[0]
	if first.Mode != "internal" || !strings.HasPrefix(first.Command, "arch:editor:load?") {
		t.Fatalf("unexpected first dynamic action: %+v", first)
	}
	values, err := url.ParseQuery(strings.TrimPrefix(first.Command, "arch:editor:load?"))
	if err != nil {
		t.Fatalf("parse action query: %v", err)
	}
	if got := values.Get("endpoint"); got != "http://runtime-target:9090/api/items/1" {
		t.Fatalf("unexpected endpoint %q", got)
	}
	if method := values.Get("method"); strings.ToUpper(method) != "PATCH" {
		t.Fatalf("expected PATCH method, got %q", method)
	}
}

func TestApplyInternalArchGraphActionLoadsEditorFromRecordAction(t *testing.T) {
	m := initialModel(t.TempDir())
	node := attackGraphNode{ID: "collection-items", Kind: "collection", Ref: "/api/items", Label: "COLLECTION /api/items"}
	action := controlAction{
		Mode:    "internal",
		Command: "arch:editor:load?endpoint=http%3A%2F%2Fruntime-target%3A9090%2Fapi%2Fitems%2F9&payload=%7B%22name%22%3A%22edited%22%7D&method=PUT",
		Label:   "Prepare Edit Session :: #9 edited",
	}

	m.applyInternalArchGraphAction(node, action)

	if !m.archEditEnabled {
		t.Fatalf("expected editor enabled")
	}
	if m.archEditEndpoint != "http://runtime-target:9090/api/items/9" {
		t.Fatalf("unexpected endpoint %q", m.archEditEndpoint)
	}
	if m.archEditMethod != "PUT" {
		t.Fatalf("unexpected method %q", m.archEditMethod)
	}
	if m.archEditPayload != `{"name":"edited"}` {
		t.Fatalf("unexpected payload %q", m.archEditPayload)
	}
}

func TestSelectOrPrepareArchEditActionAutoSelectsEditorLoad(t *testing.T) {
	m := initialModel(t.TempDir())
	node := attackGraphNode{ID: "collection-items", Kind: "collection", Ref: "/api/items", Label: "COLLECTION /api/items"}
	actions := []controlAction{
		{
			Label:     "Inspect Collection",
			Mode:      "kali",
			KaliShell: "curl -sS http://runtime-target:9090/api/items",
		},
		{
			Label:   "Prepare Edit Session :: #9 edited",
			Mode:    "internal",
			Command: "arch:editor:load?endpoint=http%3A%2F%2Fruntime-target%3A9090%2Fapi%2Fitems%2F9&payload=%7B%22name%22%3A%22edited%22%7D&method=PATCH",
		},
	}
	m.archGraphActionIdx = 0

	selected, ok := m.selectOrPrepareArchEditAction(node, actions)
	if !ok {
		t.Fatalf("expected editable action to be selected")
	}
	if !isArchEditorLoadAction(selected) {
		t.Fatalf("expected internal editor loader, got %+v", selected)
	}
	if m.archGraphActionIdx != 1 {
		t.Fatalf("expected action index to move to editor loader, got %d", m.archGraphActionIdx)
	}
	if m.archEditEndpoint != "http://runtime-target:9090/api/items/9" {
		t.Fatalf("expected editor endpoint from internal action, got %q", m.archEditEndpoint)
	}
	if m.archEditPayload != `{"name":"edited"}` {
		t.Fatalf("expected editor payload from internal action, got %q", m.archEditPayload)
	}
}

func TestSubmitManualArchEditFieldValueUpdatesPayload(t *testing.T) {
	m := initialModel(t.TempDir())
	m.archEditPayload = `{"active":true,"name":"alpha","price":1.5}`
	m.archEditFieldIdx = 1 // sorted keys -> active,name,price
	m.manualTargetInput = "beta"

	if cmd := m.submitManualArchEditFieldValue(); cmd != nil {
		t.Fatalf("expected no async cmd from field submit")
	}
	obj, ok := parseJSONPayloadObject(m.archEditPayload)
	if !ok {
		t.Fatalf("payload should remain valid json object: %q", m.archEditPayload)
	}
	if got := fmt.Sprintf("%v", obj["name"]); got != "beta" {
		t.Fatalf("expected updated field value, got %q", got)
	}
}

func TestArchCredentialFitScanActionBuildsDynamicCommand(t *testing.T) {
	root := t.TempDir()
	m := initialModel(root)
	m.state.TargetURL = "http://target.example:8080"
	m.state.DockerTarget = "http://runtime-target:9090"
	m.findings = []findingEntry{
		{Phase: "exploit", Endpoint: "/api/users", Title: "api discovered"},
	}
	m.loot = []lootEntry{
		{Kind: "credential", Name: "admin creds", Source: "email=admin@example.com", Preview: `{"email":"admin@example.com","password":"secret123"}`},
	}
	telemetryLootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(telemetryLootPath, lootEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Kind:      "token",
		Name:      "jwt",
		Source:    "auth",
		Preview:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}); err != nil {
		t.Fatalf("write token loot: %v", err)
	}

	action, ok := m.archCredentialFitScanAction(attackGraphNode{Kind: "endpoint", Ref: "/api/users"})
	if !ok {
		t.Fatalf("expected credential fit action")
	}
	if action.Mode != "kali" {
		t.Fatalf("expected kali mode, got %q", action.Mode)
	}
	if !strings.Contains(action.KaliShell, "CRED_FIT ") {
		t.Fatalf("expected credential fit markers in command, got %q", action.KaliShell)
	}
	if !strings.Contains(action.KaliShell, "Authorization: Bearer") {
		t.Fatalf("expected bearer token probe in command, got %q", action.KaliShell)
	}
}

func TestApplyCredentialFitSignalsPromotesPotentialCredLoot(t *testing.T) {
	root := t.TempDir()
	if err := appendLootJSONL(filepath.Join(root, "telemetry", "loot.jsonl"), lootEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Kind:      "credential",
		Name:      "potential creds",
		Source:    "manual",
		Preview:   "username=admin@example.com password=secret123",
	}); err != nil {
		t.Fatalf("seed loot: %v", err)
	}

	m := initialModel(root)
	wrote := m.applyCredentialFitSignals("CRED_FIT endpoint=http://credential-fit.example/api/login baseline=401 bearer=200")
	if !wrote {
		t.Fatalf("expected credential fit signal writes")
	}

	loot := loadJSONL[lootEntry](filepath.Join(root, "telemetry", "loot.jsonl"))
	foundFit := false
	foundPromoted := false
	for _, item := range loot {
		if strings.EqualFold(strings.TrimSpace(item.Kind), "credential-fit") && strings.Contains(item.Source, "/api/login") {
			foundFit = true
		}
		meta := strings.ToLower(strings.TrimSpace(item.Kind + " " + item.Name + " " + item.Preview))
		if strings.EqualFold(strings.TrimSpace(item.Kind), "credential") &&
			strings.Contains(strings.ToLower(item.Name), "auth-fit") &&
			strings.Contains(strings.ToLower(item.Name), "/api/login") &&
			strings.Contains(meta, "[validated] auth-fit") &&
			!strings.Contains(strings.ToLower(strings.TrimSpace(item.Name)), "potential") {
			foundPromoted = true
		}
	}
	if !foundFit {
		t.Fatalf("expected credential-fit loot entry")
	}
	if !foundPromoted {
		t.Fatalf("expected potential credential loot promoted with validated auth-fit tag + target mapping")
	}
}

func TestLootResultMsgAppliesCredentialFitSignals(t *testing.T) {
	root := t.TempDir()
	if err := appendLootJSONL(filepath.Join(root, "telemetry", "loot.jsonl"), lootEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Kind:      "credential",
		Name:      "potential creds",
		Source:    "manual",
		Preview:   "username=admin@example.com password=secret123",
	}); err != nil {
		t.Fatalf("seed loot: %v", err)
	}
	m := initialModel(root)

	updated, _ := m.Update(lootResultMsg{
		Label:   "Loot Action :: credential fit sweep",
		Command: "docker exec h3retik-kali bash -lc ...",
		Output:  "CRED_FIT endpoint=http://credential-fit.example/api/login baseline=401 bearer=200",
	})
	next, ok := updated.(model)
	if !ok {
		t.Fatalf("expected model type after update")
	}
	loot := loadJSONL[lootEntry](filepath.Join(root, "telemetry", "loot.jsonl"))
	if len(loot) == 0 {
		t.Fatalf("expected loot entries after update")
	}
	foundFit := false
	for _, item := range loot {
		if strings.EqualFold(strings.TrimSpace(item.Kind), "credential-fit") && strings.Contains(item.Source, "/api/login") {
			foundFit = true
			break
		}
	}
	if !foundFit {
		t.Fatalf("expected credential-fit signal persisted from loot result")
	}
	if strings.TrimSpace(next.lootFireOutcome) != "success" {
		t.Fatalf("expected loot action success outcome, got %q", next.lootFireOutcome)
	}
}

func TestApplyCredentialFitSignalsPrefersPotentialCredOverModuleArtifact(t *testing.T) {
	root := t.TempDir()
	lootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(lootPath, lootEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Kind:      "credential",
		Name:      "potential creds",
		Source:    "xsser-auto",
		Preview:   "login username=bob password=secret",
	}); err != nil {
		t.Fatalf("seed potential loot: %v", err)
	}
	if err := appendLootJSONL(lootPath, lootEntry{
		Timestamp: "2026-04-16T00:00:01Z",
		Kind:      "credential",
		Name:      "hydra credential check",
		Source:    "artifacts/exploit/modules/abc.txt",
		Preview:   "[ERROR] File for logins not found: /usr/share/wordlists/metasploit/unix_users.txt",
	}); err != nil {
		t.Fatalf("seed module loot: %v", err)
	}
	m := initialModel(root)
	if !m.applyCredentialFitSignals("CRED_FIT endpoint=http://credential-fit.example/api/login baseline=401 bearer=200") {
		t.Fatalf("expected credential fit signal writes")
	}
	loot := loadJSONL[lootEntry](lootPath)
	potentialUpdated := false
	moduleUntouched := false
	for _, item := range loot {
		if strings.EqualFold(item.Source, "xsser-auto") &&
			strings.Contains(strings.ToLower(item.Name), "auth-fit") &&
			!strings.Contains(strings.ToLower(item.Name), "potential") {
			potentialUpdated = true
		}
		if strings.Contains(item.Source, "artifacts/exploit/modules/abc.txt") &&
			!strings.Contains(strings.ToLower(item.Preview), "[validated] auth-fit") {
			moduleUntouched = true
		}
	}
	if !potentialUpdated {
		t.Fatalf("expected potential credential item to be promoted")
	}
	if !moduleUntouched {
		t.Fatalf("expected module artifact credential preview to remain untouched")
	}
}

func TestLootFollowupActionsAddCredentialFitSweepForPotentialCreds(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "telemetry"), 0o755); err != nil {
		t.Fatalf("mkdir telemetry: %v", err)
	}
	stateRaw, err := json.Marshal(stateFile{
		TargetURL:    "http://target.example:8080",
		DockerTarget: "http://runtime-target:9090",
	})
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "telemetry", "state.json"), stateRaw, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := appendFindingJSONL(filepath.Join(root, "telemetry", "findings.jsonl"), findingEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Severity:  "medium",
		Title:     "API endpoint discovered",
		Endpoint:  "/api/users",
		Evidence:  "recon",
		Impact:    "surface expanded",
		Phase:     "exploit",
	}); err != nil {
		t.Fatalf("write finding: %v", err)
	}
	item := lootEntry{
		Kind:    "credential",
		Name:    "potential creds",
		Source:  "manual-note",
		Preview: "username=admin@example.com password=secret123",
	}
	actions := lootFollowupActions(item, "http://target.example:8080", root)
	found := false
	for _, action := range actions {
		if !strings.Contains(strings.ToLower(action.Label), "credential fit sweep") {
			continue
		}
		found = true
		if !strings.Contains(action.KaliShell, "CRED_FIT") {
			t.Fatalf("expected credential-fit markers in shell, got %q", action.KaliShell)
		}
		if !strings.Contains(action.KaliShell, "http://runtime-target:9090/api/users") {
			t.Fatalf("expected telemetry endpoint in credential-fit shell, got %q", action.KaliShell)
		}
	}
	if !found {
		t.Fatalf("expected credential fit sweep follow-up action")
	}
}

func TestLootFollowupAuthBoundaryCheckUsesDynamicEndpointSet(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "telemetry"), 0o755); err != nil {
		t.Fatalf("mkdir telemetry: %v", err)
	}
	stateRaw, err := json.Marshal(stateFile{
		TargetURL:    "http://target.example:8080",
		DockerTarget: "http://runtime-target:9090",
	})
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "telemetry", "state.json"), stateRaw, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := appendFindingJSONL(filepath.Join(root, "telemetry", "findings.jsonl"), findingEntry{
		Timestamp: "2026-04-16T00:00:00Z",
		Severity:  "medium",
		Title:     "API endpoint discovered",
		Endpoint:  "/api/users",
		Evidence:  "recon",
		Impact:    "surface expanded",
		Phase:     "exploit",
	}); err != nil {
		t.Fatalf("write finding: %v", err)
	}
	item := lootEntry{
		Kind:    "credential",
		Name:    "potential creds",
		Source:  "manual-note",
		Preview: "username=admin@example.com password=secret123",
	}
	actions := lootFollowupActions(item, "http://target.example:8080", root)
	var boundary controlAction
	found := false
	for _, action := range actions {
		if strings.Contains(strings.ToLower(action.Label), "auth boundary check") {
			found = true
			boundary = action
			break
		}
	}
	if !found {
		t.Fatalf("expected auth boundary check action")
	}
	if strings.Contains(boundary.KaliShell, "/login /api/login /auth /api/auth") {
		t.Fatalf("expected dynamic endpoint probe shell, got %q", boundary.KaliShell)
	}
	if !strings.Contains(boundary.KaliShell, "for ep in") || !strings.Contains(boundary.KaliShell, "http://runtime-target:9090/api/users") {
		t.Fatalf("expected discovered endpoint in dynamic probe shell, got %q", boundary.KaliShell)
	}
}

func TestExploitAPIDiscoveryIgnoresNoisyCredentialArtifactText(t *testing.T) {
	loot := []lootEntry{
		{
			Kind:    "credential",
			Name:    "hydra credential check [validated]",
			Source:  "artifacts/exploit/modules/20260416-114347-access-hydra-http-bruteforce.txt",
			Preview: "[ERROR] file for logins not found: /usr/share/wordlists/metasploit/unix_users.txt | credential fit validated @ http://runtime-target:9090/xsser-auto, http://runtime-target:9090/api/products",
		},
		{
			Kind:    "path",
			Name:    "route discovery",
			Source:  "get /api/users",
			Preview: "found endpoint",
		},
	}
	endpoints := exploitAPIDiscovery(nil, loot, "http://target.example:8080")
	joined := strings.Join(endpoints, "\n")
	if !strings.Contains(joined, "http://target.example:8080/api/users") {
		t.Fatalf("expected sanitized /api/users endpoint, got %v", endpoints)
	}
	if strings.Contains(joined, "http://runtime-target:9090/api/products") {
		t.Fatalf("expected cross-host endpoint to be excluded, got %v", endpoints)
	}
	if strings.Contains(joined, "unix_users.txt") || strings.Contains(joined, "get%20/api/users") {
		t.Fatalf("unexpected noisy endpoint leakage: %v", endpoints)
	}
}

func TestCredentialFitEndpointsFromOutputParsesHits(t *testing.T) {
	output := strings.Join([]string{
		"NOFIT endpoint=http://target/api/a baseline=401 bearer=401",
		"CRED_FIT endpoint=http://target/api/b baseline=401 bearer=200",
		"CRED_FIT endpoint=http://target/api/c baseline=404 basic=200",
		"CRED_FIT endpoint=http://target/api/b baseline=401 bearer=200",
	}, "\n")
	hits := credentialFitEndpointsFromOutput(output)
	if len(hits) != 2 {
		t.Fatalf("expected 2 unique hits, got %d (%v)", len(hits), hits)
	}
	if hits[0] != "http://target/api/b" || hits[1] != "http://target/api/c" {
		t.Fatalf("unexpected parsed hits: %v", hits)
	}
}

func TestExploitInnerTargetsIncludesMappedEndpoints(t *testing.T) {
	findings := []findingEntry{
		{Endpoint: "/api/users"},
	}
	loot := []lootEntry{
		{Kind: "path", Source: "/api/products"},
	}
	targets := exploitInnerTargets(findings, loot, "http://target.example:8080")
	joined := strings.Join(targets, "\n")
	if !strings.Contains(joined, "http://target.example:8080/api/users") {
		t.Fatalf("expected /api/users in inner target map, got %v", targets)
	}
	if !strings.Contains(joined, "http://target.example:8080/api/products") {
		t.Fatalf("expected /api/products in inner target map, got %v", targets)
	}
}

func TestExploitInnerTargetsAvoidsHardcodedAuthFallbacks(t *testing.T) {
	targets := exploitInnerTargets(nil, nil, "http://target.example:8080")
	joined := strings.Join(targets, "\n")
	if strings.Contains(joined, "/api/login") || strings.Contains(joined, "/oauth/token") || strings.Contains(joined, "/auth") {
		t.Fatalf("unexpected hardcoded auth fallback targets: %v", targets)
	}
	if !strings.Contains(joined, "http://target.example:8080") {
		t.Fatalf("expected base target in inner targets, got %v", targets)
	}
}

func TestBruteforceAdaptiveShellUsesConfiguredSource(t *testing.T) {
	m := initialModel(t.TempDir())
	m.state.TargetURL = "http://target.example:8080"
	m.exploitBruteCredSrcIdx = 2  // manual
	m.exploitBruteAuthModeIdx = 1 // basic
	m.exploitBruteManualUser = "operator@example.com"
	m.exploitBruteManualPass = "secret"
	shell := m.bruteforceAdaptiveShell("http://target.example:8080/api/login")
	if !strings.Contains(shell, "cred_source='manual'") {
		t.Fatalf("expected manual source in shell, got %q", shell)
	}
	if !strings.Contains(shell, "auth_mode='basic'") {
		t.Fatalf("expected basic mode in shell, got %q", shell)
	}
	if !strings.Contains(shell, "operator@example.com:secret") {
		t.Fatalf("expected manual pair in shell, got %q", shell)
	}
}

func TestApplyControlResultSignalsPersistsBruteHits(t *testing.T) {
	root := t.TempDir()
	m := initialModel(root)
	msg := controlResultMsg{
		Label: "brute",
		Output: strings.Join([]string{
			"BRUTE_TRY endpoint=http://target/api/login method=basic user=admin code=401 baseline=401",
			"BRUTE_HIT endpoint=http://target/api/login method=form user=admin@example.com code=200 baseline=401 source=inferred",
		}, "\n"),
	}

	m.applyControlResultSignals(msg)

	lootLines := readJSONLLines(t, filepath.Join(root, "telemetry", "loot.jsonl"))
	if len(lootLines) == 0 {
		t.Fatalf("expected brute hit loot entry")
	}
	findingLines := readJSONLLines(t, filepath.Join(root, "telemetry", "findings.jsonl"))
	if len(findingLines) == 0 {
		t.Fatalf("expected brute hit finding entry")
	}
}

func TestBrutePreflightWarningDetectsKnownCredentialFit(t *testing.T) {
	m := initialModel(t.TempDir())
	m.state.TargetURL = "http://target.example:8080"
	m.loot = []lootEntry{
		{
			Kind:    "credential-fit",
			Name:    "credential fit",
			Source:  "/api/login",
			Preview: "credential fit scan confirmed authenticated response delta",
		},
	}
	warning := m.brutePreflightWarning("http://target.example:8080/api/login")
	if !strings.Contains(strings.ToLower(warning), "known credential-fit") {
		t.Fatalf("expected known credential-fit warning, got %q", warning)
	}
}

func TestPreflightControlActionBruteReturnsSoftWarning(t *testing.T) {
	m := initialModel(t.TempDir())
	m.state.TargetURL = "http://target.example:8080"
	m.exploitActiveTarget = "http://target.example:8080/api/login"
	m.exploitBruteManualUser = "admin@example.com"
	m.exploitBruteManualPass = "secret"
	m.loot = []lootEntry{
		{Kind: "credential-fit", Name: "credential fit", Source: "/api/login", Preview: "fit"},
	}
	action := controlAction{
		Label:    "[BRUTE] Run Adaptive Endpoint Attack",
		Mode:     "local",
		Command:  "echo test",
		Args:     []string{"echo", "test"},
		ActionID: "bruteforce-adaptive",
	}
	ok, reason := m.preflightControlAction(action)
	if !ok {
		t.Fatalf("expected soft-warning preflight success, got block: %q", reason)
	}
	if !strings.Contains(strings.ToLower(reason), "known credential-fit") {
		t.Fatalf("expected preflight warning reason, got %q", reason)
	}
}
