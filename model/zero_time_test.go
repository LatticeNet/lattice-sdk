package model

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// zeroTimeOmitted names, per type, every time.Time member whose zero value
// means "never" or "not set" and must therefore be absent from the wire.
// omitempty never omits a time.Time (a struct is never empty), so each of
// these used to ship "0001-01-01T00:00:00Z", which a console reads as a real
// date. A path with a dot names a member of a nested object.
var zeroTimeOmitted = []struct {
	name  string
	value any
	keys  []string
}{
	{"Token", Token{}, []string{"revoked_at"}},
	{"Node", Node{}, []string{
		"token_last_used_at", "last_seen", "online_since", "disabled_at",
		"metrics.collected_at", "host_facts.boot_time", "host_facts.reported_at",
		"agent_debug.updated_at", "trace.updated_at",
	}},
	{"Node with launch, ip and geo", Node{AgentLaunch: &AgentLaunchConfig{}, IPConfig: &NodeIPConfig{}, Geo: &NodeGeo{}}, []string{
		"agent_launch.updated_at", "ip_config.updated_at", "geo.updated_at",
	}},
	{"MachineProfile", MachineProfile{}, []string{"purchased_at", "next_renewal"}},
	{"DNSDeployment", DNSDeployment{}, []string{"cert_not_after", "last_applied_at", "last_published_at"}},
	{"GeoRouting", GeoRouting{}, []string{"last_applied_at", "last_delegated_at"}},
	{"NetPolicy", NetPolicy{}, []string{"last_applied_at"}},
	{"NodeGuardBinding", NodeGuardBinding{}, []string{"last_applied_at"}},
	{"WGExternalPeer", WGExternalPeer{}, []string{"last_issued_at"}},
	{"ProxyUser", ProxyUser{}, []string{"expires_at", "last_seen_at"}},
	{"ProxyNodeProfile", ProxyNodeProfile{}, []string{
		"last_apply_at", "usage_collector_checked_at", "usage_collector_last_ok_at", "usage_collector_last_error_at",
	}},
	{"ProxyUsageSnapshot", ProxyUsageSnapshot{}, []string{"collector_checked_at"}},
	{"SingBoxRuntime", SingBoxRuntime{}, []string{"started_at", "probed_at"}},
	{"Task", Task{TargetLeases: map[string]TaskLease{"node_1": {LeaseID: "lease_1"}}}, []string{
		"started_at", "finished_at", "target_leases.node_1.started_at",
	}},
	{"TerminalSession", TerminalSession{}, []string{"opened_at", "closed_at", "last_seen"}},
	{"StorageAccessToken", StorageAccessToken{}, []string{"revoked_at", "last_used_at"}},
	{"PluginInstallation", PluginInstallation{}, []string{"verified_at", "installed_at", "activated_at", "disabled_at"}},
	{"DDNSProfile", DDNSProfile{}, []string{"last_run_at"}},
	{"AgentMirror", AgentMirror{}, []string{"created_at", "updated_at"}},
	{"OIDCIdentity", OIDCIdentity{}, []string{"second_factor_at"}},
}

func lookupJSONPath(t *testing.T, doc map[string]any, path string) (any, bool) {
	t.Helper()
	parts := strings.Split(path, ".")
	var cur any = doc
	for _, part := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func marshalToDoc(t *testing.T, name string, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	return doc
}

// setEveryTime sets every time.Time reachable from v (through structs,
// non-nil pointers, slices and map values) to at.
func setEveryTime(v reflect.Value, at time.Time) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			setEveryTime(v.Elem(), at)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(at))
			return
		}
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				setEveryTime(f, at)
			}
		}
	case reflect.Slice:
		for i := range v.Len() {
			setEveryTime(v.Index(i), at)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(v.MapIndex(key))
			setEveryTime(elem, at)
			v.SetMapIndex(key, elem)
		}
	}
}

func TestZeroTimesAreAbsentFromTheWire(t *testing.T) {
	at := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	for _, tc := range zeroTimeOmitted {
		doc := marshalToDoc(t, tc.name, tc.value)
		for _, key := range tc.keys {
			if v, ok := lookupJSONPath(t, doc, key); ok {
				t.Errorf("%s: zero %s is on the wire as %v", tc.name, key, v)
			}
		}
		// The same value with every time set carries every listed key, so a
		// path in the table names a member the type really has.
		set := reflect.New(reflect.TypeOf(tc.value)).Elem()
		set.Set(reflect.ValueOf(tc.value))
		setEveryTime(set, at)
		doc = marshalToDoc(t, tc.name, set.Interface())
		for _, key := range tc.keys {
			if v, ok := lookupJSONPath(t, doc, key); !ok || v != at.Format(time.RFC3339) {
				t.Errorf("%s: set %s is %v (present %v), want %s", tc.name, key, v, ok, at.Format(time.RFC3339))
			}
		}
	}
}

// alwaysSetTimes are the value time.Time members that keep a plain tag
// because their writer always sets them: an agent on every report, the
// server when it records or computes the value, or the session that opens
// them. created_at and updated_at need no entry; the store sets both on
// every write. Anything else must be omitzero, so a new optional instant
// cannot arrive with omitempty, or with no option, and ship year 1.
var alwaysSetTimes = map[string]string{
	"AgentDebugBatch.CapturedAt":     "agent, every batch",
	"AgentHealth.StartedAt":          "agent, process start",
	"AuditEvent.At":                  "server, when recorded",
	"ConnRecord.StartedAt":           "agent, connection open",
	"GuardNodeReality.CollectedAt":   "agent, every report",
	"GuardSSHDFacts.ObservedAt":      "agent, behind a nil-able pointer",
	"LatencyBucket.At":               "computed bucket",
	"LatencyRollups.GeneratedAt":     "computed per response",
	"LatencySeries.From":             "computed window",
	"LatencySeries.To":               "computed window",
	"LineCatalogueProbe.At":          "set with the verdict, behind a nil-able pointer",
	"LogBatch.CapturedAt":            "agent, every batch",
	"LogLine.At":                     "agent, every line",
	"MonitorResult.At":               "server, when recorded",
	"PathBaseline.From":              "computed window",
	"PathBaseline.To":                "computed window",
	"PathBucket.T":                   "computed bucket",
	"PathDegradation.EvaluatedAt":    "server, every evaluation",
	"PathDegradation.Since":          "server, when the degradation opened",
	"PathMatrix.ObservedAt":          "computed per response",
	"PathMethodChange.T":             "computed per change",
	"PathPreviousSeries.From":        "computed window",
	"PathPreviousSeries.To":          "computed window",
	"PathSeries.From":                "computed window",
	"PathSeries.To":                  "computed window",
	"ProxyUsageSnapshot.At":          "agent, every snapshot",
	"SingBoxInventory.At":            "agent, every inventory",
	"SubscriptionSnapshot.FetchedAt": "the fetch that produced the snapshot",
	"TaskResult.FinishedAt":          "agent, every exit path",
	"TaskResult.StartedAt":           "agent, taskexec start",
	"TraceAgentSession.ExpiresAt":    "set when the session opens",
	"TraceBatch.CapturedAt":          "agent, every batch",
	"TraceLine.At":                   "agent, every line",
	"TraceMarker.At":                 "agent, every marker",
	"TraceSession.ExpiresAt":         "set when the session opens",
	"TraceSession.StartedAt":         "set when the session opens",
	"wire.FetchedAt":                 "SubscriptionSnapshot's encoding",
	"wire.LastAttemptAt":             "SubscriptionSnapshot's encoding, see below",
}

// unclearTimes keep their tag on purpose and are listed so the guard below
// does not read them as a regression.
var unclearTimes = map[string]string{
	"SubscriptionSnapshot.LastAttemptAt": "plugin-written durable record with a strict decoder; its bytes belong to the sub-store goldens",
}

func TestEveryOptionalTimeIsOmitzero(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				sel, ok := field.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Time" || len(field.Names) == 0 {
					continue
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "time" {
					continue
				}
				tag := ""
				if field.Tag != nil {
					tag, _ = strconv.Unquote(field.Tag.Value)
				}
				opts := strings.Split(reflect.StructTag(tag).Get("json"), ",")
				for _, name := range field.Names {
					member := spec.Name.Name + "." + name.Name
					seen[member] = true
					switch {
					case opts[0] == "-" || opts[0] == "" && tag == "":
						// Not on the wire under a JSON name of its own.
					case strings.Contains(","+strings.Join(opts[1:], ",")+",", ",omitzero,"):
					case unclearTimes[member] != "":
					case len(opts) == 1 && (opts[0] == "created_at" || opts[0] == "updated_at"):
					case len(opts) == 1 && alwaysSetTimes[member] != "":
					default:
						t.Errorf("%s (%s, json %q): an unset time ships as year 1; tag it omitzero, or list it in alwaysSetTimes if every writer sets it",
							member, fset.Position(field.Pos()), strings.Join(opts, ","))
					}
				}
			}
			return true
		})
	}
	for member := range alwaysSetTimes {
		if !seen[member] {
			t.Errorf("alwaysSetTimes names %s, which is not a time.Time member of this package", member)
		}
	}
	for member := range unclearTimes {
		if !seen[member] {
			t.Errorf("unclearTimes names %s, which is not a time.Time member of this package", member)
		}
	}
}

// A never-reported node and an unfinished task are the two shapes the
// console renders most; neither may carry year 1 anywhere, including the
// nested metrics, host facts and debug policy every node embeds.
func TestNeverReportedNodeAndUnfinishedTaskCarryNoYearOne(t *testing.T) {
	created := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	for name, value := range map[string]any{
		"node": Node{ID: "node_1", Name: "fresh", CreatedAt: created},
		"task": Task{ID: "task_1", Status: "pending", Targets: []string{"node_1"}, CreatedAt: created,
			TargetLeases: map[string]TaskLease{"node_1": {LeaseID: "lease_1"}}},
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(raw), "0001-01-01") {
			t.Errorf("%s carries year 1: %s", name, raw)
		}
	}
}

// A set time still travels and reads back exactly, and both an absent key and
// the 0001 string an older server sends decode to the zero time, so a reader
// built on these types needs no special case for either.
func TestOmittedTimesRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 17, 9, 30, 0, 123456789, time.UTC)
	raw, err := json.Marshal(Task{ID: "task_1", StartedAt: at, FinishedAt: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var back Task
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.StartedAt.Equal(at) || !back.FinishedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("round trip = %v / %v, want %v / %v", back.StartedAt, back.FinishedAt, at, at.Add(time.Minute))
	}
	for _, body := range []string{
		`{"id":"node_1"}`,
		`{"id":"node_1","last_seen":"0001-01-01T00:00:00Z","metrics":{"collected_at":"0001-01-01T00:00:00Z"}}`,
	} {
		var node Node
		if err := json.Unmarshal([]byte(body), &node); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if !node.LastSeen.IsZero() || !node.Metrics.CollectedAt.IsZero() {
			t.Fatalf("%s: last_seen %v, collected_at %v, want zero", body, node.LastSeen, node.Metrics.CollectedAt)
		}
	}
}
