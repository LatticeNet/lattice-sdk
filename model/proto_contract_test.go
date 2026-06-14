package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtoContractsExistAndStayRedacted(t *testing.T) {
	root := filepath.Join("..", "proto", "lattice", "v1")
	required := []string{"common.proto", "control_plane.proto", "agent.proto", "plugin.proto"}
	for _, name := range required {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing proto contract %s: %v", name, err)
		}
		text := string(data)
		for _, needle := range []string{
			`syntax = "proto3";`,
			"package lattice.v1;",
			`option go_package = "github.com/LatticeNet/lattice-sdk/gen/lattice/v1;latticev1";`,
		} {
			if !strings.Contains(text, needle) {
				t.Fatalf("%s missing %q", name, needle)
			}
		}
		for _, forbidden := range []string{"token_hash", "password_hash", "cf_api_token", "webhook_headers", "console_url", "detail_url"} {
			if strings.Contains(text, " "+forbidden+" =") {
				t.Fatalf("%s exposes forbidden secret field %q", name, forbidden)
			}
		}
	}
	joined := readAllProto(t, root)
	controlPlane, err := os.ReadFile(filepath.Join(root, "control_plane.proto"))
	if err != nil {
		t.Fatal(err)
	}
	taskView := messageBody(t, string(controlPlane), "TaskView")
	for _, forbidden := range []string{" string script ", "script_preview"} {
		if strings.Contains(taskView, forbidden) {
			t.Fatalf("TaskView exposes forbidden task script field %q", forbidden)
		}
	}
	taskResultView := messageBody(t, string(controlPlane), "TaskResultView")
	if strings.Contains(taskResultView, "lease_id") {
		t.Fatal("TaskResultView exposes forbidden lease_id field")
	}
	listAuditRequest := messageBody(t, string(controlPlane), "ListAuditRequest")
	for _, field := range []string{
		"string node_id = 1;",
		"string actor_id = 2;",
		"PageRequest page = 3;",
		"string action = 4;",
		"string decision = 5;",
		"string scope = 6;",
		"string correlation_id = 7;",
		"string token_id = 8;",
	} {
		if !strings.Contains(listAuditRequest, field) {
			t.Fatalf("ListAuditRequest missing field %s", field)
		}
	}
	agentProto, err := os.ReadFile(filepath.Join(root, "agent.proto"))
	if err != nil {
		t.Fatal(err)
	}
	leasedTask := messageBody(t, string(agentProto), "LeasedTask")
	for _, forbidden := range []string{"actor_id", "token_id", "target_node_ids", "profile", "script_sha256"} {
		if strings.Contains(leasedTask, forbidden) {
			t.Fatalf("LeasedTask exposes forbidden control-plane field %q", forbidden)
		}
	}
	for _, msg := range []string{
		"message NodeView",
		"message MachineView",
		"message NFTInputsView",
		"message NetPolicyView",
		"message NetPolicyGraph",
		"message NodeGeo",
		"message AgentEnvelope",
		"message PluginManifest",
		"enum CapabilityRisk",
		"message ApiError",
	} {
		if !strings.Contains(joined, msg) {
			t.Fatalf("proto contracts missing %s", msg)
		}
	}
	pluginProto, err := os.ReadFile(filepath.Join(root, "plugin.proto"))
	if err != nil {
		t.Fatal(err)
	}
	pluginManifest := messageBody(t, string(pluginProto), "PluginManifest")
	for _, field := range []string{
		"string publisher = 7;",
		"string digest_sha256 = 8;",
		"string signature_ed25519 = 9;",
	} {
		if !strings.Contains(pluginManifest, field) {
			t.Fatalf("PluginManifest missing field %s", field)
		}
	}
	common, err := os.ReadFile(filepath.Join(root, "common.proto"))
	if err != nil {
		t.Fatal(err)
	}
	apiError := messageBody(t, string(common), "ApiError")
	for _, field := range []string{"string code = 1;", "string message = 2;", "string request_id = 3;"} {
		if !strings.Contains(apiError, field) {
			t.Fatalf("ApiError missing field %s", field)
		}
	}
	netEndpoint := messageBody(t, string(common), "NetEndpoint")
	for _, field := range []string{"string kind = 1;", "string node_id = 2;", "string cidr = 3;", "string domain = 4;"} {
		if !strings.Contains(netEndpoint, field) {
			t.Fatalf("NetEndpoint missing field %s", field)
		}
	}
}

func readAllProto(t *testing.T, root string) string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".proto" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

func messageBody(t *testing.T, protoText, name string) string {
	t.Helper()
	start := strings.Index(protoText, "message "+name+" {")
	if start < 0 {
		t.Fatalf("missing message %s", name)
	}
	open := strings.Index(protoText[start:], "{")
	if open < 0 {
		t.Fatalf("malformed message %s", name)
	}
	pos := start + open + 1
	depth := 1
	for i := pos; i < len(protoText); i++ {
		switch protoText[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return protoText[pos:i]
			}
		}
	}
	t.Fatalf("unterminated message %s", name)
	return ""
}
