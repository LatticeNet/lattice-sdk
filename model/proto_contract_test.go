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
	approvalView := messageBody(t, string(controlPlane), "ApprovalView")
	for _, field := range []string{
		"string reason = 12;",
		"bool stale = 13;",
		"string stale_code = 14;",
	} {
		if !strings.Contains(approvalView, field) {
			t.Fatalf("ApprovalView missing field %s", field)
		}
	}
	leasedTask := messageBody(t, string(agentProto), "LeasedTask")
	for _, forbidden := range []string{"actor_id", "token_id", "target_node_ids", "profile", "script_sha256"} {
		if strings.Contains(leasedTask, forbidden) {
			t.Fatalf("LeasedTask exposes forbidden control-plane field %q", forbidden)
		}
	}
	for _, msg := range []string{
		"message NodeView",
		"message AgentDebugPolicy",
		"message NodeIPConfigView",
		"message MachineView",
		"message NFTInputsView",
		"message DNSDeploymentView",
		"message NetPolicyView",
		"message NetPolicyGraph",
		"message ProxyInboundView",
		"message ProxyUserView",
		"message ProxyNodeProfileView",
		"message ProxyUsageSnapshot",
		"message NodeGeo",
		"message NodeInventory",
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
	metrics := messageBody(t, string(common), "Metrics")
	for _, field := range []string{
		"double load5 = 11;",
		"double load15 = 12;",
		"double net_rx_speed = 13;",
		"double net_tx_speed = 14;",
	} {
		if !strings.Contains(metrics, field) {
			t.Fatalf("Metrics missing field %s", field)
		}
	}
	nodeView := messageBody(t, string(common), "NodeView")
	for _, field := range []string{
		"string comment = 18;",
		"string internal_ip = 19;",
		"string internal_ipv6 = 20;",
		"bool disabled = 21;",
		"AgentDebugPolicy agent_debug = 22;",
		"NodeIPConfigView ip_config = 23;",
		"repeated string group_ids = 24;",
		"TimePoint token_last_used_at = 25;",
		"repeated string agent_source_allowlist = 26;",
		"string lattice_identity_uuid = 27;",
		"NodeInventory inventory = 28;",
	} {
		if !strings.Contains(nodeView, field) {
			t.Fatalf("NodeView missing field %s", field)
		}
	}
	nodeIPConfigView := messageBody(t, string(common), "NodeIPConfigView")
	if strings.Contains(nodeIPConfigView, " script =") {
		t.Fatal("NodeIPConfigView exposes forbidden script body")
	}
	for _, field := range []string{
		"string mode = 1;",
		"string static_ipv4 = 2;",
		"string static_ipv6 = 3;",
		"repeated string resolvers = 4;",
		"string script_sha256 = 5;",
		"TimePoint updated_at = 6;",
	} {
		if !strings.Contains(nodeIPConfigView, field) {
			t.Fatalf("NodeIPConfigView missing field %s", field)
		}
	}
	apiError := messageBody(t, string(common), "ApiError")
	for _, field := range []string{"string code = 1;", "string message = 2;", "string request_id = 3;"} {
		if !strings.Contains(apiError, field) {
			t.Fatalf("ApiError missing field %s", field)
		}
	}
	netEndpoint := messageBody(t, string(common), "NetEndpoint")
	for _, field := range []string{"string kind = 1;", "string node_id = 2;", "string cidr = 3;", "string domain = 4;", "string zone_id = 5;"} {
		if !strings.Contains(netEndpoint, field) {
			t.Fatalf("NetEndpoint missing field %s", field)
		}
	}
	guardPortRange := messageBody(t, string(common), "GuardPortRange")
	for _, field := range []string{"uint32 from = 1;", "uint32 to = 2;"} {
		if !strings.Contains(guardPortRange, field) {
			t.Fatalf("GuardPortRange missing field %s", field)
		}
	}
	guardZone := messageBody(t, string(common), "GuardZone")
	for _, field := range []string{
		"string id = 1;",
		"string name = 2;",
		"bool builtin = 3;",
		"repeated string interfaces = 4;",
		"repeated string cidrs = 5;",
		"TimePoint updated_at = 8;",
	} {
		if !strings.Contains(guardZone, field) {
			t.Fatalf("GuardZone missing field %s", field)
		}
	}
	guardRule := messageBody(t, string(common), "GuardRule")
	if strings.Contains(guardRule, "rate_limit") {
		t.Fatal("GuardRule must not freeze rate_limit before the structured contract is designed")
	}
	for _, field := range []string{
		"string action = 3;",
		"string direction = 4;",
		"string protocol = 5;",
		"repeated GuardPortRange ports = 6;",
		"NetEndpoint remote = 7;",
		"bool log = 8;",
		"bool disabled = 9;",
	} {
		if !strings.Contains(guardRule, field) {
			t.Fatalf("GuardRule missing field %s", field)
		}
	}
	securityGroup := messageBody(t, string(common), "SecurityGroup")
	for _, field := range []string{
		"repeated GuardRule rules = 4;",
		"int64 version = 5;",
		"TimePoint updated_at = 7;",
	} {
		if !strings.Contains(securityGroup, field) {
			t.Fatalf("SecurityGroup missing field %s", field)
		}
	}
	nodeGuardBinding := messageBody(t, string(common), "NodeGuardBinding")
	for _, field := range []string{
		"repeated string group_ids = 2;",
		"repeated GuardRule overrides = 3;",
		"repeated string zone_ids = 4;",
		"bool managed = 5;",
		"string applied_table_sha = 10;",
	} {
		if !strings.Contains(nodeGuardBinding, field) {
			t.Fatalf("NodeGuardBinding missing field %s", field)
		}
	}
	guardReality := messageBody(t, string(common), "GuardNodeReality")
	for _, field := range []string{
		"repeated GuardListener listeners = 2;",
		"repeated GuardInterface interfaces = 3;",
		"string managed_sha = 4;",
		"repeated string foreign_tables = 5;",
		"TimePoint collected_at = 7;",
	} {
		if !strings.Contains(guardReality, field) {
			t.Fatalf("GuardNodeReality missing field %s", field)
		}
	}
	wgNetwork := messageBody(t, string(common), "WGNetwork")
	for _, field := range []string{
		"string cidr = 3;",
		"string topology = 4;",
		"uint32 listen_port = 5;",
		"repeated string dns = 8;",
		"int64 version = 10;",
	} {
		if !strings.Contains(wgNetwork, field) {
			t.Fatalf("WGNetwork missing field %s", field)
		}
	}
	wgMembership := messageBody(t, string(common), "WGMembership")
	for _, field := range []string{
		"string network_id = 1;",
		"string node_id = 2;",
		"string interface_name = 5;",
		"string endpoint = 7;",
		"repeated string extra_allowed_ips = 10;",
	} {
		if !strings.Contains(wgMembership, field) {
			t.Fatalf("WGMembership missing field %s", field)
		}
	}
	wgExternalPeer := messageBody(t, string(common), "WGExternalPeer")
	for _, field := range []string{
		"string public_key = 5;",
		"repeated string allowed_ips = 6;",
		"TimePoint last_issued_at = 7;",
	} {
		if !strings.Contains(wgExternalPeer, field) {
			t.Fatalf("WGExternalPeer missing field %s", field)
		}
	}
	dnsDeployment := messageBody(t, string(common), "DNSDeploymentView")
	for _, forbidden := range []string{"cf_api_token"} {
		if strings.Contains(dnsDeployment, forbidden) {
			t.Fatalf("DNSDeploymentView exposes forbidden secret field %q", forbidden)
		}
	}
	for _, field := range []string{
		"string node_id = 3;",
		"repeated DNSZone zones = 10;",
		"bool has_credential = 16;",
		"string status = 17;",
		"TimePoint created_at = 24;",
		"TimePoint updated_at = 25;",
		"TimePoint last_published_at = 26;",
		"string last_publish_error = 27;",
	} {
		if !strings.Contains(dnsDeployment, field) {
			t.Fatalf("DNSDeploymentView missing field %s", field)
		}
	}
	proxyInbound := messageBody(t, string(common), "ProxyInboundView")
	for _, forbidden := range []string{" string reality_private_key "} {
		if strings.Contains(proxyInbound, forbidden) {
			t.Fatalf("ProxyInboundView exposes forbidden secret field %q", forbidden)
		}
	}
	for _, field := range []string{
		"string core = 3;",
		"string protocol = 4;",
		"uint32 port = 6;",
		"string security = 10;",
		"bool has_reality_private_key = 16;",
		"string reality_public_key = 17;",
		"bool enabled = 21;",
	} {
		if !strings.Contains(proxyInbound, field) {
			t.Fatalf("ProxyInboundView missing field %s", field)
		}
	}
	proxyUser := messageBody(t, string(common), "ProxyUserView")
	for _, forbidden := range []string{" string uuid ", " string password ", " string sub_token "} {
		if strings.Contains(proxyUser, forbidden) {
			t.Fatalf("ProxyUserView exposes forbidden secret field %q", forbidden)
		}
	}
	for _, field := range []string{
		"bool has_uuid = 4;",
		"bool has_password = 5;",
		"bool has_sub_token = 6;",
		"repeated string inbound_ids = 7;",
		"int64 traffic_limit_bytes = 8;",
		"string status = 12;",
	} {
		if !strings.Contains(proxyUser, field) {
			t.Fatalf("ProxyUserView missing field %s", field)
		}
	}
	proxyProfile := messageBody(t, string(common), "ProxyNodeProfileView")
	for _, field := range []string{
		"string node_id = 2;",
		"string node_name = 3;",
		"repeated string inbound_ids = 5;",
		"string applied_sha256 = 10;",
	} {
		if !strings.Contains(proxyProfile, field) {
			t.Fatalf("ProxyNodeProfileView missing field %s", field)
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
