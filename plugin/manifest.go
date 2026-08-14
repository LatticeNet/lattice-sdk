package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	TypeSystem = "system"
	TypeWasm   = "wasm"
	TypeWorker = "worker"

	ManifestSchemaV2           = "lattice.plugin.manifest.v2"
	BundleFormatTarGzip        = "tar+gzip"
	RuntimeProtocolStdioJSONV1 = "stdio-json-v1"
	RuntimeProtocolStdioJSONV2 = "stdio-json-v2"
	UIRuntimeModeSandbox       = "sandbox"
	UIBridgeVersion1           = "1"

	InterfaceEffectRead  = "read"
	InterfaceEffectWrite = "write"
	InterfaceEffectPlan  = "plan"

	BackingRuntime = "runtime"
	BackingCore    = "core"
)

const (
	CapabilityAuditRead          = "audit:read"
	CapabilityHTTPEgress         = "http:egress"
	CapabilityHTTPOperatorTarget = "http:operator-target"
	CapabilityKVRead             = "kv:read"
	CapabilityKVWrite            = "kv:write"
	CapabilityLogWrite           = "log:write"
	CapabilityMonitorRead        = "monitor:read"
	CapabilityMonitorAdmin       = "monitor:admin"
	CapabilityNetguardRead       = "netguard:read"
	CapabilityNetguardAdmin      = "netguard:admin"
	CapabilityNetpolicyRead      = "netpolicy:read"
	CapabilityNetpolicyAdmin     = "netpolicy:admin"
	CapabilityNetworkApply       = "network:apply"
	CapabilityNetworkPlan        = "network:plan"
	CapabilityNodeRead           = "node:read"
	CapabilityNodeAdmin          = "node:admin"
	CapabilityNotifySend         = "notify:send"
	CapabilityRPCCall            = "rpc:call"
	CapabilityRPCExpose          = "rpc:expose"
	CapabilitySecretRead         = "secret:read"
	CapabilitySecretWrite        = "secret:write"
	CapabilityStaticRead         = "static:read"
	CapabilityStaticWrite        = "static:write"
	CapabilityTaskRead           = "task:read"
	CapabilityTaskRun            = "task:run"
	CapabilityTunnelAdmin        = "tunnel:admin"
	CapabilityWorkerRoute        = "worker:route"
	CapabilityDDNSAdmin          = "ddns:admin"
)

type Manifest struct {
	Schema           string              `json:"schema,omitempty"`
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	Type             string              `json:"type"`
	Capabilities     []string            `json:"capabilities"`
	Version          string              `json:"version,omitempty"`
	Entrypoint       string              `json:"entrypoint,omitempty"`
	Publisher        string              `json:"publisher,omitempty"`
	DigestSHA256     string              `json:"digest_sha256,omitempty"`
	SignatureEd25519 string              `json:"signature_ed25519,omitempty"`
	Bundle           *BundleSpec         `json:"bundle,omitempty"`
	Runtime          *RuntimeSpec        `json:"runtime,omitempty"`
	UIRuntime        *UIRuntimeSpec      `json:"ui_runtime,omitempty"`
	Compatibility    *CompatibilitySpec  `json:"compatibility,omitempty"`
	MinServer        string              `json:"min_server,omitempty"`
	HostAccess       *HostAccessSpec     `json:"host_access,omitempty"`
	UI               *ManifestUI         `json:"ui,omitempty"`
	Interfaces       []InterfaceContract `json:"interfaces,omitempty"`
}

func DecodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if err := decodeStrict(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	return manifest, nil
}

type BundleSpec struct {
	Format       string `json:"format"`
	DigestSHA256 string `json:"digest_sha256"`
}

type RuntimeSpec struct {
	Protocol    string            `json:"protocol"`
	Entrypoints map[string]string `json:"entrypoints"`
}

type UIRuntimeSpec struct {
	Mode          string `json:"mode"`
	Entrypoint    string `json:"entrypoint"`
	BridgeVersion string `json:"bridge_version"`
}

type CompatibilitySpec struct {
	Server          string `json:"server"`
	DashboardHost   string `json:"dashboard_host"`
	RuntimeProtocol string `json:"runtime_protocol"`
}

type HostAccessSpec struct {
	RPC []RPCDependency `json:"rpc,omitempty"`
}

type RPCDependency struct {
	Service string   `json:"service"`
	Methods []string `json:"methods"`
}

type NavContribution struct {
	Section      string   `json:"section"`
	SectionTitle string   `json:"section_title,omitempty"`
	Title        string   `json:"title"`
	Route        string   `json:"route"`
	Icon         string   `json:"icon,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type ViewSource struct {
	Interface string `json:"interface"`
	Method    string `json:"method"`
}

type ViewColumn struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Render string `json:"render,omitempty"`
}

type ViewFormField struct {
	Key     string   `json:"key"`
	Label   string   `json:"label,omitempty"`
	Kind    string   `json:"kind"`
	Options []string `json:"options,omitempty"`
}

type ViewAction struct {
	Label     string          `json:"label"`
	Interface string          `json:"interface"`
	Method    string          `json:"method"`
	Form      []ViewFormField `json:"form,omitempty"`
	Scopes    []string        `json:"scopes,omitempty"`
}

type ViewContribution struct {
	Route   string       `json:"route"`
	Title   string       `json:"title"`
	Kind    string       `json:"kind"`
	Source  *ViewSource  `json:"source,omitempty"`
	Columns []ViewColumn `json:"columns,omitempty"`
	Actions []ViewAction `json:"actions,omitempty"`
}

type ManifestUI struct {
	Nav   []NavContribution  `json:"nav,omitempty"`
	Views []ViewContribution `json:"views,omitempty"`
}

type InterfaceMethod struct {
	Name                 string            `json:"name"`
	Effect               string            `json:"effect"`
	Scopes               []string          `json:"scopes,omitempty"`
	OperatorTargetFields []string          `json:"operator_target_fields,omitempty"`
	Budget               *InvokeBudgetSpec `json:"budget,omitempty"`
}

type InterfaceContract struct {
	Service      string            `json:"service"`
	Methods      []string          `json:"-"`
	MethodSpecs  []InterfaceMethod `json:"-"`
	Scopes       []string          `json:"scopes,omitempty"`
	Backing      string            `json:"backing,omitempty"`
	typedMethods bool
}

func (m Manifest) InterfaceFor(service string) (InterfaceContract, bool) {
	for _, contract := range m.Interfaces {
		if contract.Service == service {
			return contract, true
		}
	}
	return InterfaceContract{}, false
}

func (c InterfaceContract) EffectiveBacking() string {
	if c.Backing == "" {
		return BackingRuntime
	}
	return c.Backing
}

func (c InterfaceContract) MarshalJSON() ([]byte, error) {
	type stringMethods struct {
		Service string   `json:"service"`
		Methods []string `json:"methods"`
		Scopes  []string `json:"scopes,omitempty"`
		Backing string   `json:"backing,omitempty"`
	}
	type typedMethods struct {
		Service string            `json:"service"`
		Methods []InterfaceMethod `json:"methods"`
		Scopes  []string          `json:"scopes,omitempty"`
		Backing string            `json:"backing,omitempty"`
	}
	if c.typedMethods || len(c.MethodSpecs) > 0 {
		return json.Marshal(typedMethods{Service: c.Service, Methods: c.MethodSpecs, Scopes: c.Scopes, Backing: c.Backing})
	}
	return json.Marshal(stringMethods{Service: c.Service, Methods: c.Methods, Scopes: c.Scopes, Backing: c.Backing})
}

func (c *InterfaceContract) UnmarshalJSON(data []byte) error {
	var raw struct {
		Service string          `json:"service"`
		Methods json.RawMessage `json:"methods"`
		Scopes  []string        `json:"scopes,omitempty"`
		Backing string          `json:"backing,omitempty"`
	}
	if err := decodeStrict(data, &raw); err != nil {
		return err
	}
	*c = InterfaceContract{Service: raw.Service, Scopes: raw.Scopes, Backing: raw.Backing}
	if len(raw.Methods) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Methods, &c.Methods); err == nil {
		return nil
	}
	methodDec := json.NewDecoder(bytes.NewReader(raw.Methods))
	methodDec.DisallowUnknownFields()
	if err := methodDec.Decode(&c.MethodSpecs); err != nil {
		return fmt.Errorf("interface methods must be all strings or all typed objects: %w", err)
	}
	if err := ensureNoTrailingJSON(methodDec); err != nil {
		return fmt.Errorf("interface methods: %w", err)
	}
	c.typedMethods = true
	c.Methods = make([]string, len(c.MethodSpecs))
	for i, method := range c.MethodSpecs {
		c.Methods[i] = method.Name
	}
	return nil
}

func (c InterfaceContract) TypedMethods() bool {
	return c.typedMethods || len(c.MethodSpecs) > 0
}

func (c InterfaceContract) MethodContracts() []InterfaceMethod {
	methods := c.effectiveMethods()
	out := make([]InterfaceMethod, len(methods))
	for i, method := range methods {
		out[i] = method
		out[i].Scopes = append([]string(nil), method.Scopes...)
		out[i].OperatorTargetFields = append([]string(nil), method.OperatorTargetFields...)
	}
	return out
}

func (c InterfaceContract) MethodContract(name string) (InterfaceMethod, bool) {
	for _, method := range c.MethodContracts() {
		if method.Name == name {
			return method, true
		}
	}
	return InterfaceMethod{}, false
}

func (c InterfaceContract) EffectiveMethodScopes(name string) ([]string, bool) {
	method, ok := c.MethodContract(name)
	if !ok {
		return nil, false
	}
	if len(method.Scopes) > 0 {
		return append([]string(nil), method.Scopes...), true
	}
	return append([]string(nil), c.Scopes...), true
}

func (c InterfaceContract) effectiveMethods() []InterfaceMethod {
	if c.typedMethods || len(c.MethodSpecs) > 0 {
		return c.MethodSpecs
	}
	out := make([]InterfaceMethod, len(c.Methods))
	for i, name := range c.Methods {
		out[i] = InterfaceMethod{Name: name, Effect: InterfaceEffectRead, Scopes: c.Scopes}
	}
	return out
}
