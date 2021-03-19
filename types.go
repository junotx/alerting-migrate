package main

import (
	"fmt"
	"time"
)

//var nameReplacer = regexp.MustCompile("[^-a-z0-9]")

type RawRule struct {
	// from table rule
	RuleName         string
	RuleDisabled     *int
	Severity         string // critical
	ConditionType    string
	Thresholds       string
	Unit             string // core/%/GB
	MonitorPeriods   string
	ConsecutiveCount *int
	CreateTime       *time.Time
	UpdateTime       *time.Time

	// from table metric
	MetricName  string
	MetricScale string

	// from table policy
	PolicyConfig string
	Language     string

	// from table alert
	AlertName     string
	AlertDisabled *int

	// from table resource_filter
	ResourceFilterParam string `db:"rs_filter_param"`

	// from table resource_type
	ResourceTypeName  string `db:"rs_type_name"`
	ResourceTypeParam string `db:"rs_type_param"`
}

func (r *RawRule) String() string {
	return fmt.Sprintf(`rule{alert_name="%s",rule_name="%s",resource_type_name="%s",resource_filter_param="%s"}`,
		r.AlertName, r.RuleName, r.ResourceTypeName, r.ResourceFilterParam)
}

type resourceFilterParam struct {
	NsName        string `json:"ns_name,omitempty"`
	NodeId        string `json:"node_id,omitempty"`
	PodName       string `json:"pod_name,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	WorkloadKind  string `json:"workload_kind,omitempty"`
	WorkloadName  string `json:"workload_name,omitempty"`
	ComponentName string `json:"component_name,omitempty"`
	WorkspaceName string `json:"ws_name,omitempty"`
	Selector      string `json:"selector,omitempty"`
}

type RareRule struct {
	Templated bool

	Namespace  string
	AlertName  string
	RuleName   string
	MetricName string

	MetricExpr string

	ResourceKind  string
	ResourceNames string

	Severity       string
	PeriodInMinute float64

	CompareOperator string
	Threshold       float64
	ThresholdFmt    string
	Unit            string
	ThresholdUI     float64
	UnitUI          string

	Language string
}

type RipeRule struct {
	Name string `json:"name,omitempty" description:"rule name should be unique in one namespace for custom alerting rules"`

	Query       string            `json:"query,omitempty" description:"prometheus query expression, grammars of which may be referred to https://prometheus.io/docs/prometheus/latest/querying/basics/"`
	Duration    string            `json:"duration,omitempty" description:"duration an alert transitions from Pending to Firing state, which must match ^([0-9]+)(y|w|d|h|m|s|ms)$"`
	Labels      map[string]string `json:"labels,omitempty" description:"extra labels to attach to the resulting alert sample vectors (the key string has to match [a-zA-Z_][a-zA-Z0-9_]*). eg: a typical label called severity, whose value may be info, warning, error, critical, is usually used to indicate the severity of an alert"`
	Annotations map[string]string `json:"annotations,omitempty" description:"non-identifying key/value pairs. summary, message, description are the commonly used annotation names"`
}
