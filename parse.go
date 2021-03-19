package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
)

func parseRawToRare(raw *RawRule, informerFactory informers.SharedInformerFactory) (*RareRule, error) {
	if raw == nil {
		return nil, nil
	}

	var (
		err  error
		rare = RareRule{
			AlertName:       raw.AlertName,
			RuleName:        raw.RuleName,
			MetricName:      raw.MetricName,
			CompareOperator: raw.ConditionType,
			Language:        raw.Language,
		}
	)

	rare.PeriodInMinute, err = strconv.ParseFloat(raw.MonitorPeriods, 64)
	if err != nil {
		return nil, ruleError{errors.Errorf("invalid monitor period: %s", raw.MonitorPeriods)}
	}

	switch strings.ToLower(raw.Severity) {
	case "critical":
		rare.Severity = "critical"
	case "major":
		rare.Severity = "error"
	default:
		rare.Severity = "warning"
	}

	var thresholds float64
	thresholds, err = strconv.ParseFloat(raw.Thresholds, 64)
	if err != nil {
		return nil, ruleError{errors.Wrapf(err, "invalid thresholds: %v", raw.Thresholds)}
	}
	scale, _ := strconv.ParseFloat(raw.MetricScale, 64)
	if scale == 0 {
		rare.Threshold = thresholds
	} else {
		rare.Threshold = thresholds / scale
	}
	rare.ThresholdFmt = "%v"
	rare.ThresholdUI = thresholds
	rare.UnitUI = raw.Unit

	var resourceFilter resourceFilterParam
	if raw.ResourceFilterParam != "" {
		if err = json.Unmarshal([]byte(raw.ResourceFilterParam), &resourceFilter); err != nil {
			return nil, ruleError{errors.Wrapf(err, "parsing resource filter param failed")}
		}
	}

	var resourceSelector = make(map[string]string)
	if resourceFilter.Selector != "" {
		var sel []map[string]string
		if err = json.Unmarshal([]byte(resourceFilter.Selector), &sel); err != nil {
			return nil, ruleError{errors.Wrapf(err, "parsing resourceSelector param failed")}
		}
		for _, m := range sel {
			for k, v := range m {
				resourceSelector[k] = v
			}
		}
	}

exit:
	switch strings.ToLower(raw.ResourceTypeName) {
	case "node":
		rare.ResourceKind = "node"
		rare.ResourceNames = resourceFilter.NodeId
		if len(resourceSelector) > 0 {
			var list []*corev1.Node
			list, err = informerFactory.Core().V1().Nodes().Lister().List(labels.SelectorFromSet(resourceSelector))
			if err != nil {
				return nil, err
			}
			var names = make([]string, 0, len(list)+1)
			if rare.ResourceNames != "" {
				names = append(names, rare.ResourceNames)
			}
			for _, elem := range list {
				names = append(names, elem.Name)
			}
			if len(names) > 0 {
				rare.ResourceNames = strings.Join(names, "|")
			}
		}

		if rare.ResourceNames == "" {
			return nil, ruleError{errors.New("no resources are selected")}
		}
		var q string
		var ok bool
		if t, exist := promQLTemplatesV2[raw.MetricName]; exist {
			rare.Templated = true
			q, ok = t.Template, true
			rare.ThresholdFmt = t.ThresholdFmt
		} else {
			q, ok = promQLTemplates[raw.MetricName]
		}
		if !ok {
			return nil, ruleError{errors.Errorf("not supported to metric: %s", raw.MetricName)}
		}
		rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`node=~"%s"`, rare.ResourceNames))
	case "workload":
		if resourceFilter.NsName == "" || resourceFilter.WorkloadKind == "" {
			return nil, ruleError{errors.New("resource filter param is invalid")}
		}
		rare.Namespace = resourceFilter.NsName
		rare.ResourceKind, rare.ResourceNames = resourceFilter.WorkloadKind, resourceFilter.WorkloadName
		if len(resourceSelector) > 0 {
			var names []string
			switch resourceFilter.WorkloadKind {
			case "deployment":
				list, err := informerFactory.Apps().V1().Deployments().Lister().
					Deployments(resourceFilter.NsName).List(labels.SelectorFromSet(resourceSelector))
				if err != nil {
					return nil, err
				}
				for _, elem := range list {
					names = append(names, elem.Name)
				}
			case "statefulset":
				list, err := informerFactory.Apps().V1().StatefulSets().Lister().
					StatefulSets(resourceFilter.NsName).List(labels.SelectorFromSet(resourceSelector))
				if err != nil {
					return nil, err
				}
				for _, elm := range list {
					names = append(names, elm.Name)
				}
			case "daemonset":
				list, err := informerFactory.Apps().V1().DaemonSets().Lister().
					DaemonSets(resourceFilter.NsName).List(labels.SelectorFromSet(resourceSelector))
				if err != nil {
					return nil, err
				}
				for _, elm := range list {
					names = append(names, elm.Name)
				}
			}
			if len(names) > 0 {
				if rare.ResourceNames == "" {
					rare.ResourceNames = strings.Join(names, "|")
				} else {
					rare.ResourceNames += "|" + strings.Join(names, "|")
				}
			}
		}
		if rare.ResourceNames == "" {
			return nil, ruleError{errors.New("no resources are selected")}
		}
		if qn, ok := promQLTemplatesV2[raw.MetricName]; ok {
			switch resourceFilter.WorkloadKind {
			case "deployment", "statefulset", "daemonset":
				rare.Templated = true
				rare.ThresholdFmt = qn.ThresholdFmt
				rare.MetricExpr = strings.NewReplacer("$1",
					fmt.Sprintf(`workload=~"%s:(%s)"`, strings.Title(rare.ResourceKind), rare.ResourceNames),
					"$2", rare.ResourceKind).Replace(qn.Template)
				break exit
			}
		}
		q, ok := promQLTemplates[raw.MetricName]
		if !ok {
			return nil, ruleError{errors.Errorf("not supported to metric: %s", raw.MetricName)}
		}
		rare.MetricExpr = strings.NewReplacer("$1",
			fmt.Sprintf(`workload=~"%s:(%s)"`, strings.Title(rare.ResourceKind), rare.ResourceNames),
			"$2", fmt.Sprintf(`%s=~"%s"`, rare.ResourceKind, rare.ResourceNames)).Replace(q)
	default:
		q, ok := promQLTemplates[raw.MetricName]
		if !ok {
			return nil, ruleError{errors.Errorf("not supported to metric: %s", raw.MetricName)}
		}
		switch resourceFilter.WorkloadKind {
		case "container":
			switch {
			case resourceFilter.NsName != "" && resourceFilter.PodName != "":
				rare.Namespace = resourceFilter.NsName
				rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`pod=~"%s",container=~"%s"`,
					resourceFilter.PodName, resourceFilter.ContainerName))
			case resourceFilter.NodeId != "" && resourceFilter.PodName != "":
				rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`node="%s",pod="%s",container=~"%s"`,
					resourceFilter.NodeId, resourceFilter.PodName, resourceFilter.ContainerName))
			default:
				return nil, ruleError{errors.New("resource filter param is invalid")}
			}
		case "pod":
			switch {
			case resourceFilter.NsName != "":
				rare.Namespace = resourceFilter.NsName
				rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`pod=~"%s"`, resourceFilter.PodName))
			case resourceFilter.NodeId != "":
				rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`node="%s",pod=~"%s"`,
					resourceFilter.NodeId, resourceFilter.PodName))
			default:
				return nil, ruleError{errors.New("resource filter param is invalid")}
			}
		case "workspace":
			if resourceFilter.WorkspaceName == "" {
				return nil, ruleError{errors.New("resource filter param is invalid")}
			}
			rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`workspace=~"%s"`, resourceFilter.WorkspaceName))
		case "namespace":
			if resourceFilter.NsName == "" {
				return nil, ruleError{errors.New("resource filter param is invalid")}
			}
			rare.MetricExpr = strings.ReplaceAll(q, "$1", fmt.Sprintf(`namespace=~"%s"`, resourceFilter.NsName))
		default:
			rare.MetricExpr = strings.NewReplacer("$1", "", "$2", "").Replace(q)
		}
	}

	return &rare, nil
}

func parseRareToRipe(rare *RareRule, nameFunc func(*RareRule) string) (*RipeRule, error) {
	if rare == nil {
		return nil, nil
	}
	var ripe = RipeRule{
		Name:     nameFunc(rare),
		Query:    fmt.Sprintf("%s %s %s", rare.MetricExpr, rare.CompareOperator, fmt.Sprintf(rare.ThresholdFmt, rare.Threshold)),
		Duration: fmt.Sprintf("%.0fm", rare.PeriodInMinute),
		Labels: map[string]string{
			"severity": rare.Severity,
		},
	}

	if rare.Templated {
		var kind = strings.Title(rare.ResourceKind)
		ripe.Annotations = map[string]string{"kind": kind}

		bs, err := json.Marshal(strings.Split(rare.ResourceNames, "|"))
		if err != nil {
			return nil, err
		}
		ripe.Annotations["resources"] = string(bs)

		ruleInfo := []map[string]string{{
			"_metricType":    promQLTemplatesV2[rare.MetricName].Template,
			"condition_type": rare.CompareOperator,
			"thresholds":     fmt.Sprintf("%v", rare.ThresholdUI),
			"unit":           rare.UnitUI,
		}}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		err = enc.Encode(ruleInfo)
		if err != nil {
			return nil, err
		}
		ripe.Annotations["rules"] = buf.String()

		var metricName = rare.MetricName
		if rare.Language == "zh" {
			if k, ok := kindLocaleV2[kind]; ok {
				kind = k
			}
			if p, ok := promQLTemplatesV2[metricName]; ok {
				metricName = p.Cn
			}
		} else {
			if p, ok := promQLTemplatesV2[metricName]; ok {
				metricName = p.En
			}
		}
		ripe.Annotations["summary"] = fmt.Sprintf("%s %s %s %s %v%s",
			kind, rare.ResourceNames, metricName, rare.CompareOperator, rare.ThresholdUI, rare.UnitUI)
	}

	return &ripe, nil
}
