package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gocraft/dbr/v2"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

var gvrs = []schema.GroupVersionResource{
	{Group: "", Version: "v1", Resource: "namespaces"},
	{Group: "", Version: "v1", Resource: "nodes"},
	{Group: "apps", Version: "v1", Resource: "deployments"},
	{Group: "apps", Version: "v1", Resource: "daemonsets"},
	{Group: "apps", Version: "v1", Resource: "replicasets"},
	{Group: "apps", Version: "v1", Resource: "statefulsets"},
}

func buildRuleSelect(sess *dbr.Session) *dbr.SelectStmt {
	return sess.Select(
		"rule.rule_name", "rule.disabled as rule_disabled", "rule.severity", "rule.condition_type",
		"rule.thresholds", "rule.unit", "rule.monitor_periods", "rule.consecutive_count", "rule.create_time", "rule.update_time",
		"metric.metric_name", "metric.metric_param as metric_scale",
		"policy.language, policy.policy_config",
		"alert.alert_name", "alert.disabled as alert_disabled",
		"resource_filter.rs_filter_param",
		"resource_type.rs_type_name, resource_type.rs_type_param").
		From("rule").
		LeftJoin("metric", "rule.metric_id=metric.metric_id").
		LeftJoin("policy", "rule.policy_id=policy.policy_id").
		LeftJoin("alert", "policy.policy_id=alert.policy_id").
		LeftJoin("resource_filter", "alert.rs_filter_id=resource_filter.rs_filter_id").
		LeftJoin("resource_type", "policy.rs_type_id=resource_type.rs_type_id")
}

func main() {
	var config Config
	config.AddFlags()
	klog.InitFlags(nil)
	flag.Parse()

	k8sConfig, err := clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
	if err != nil {
		klog.Fatal(err)
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		klog.Fatal(err)
	}
	informerFactory := informers.NewSharedInformerFactory(k8sClient, time.Minute)
	for _, gvr := range gvrs {
		_, err := informerFactory.ForResource(gvr)
		if err != nil {
			klog.Fatal(err)
		}
	}
	stopCh := signalHandler()
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	// query rules from mysql
	mysqlConn, err := dbr.Open("mysql",
		fmt.Sprintf("%s@tcp(%s)/%s?parseTime=1&multiStatements=1&charset=utf8mb4&collation=utf8mb4_unicode_ci",
			config.Mysql.User, config.Mysql.Address, config.Mysql.Database), nil)
	if err != nil {
		klog.Fatal(err)
	}
	defer mysqlConn.Close()
	iterator, err := buildRuleSelect(mysqlConn.NewSession(nil)).IterateContext(context.Background())
	if err != nil {
		klog.Fatal(err)
	}

	// parse raw rules to rare rules which are semi-manufactures
	var (
		raw      RawRule
		rares    []*RareRule
		counters = make(map[string]int) // key is namespace/alertname
	)
	for iterator.Next() {
		err := iterator.Scan(&raw)
		if err != nil {
			klog.Fatal(err)
		}
		rare, err := parseRawToRare(&raw, informerFactory)
		if err != nil {
			switch err.(type) {
			case ruleError:
				klog.Errorf("rule error %s: %s\n", raw.String(), err)
				continue
			default:
				klog.Fatal(err)
			}
		}
		if rare == nil {
			continue
		}
		rares = append(rares, rare)
		counters[rare.Namespace+"/"+rare.AlertName]++
	}

	// parse upper semi-manufactures to ripe rules which can be sent to alerting v2 api
	var ripes = make(map[string][]*RipeRule) // key is namespace
	for i := range rares {
		rare := rares[i]
		ripe, err := parseRareToRipe(rare, func(rule *RareRule) string {
			k := rule.Namespace + "/" + rule.AlertName
			if c, ok := counters[k]; ok {
				if c > 1 {
					counters[k]--
					return fmt.Sprintf("%s-%d", rule.AlertName, c-1)
				}
			}
			return rule.AlertName
		})
		if err != nil {
			klog.Fatal(err)
		}
		ripes[rare.Namespace] = append(ripes[rare.Namespace], ripe)
	}

	// if dry run is required, print all rules directly
	if config.DryRun {
		bs, err := json.MarshalIndent(ripes, "", "\t")
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Println(string(bs))
		return
	}

	// get auth to ks-apiserver

	var auth string
	if config.Kubesphere.User != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Kubesphere.User))
	} else if config.Kubesphere.Token != "" {
		auth = "Bearer " + config.Kubesphere.Token
	} else {
		// get token in secret kubesphere-system/kubesphere-secret when no user or token configured
		var (
			tokenSecretNs   = "kubesphere-system"
			tokenSecretName = "kubesphere-secret"
			tokenSecretKey  = "token"
		)
		secret, err := k8sClient.CoreV1().Secrets(tokenSecretNs).
			Get(context.TODO(), tokenSecretName, metav1.GetOptions{})
		if err == nil {
			token := secret.Data[tokenSecretKey]
			if len(token) > 0 {
				auth = "Bearer " + string(token)
			}
		} else if resourceNotFound(err) {
			klog.Warning("kubesphere secret is not found, do not use auth")
		} else {
			klog.Fatal(err)
		}
	}

	// send all rules that can be sent

	const bulkSize = 100
	var endpoint = strings.TrimRight(config.Kubesphere.AlertingEndpoint, "/")
	var errs []error
	for ns := range ripes {
		rs := ripes[ns]
		var url string
		if ns == "" {
			url = fmt.Sprintf("%s/bulkrules", endpoint)
		} else {
			url = fmt.Sprintf("%s/namespaces/%s/bulkrules", endpoint, ns)
		}

		for i, l := 0, len(rs); i < l; {
			stop := i + bulkSize
			if stop > l {
				stop = l
			}
			sub := rs[i:stop]

			if err := send(sub, url, auth); err != nil {
				errs = append(errs, err)
				klog.Error(err)
			}

			i = stop
		}
	}

	if len(errs) > 0 {
		os.Exit(1)
	}
}

func send(ripes []*RipeRule, url, auth string) error {
	bs, err := json.Marshal(ripes)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bs))
	if err != nil {
		return err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		response := struct {
			Errors bool `json:"errors"`
			Items  []struct {
				RuleName  string `json:"ruleName"`
				Status    string `json:"status"`
				ErrorType string `json:"errorType"`
				Error     string `json:"error"`
			}
		}{}

		err = json.Unmarshal(body, &response)
		if err != nil {
			return err
		}

		if response.Errors {
			for j := range response.Items {
				item := response.Items[j]
				if item.Status == "error" {
					klog.Errorf("rule request error: name[%s], errorType[%s], error[%s]\n",
						item.RuleName, item.ErrorType, item.Error)
				}
			}
		}
		return nil
	}
	return errors.Errorf("ks-apiserver request error: code[%v], body[%s]", resp.StatusCode, strings.TrimSpace(string(body)))
}

func signalHandler() <-chan struct{} {
	stop := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c,
			syscall.SIGINT,  // Ctrl+C
			syscall.SIGTERM, // Termination Request
			syscall.SIGSEGV, // FullDerp
			syscall.SIGABRT, // Abnormal termination
			syscall.SIGILL,  // illegal instruction
			syscall.SIGFPE)  // floating point - this is why we can't have nice things
		sig := <-c
		klog.Warningf("Signal (%v) Detected, Shutting Down", sig)
		close(stop)
	}()
	return stop
}

func resourceNotFound(err error) bool {
	switch e := err.(type) {
	case *apierrors.StatusError:
		if e.Status().Code == http.StatusNotFound {
			return true
		}
	}
	return false
}
