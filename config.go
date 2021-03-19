package main

import "flag"

type Config struct {
	Kubeconfig string

	Mysql struct {
		Address  string
		User     string
		Database string
	}

	Kubesphere struct {
		AlertingEndpoint string
		User             string
		Token            string
	}

	DryRun bool
}

func (c *Config) AddFlags() {
	flag.StringVar(&c.Kubeconfig, "kubeconfig", "", "path to the kubeconfig file. If left blank, use the inClusterConfig")

	flag.StringVar(&c.Mysql.Address, "mysql.address", "mysql.kubesphere-system.svc:3306", "mysql service address. Default to mysql.kubesphere-system.svc:3306")
	flag.StringVar(&c.Mysql.User, "mysql.user", "root:password", "<user:password> mysql service user and password. Default to root:password")
	flag.StringVar(&c.Mysql.Database, "mysql.database", "alert", "mysql database name. Default to alert")

	flag.StringVar(&c.Kubesphere.AlertingEndpoint, "kubesphere.alerting-endpoint", "http://ks-apiserver.kubesphere-system.svc:80/kapis/alerting.kubesphere.io/v2alpha1", "ks-apiserver alerting endpoint. Default to http://ks-apiserver.kubesphere-system.svc:80/kapis/alerting.kubesphere.io/v2apha1")
	flag.StringVar(&c.Kubesphere.User, "kubesphere.user", "", "<user:password> ks-apiserver user and password")
	flag.StringVar(&c.Kubesphere.Token, "kubesphere.token", "", "ks-apiserver auth token")

	flag.BoolVar(&c.DryRun, "dry-run", false, "If true, only print the rules parsed from the previous rules. Default to false")
}
