// Copyright © 2020 Sparebanken Vest
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Note: Code is based on bank-vaults from Banzai Cloud
//       (https://github.com/banzaicloud/bank-vaults)

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	vault "github.com/SparebankenVest/azure-key-vault-to-kubernetes/pkg/azurekeyvault/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	clientCertDir = "/client-cert/"
)

type azureKeyVaultConfig struct {
	customAuth          bool
	credentials         vault.AzureKeyVaultCredentials
	aadPodBindingLabel  string
	cloudConfigHostPath string
	certFile            string
	keyFile             string
	caFile              string
	port                string
	healthzPort         string
}

var config azureKeyVaultConfig

func setLogLevel(logLevel string) {
	if logLevel == "" {
		logLevel = log.InfoLevel.String()
	}

	logrusLevel, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("error setting log level: %s", err.Error())
	}
	log.SetLevel(logrusLevel)
}

func initConfig() {
	viper.SetDefault("cloud_config_host_path", "/etc/kubernetes/azure.json")
	viper.SetDefault("client_cert_secret_name", "akv2k8s-client-cert")
	viper.SetDefault("port", "8443")
	viper.SetDefault("healthz_port", "3000")
	viper.AutomaticEnv()
}

// accept a client certificate for authentication (which is be provided by init-container)
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		host := ""
		hosts, ok := r.URL.Query()["host"]
		if !ok || len(hosts[0]) < 1 {
			log.Warn("url param 'host' is missing")
		} else {
			host = hosts[0]
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)

		log.Infof("served oauth token to '%s' at address '%s'", host, r.RemoteAddr)

		if err := json.NewEncoder(w).Encode(config.credentials); err != nil {
			log.Errorf("failed to json encode token, error: %+v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		log.Error("invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func serveHealthz() {
	healthzMux := http.NewServeMux()
	healthzMux.HandleFunc("/healthz", healthHandler)
	err := http.ListenAndServeTLS(fmt.Sprintf(":%s", config.healthzPort), config.certFile, config.keyFile, healthzMux)
	if err != nil {
		log.Fatalf("error serving metrics: %s", err)
	}
}

func main() {
	fmt.Fprintln(os.Stdout, "initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "config initialized")

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)

	config = azureKeyVaultConfig{
		customAuth:          viper.GetBool("custom_auth"),
		cloudConfigHostPath: viper.GetString("cloud_config_host_path"),
		certFile:            viper.GetString("tls_cert_file"),
		keyFile:             viper.GetString("tls_private_key_file"),
		caFile:              viper.GetString("tls_ca_file"),
		port:                viper.GetString("port"),
		healthzPort:         viper.GetString("healthz_port"),
	}

	var err error
	if config.customAuth {
		config.credentials, err = vault.NewAzureKeyVaultCredentialsFromEnvironment()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		config.credentials, err = vault.NewAzureKeyVaultCredentialsFromCloudConfig(config.cloudConfigHostPath)
		if err != nil {
			log.Fatal(err)
		}
	}

	// log.Infof("serving credentials of type %s", credType)

	caCert, err := ioutil.ReadFile(config.caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	authMux := http.NewServeMux()
	authMux.HandleFunc("/auth", authHandler)

	// need to serve health endpoint on a different port
	// to avoid client cert requirement
	go serveHealthz()

	authServer := &http.Server{
		Addr:      fmt.Sprintf(":%s", config.port),
		TLSConfig: tlsConfig,
		Handler:   authMux,
	}

	log.Infof("auth listening on :%s", config.port)
	err = authServer.ListenAndServeTLS(config.certFile, config.keyFile)
	if err != nil {
		log.Fatalf("error serving webhook auth endpoint: %+v", err)
	}
}
