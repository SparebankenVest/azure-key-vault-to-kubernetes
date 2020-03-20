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
	credentials         *vault.AzureKeyVaultCredentials
	aadPodBindingLabel  string
	cloudConfigHostPath string
	certFile            string
	keyFile             string
	caFile              string
	port                string
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
	viper.SetDefault("client_cert_secret_name", "akv2k8s-client-cert")
	viper.SetDefault("port", "8443")
	viper.AutomaticEnv()
}

// accept a client certificate for authentication (which is be provided by init-container)
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		token, err := config.credentials.OAuthToken()
		if err != nil {
			log.Errorf("failed to get azure token, err: %+v", err)
			http.Error(w, "failed to get azure token", http.StatusNotFound)
			return
		}

		log.Infof("served token to '%s' at address '%s'", r.FormValue("host"), r.RemoteAddr)
		fmt.Fprint(w, token)
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

func main() {
	fmt.Fprintln(os.Stdout, "initializing config...")
	initConfig()
	fmt.Fprintln(os.Stdout, "config initialized")

	logLevel := viper.GetString("LOG_LEVEL")
	setLogLevel(logLevel)

	config = azureKeyVaultConfig{
		customAuth:          viper.GetBool("CUSTOM_AUTH"),
		cloudConfigHostPath: "/etc/kubernetes/azure.json",
		certFile:            viper.GetString("tls_cert_file"),
		keyFile:             viper.GetString("tls_private_key_file"),
		caFile:              viper.GetString("tls_ca_file"),
		port:                viper.GetString("port"),
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

	credType, err := config.credentials.CredentialsType()
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("serving credentials of type %s", credType)

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
	authMux.HandleFunc("/healthz", healthHandler)

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
