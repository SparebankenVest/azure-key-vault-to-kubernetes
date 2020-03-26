package main

import (
	"os"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type kubeConfig struct {
	master string
	config string
}

func ensureIntegrationEnvironment(t *testing.T) kubeConfig {
	if os.Getenv("AKV2K8S_K8S_MASTER_URL") == "" || os.Getenv("AKV2K8S_K8S_CONFIG") == "" {
		t.Skip("Skipping integration test - no k8s cluster defined")
	}

	return kubeConfig{
		master: os.Getenv("AKV2K8S_K8S_MASTER_URL"),
		config: os.Getenv("AKV2K8S_K8S_CONFIG"),
	}
}

func TestAuthorization(t *testing.T) {
	config := ensureIntegrationEnvironment(t)

	podName := os.Getenv("AKV2K8S_K8S_TEST_POD")
	podNamespace := os.Getenv("AKV2K8S_K8S_TEST_NAMESPACE")
	podIP := os.Getenv("AKV2K8S_K8S_TEST_POD_IP")

	cfg, err := clientcmd.BuildConfigFromFlags(config.master, config.config)
	if err != nil {
		t.Errorf("Error building kubeconfig: %s", err.Error())
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Errorf("Error building kubernetes clientset: %s", err.Error())
	}

	pod := podData{
		name:          podName,
		namespace:     podNamespace,
		remoteAddress: podIP,
	}

	err = authorize(kubeClient, pod)
	if err != nil {
		t.Errorf("failed, error: %+v", err)
	}

}
