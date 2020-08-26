package main

import (
	"os"
	"testing"

	authenticationapi "k8s.io/api/authentication/v1"
	authorizatonapi "k8s.io/api/authorization/v1"
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

func TestTokenReview(t *testing.T) {
	config := ensureIntegrationEnvironment(t)

	cfg, err := clientcmd.BuildConfigFromFlags("https://127.0.0.1:32770", config.config)
	if err != nil {
		t.Errorf("Error building kubeconfig: %s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Error(err)
	}

	tr := &authenticationapi.TokenReview{
		Spec: authenticationapi.TokenReviewSpec{
			Token: "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJha3YyazhzLXRlc3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoiZGVmYXVsdC10b2tlbi1rcWY3NyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMjViYTczYWMtNzA3YS0xMWVhLTg2YzEtMDI0MmFjMTEwMDAyIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmFrdjJrOHMtdGVzdDpkZWZhdWx0In0.gQu3MuqG3lqtuuQnjY70PHjKfdIfxnc2K2wTTgINoHi7LyG5bTr6iKc15e3wpQy1Tt-AeCz4SyfXxIJVXvXKSNKaE47Lj2nzfcaQa7PR_A3i6wxRBke0klQl8pm5ZYNTP54cKcyBD7MNlLCcqmg5Jqpzpsj5mVHIVDAQza5--7ujietpEhTo6goUZluu4psVm-24BViVUnYWPdRBEEbCj7UdxImcIB7luFqXWwiBGYHcaY0CgfxSPYdy1CnRitbuPBIQU9Gpsg9HtHNXNdNJO9LH17uonIMvg6TyMhCiKTMJIw9lNkUbcu-cf5EFpIo3Xev8lbG_VybHUQoqjeRaMQ",
			// Audiences: []string{
			// 	"",
			// 	"",
			// },
		},
	}

	trResult, err := clientset.AuthenticationV1().TokenReviews().Create(tr)
	if err != nil {
		t.Error(err)
	}

	if trResult == nil {
		t.Fail()
	}

	sar := &authorizatonapi.SubjectAccessReview{
		Spec: authorizatonapi.SubjectAccessReviewSpec{
			User: trResult.Status.User.Username,
			ResourceAttributes: &authorizatonapi.ResourceAttributes{
				Resource:  "AzureKeyVaultSecret",
				Group:     "spv.no",
				Namespace: "akv2k8s-test",
				Verb:      "get",
				Name:      "test-secret",
			},
		},
	}
	sarResult, err := clientset.AuthorizationV1().SubjectAccessReviews().Create(sar)
	if err != nil {
		t.Error(err)
	}

	if sarResult == nil {
		t.Fail()
	}

	t.Logf("ns: %s", trResult.Namespace)

}

// func TestAuthorization(t *testing.T) {
// 	config := ensureIntegrationEnvironment(t)

// 	podName := os.Getenv("AKV2K8S_K8S_TEST_POD")
// 	podNamespace := os.Getenv("AKV2K8S_K8S_TEST_NAMESPACE")
// 	podIP := os.Getenv("AKV2K8S_K8S_TEST_POD_IP")

// 	cfg, err := clientcmd.BuildConfigFromFlags(config.master, config.config)
// 	if err != nil {
// 		t.Errorf("Error building kubeconfig: %s", err.Error())
// 	}

// 	kubeClient, err := kubernetes.NewForConfig(cfg)
// 	if err != nil {
// 		t.Errorf("Error building kubernetes clientset: %s", err.Error())
// 	}

// 	pod := podData{
// 		name:          podName,
// 		namespace:     podNamespace,
// 		remoteAddress: podIP,
// 	}

// 	err = authorize(kubeClient, pod)
// 	if err != nil {
// 		t.Errorf("failed, error: %+v", err)
// 	}

// }
