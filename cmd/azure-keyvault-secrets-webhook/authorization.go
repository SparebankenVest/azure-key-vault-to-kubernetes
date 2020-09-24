package main

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type podData struct {
	remoteAddress string
	name          string
	namespace     string
	token         string
}

func authorize(clientset kubernetes.Interface, podData podData) error {
	ns, err := clientset.CoreV1().Namespaces().Get(podData.namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace '%s', error: %+v", podData.namespace, err)
	}

	if ns.Labels["azure-key-vault-env-injection"] != "enabled" {
		return fmt.Errorf("env-injection not enabled for namespace,")
	}

	pod, err := clientset.CoreV1().Pods(podData.namespace).Get(podData.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get pod '%s' in namespace '%s', error: %+v", podData.name, podData.namespace, err)
	}

	remoteIP := strings.Split(podData.remoteAddress, ":")[0]
	if pod.Status.PodIP != remoteIP {
		return fmt.Errorf("the provided pod data does not correspond with caller ip")
	}

	containerHasInjectorCmd := false
	for _, container := range pod.Spec.Containers {
		if len(container.Command) > 0 && container.Command[0] == "/azure-keyvault/azure-keyvault-env" {
			containerHasInjectorCmd = true
			break
		}
	}

	if !containerHasInjectorCmd {
		return fmt.Errorf("no container has env-injector command")
	}

	hasEnvInjectorInitContainer := false
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == "copy-azurekeyvault-env" {
			hasEnvInjectorInitContainer = true
			break
		}
	}

	if !hasEnvInjectorInitContainer {
		return fmt.Errorf("pod has no env-injector initContainer")
	}

	return nil
}
