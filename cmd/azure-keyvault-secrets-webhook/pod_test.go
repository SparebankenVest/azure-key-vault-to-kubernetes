package main

import (
	"context"
	"fmt"
	"testing"

	cmp "github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fake "k8s.io/client-go/kubernetes/fake"
)

func TestGetInitContainersIncludesResources(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	initConfig()

	pw := podWebHook{
		injectorDir: "/azure-keyvault/",
	}

	got := pw.getInitContainers()
	if len(got) != 1 {
		t.Fatalf("expected 1 init container, got %d", len(got))
	}

	resources := got[0].Resources
	if cpu := resources.Requests.Cpu(); cpu == nil || cpu.Cmp(resource.MustParse("5m")) != 0 {
		t.Fatalf("expected cpu request 5m, got %v", cpu)
	}
	if memory := resources.Requests.Memory(); memory == nil || memory.Cmp(resource.MustParse("32Mi")) != 0 {
		t.Fatalf("expected memory request 32Mi, got %v", memory)
	}
	if memory := resources.Limits.Memory(); memory == nil || memory.Cmp(resource.MustParse("32Mi")) != 0 {
		t.Fatalf("expected memory limit 32Mi, got %v", memory)
	}
	if _, ok := resources.Limits[corev1.ResourceCPU]; ok {
		t.Fatalf("expected no cpu limit, got %v", resources.Limits[corev1.ResourceCPU])
	}
}

func TestMutateContainers(t *testing.T) {
	t.SkipNow()

	pw := podWebHook{
		clientset:  fake.NewSimpleClientset(),
		mutationID: "lasjdf",
		namespace:  "my-namespace",
	}

	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "MyContainer",
					Image:   "myimage",
					Command: []string{"/bin/bash"},
					Args:    nil,
					Env: []corev1.EnvVar{
						{
							Name:  "MY_ENV_VAR",
							Value: "myvar@azurekeyvault",
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:    "MyInitContainer",
					Image:   "myimage",
					Command: []string{"/bin/bash"},
					Args:    nil,
					Env: []corev1.EnvVar{
						{
							Name:  "MY_ENV_VAR",
							Value: "myvar@azurekeyvault",
						},
					},
				},
			},
		},
	}

	cmd := fmt.Sprintf("cp /usr/local/bin/%s %s", injectorExecutable, config.injectorDir)
	wantedPod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "MyContainer",
					Image:   "myimage",
					Command: []string{"azure-keyvault-env"},
					Args:    []string{"/bin/bash"},
					Env: []corev1.EnvVar{
						{
							Name:  "MY_ENV_VAR",
							Value: "myvar@azurekeyvault",
						},
						{
							Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
							Value: "bWh6TzFkUjVhWlk0ck1oaGw5YVN1NVltS2tManJKOWwzcFNyVnlYSSs4UlVPOWxrKzRtdUZ4dnhhM3o5WUxBWmZscUd1dlVhVC9YcGRlVjRGeDBWSWUvRmplbExxRUN5czRadWU3ODJQS29kQUFIQkVWWHh3eVlZdGFYd2dTOWx5VGsxNGdSRHJpN3BIZ2gybk5RcUdBZlltWkg4WGpoWkZnNnM5eUsyNlBBdDZlY2l1U0FhRFBWWHZhelpkZHlh",
						},
						{
							Name:  "ENV_INJECTOR_ARGS_KEY",
							Value: "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBM1JwZ09CYkVidENmTWNUQnJzdEwKaHRIMXdEbENMRkxNaUE2UnBCZ2h2R3V0ZFNOVU1Kb0p3bWJ0eGtFeUUxM2J3akRIM0dOSms2MGZYUnRSYitNWQpJUVR4d3BxdXJFWnRFMGRENkY4c3BjaFFRblQrWlJO",
						},
						{
							Name:  "ENV_INJECTOR_USE_AUTH_SERVICE",
							Value: "false",
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:            "copy-azurekeyvault-env",
					Image:           "",
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sh", "-c", cmd},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      initContainerVolumeName,
							MountPath: config.injectorDir,
						},
					},
				},
				{
					Name:    "MyInitContainer",
					Image:   "myimage",
					Command: []string{"azure-keyvault-env"},
					Args:    []string{"/bin/bash"},
					Env: []corev1.EnvVar{
						{
							Name:  "MY_ENV_VAR",
							Value: "myvar@azurekeyvault",
						},
						{
							Name:  "ENV_INJECTOR_ARGS_SIGNATURE",
							Value: "bWh6TzFkUjVhWlk0ck1oaGw5YVN1NVltS2tManJKOWwzcFNyVnlYSSs4UlVPOWxrKzRtdUZ4dnhhM3o5WUxBWmZscUd1dlVhVC9YcGRlVjRGeDBWSWUvRmplbExxRUN5czRadWU3ODJQS29kQUFIQkVWWHh3eVlZdGFYd2dTOWx5VGsxNGdSRHJpN3BIZ2gybk5RcUdBZlltWkg4WGpoWkZnNnM5eUsyNlBBdDZlY2l1U0FhRFBWWHZhelpkZHlh",
						},
						{
							Name:  "ENV_INJECTOR_ARGS_KEY",
							Value: "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBM1JwZ09CYkVidENmTWNUQnJzdEwKaHRIMXdEbENMRkxNaUE2UnBCZ2h2R3V0ZFNOVU1Kb0p3bWJ0eGtFeUUxM2J3akRIM0dOSms2MGZYUnRSYitNWQpJUVR4d3BxdXJFWnRFMGRENkY4c3BjaFFRblQrWlJO",
						},
						{
							Name:  "ENV_INJECTOR_USE_AUTH_SERVICE",
							Value: "false",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: keyVaultEnvVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumMemory,
						},
					},
				},
			},
		},
	}

	// authSecret := corev1.Secret{
	// 	ObjectMeta: v1.ObjectMeta{
	// 		Name:      "myAuthSecret",
	// 		Namespace: ns,
	// 	},
	// 	StringData: map[string]string{"secret": "my secret"},
	// }

	err := pw.mutatePodSpec(context.Background(), &pod) //mutateContainers(kubeClient, podSpec.Containers, &podSpec, ns, &authSecret)
	if err != nil {
		t.Error(err)
	}

	// if !mutated {
	// 	t.Error("Pod not mutated")
	// }

	if !cmp.Equal(pod, wantedPod) {
		t.Errorf("mutatingWebhook.mutateContainers() = diff %v", cmp.Diff(pod, wantedPod))
	}

	// got, err := mw.mutateContainers(context.Background(), tt.args.containers, tt.args.podSpec, tt.args.vaultConfig, tt.args.ns)
	// if (err != nil) != tt.wantErr {
	// 	t.Errorf("mutatingWebhook.mutateContainers() error = %v, wantErr %v", err, tt.wantErr)
	// 	return
	// }
	// if got != tt.mutated {
	// 	t.Errorf("mutatingWebhook.mutateContainers() = %v, want %v", got, tt.mutated)
	// }
	// if !cmp.Equal(tt.args.containers, tt.wantedContainers) {
	// 	t.Errorf("mutatingWebhook.mutateContainers() = diff %v", cmp.Diff(tt.args.containers, tt.wantedContainers))
	// }
}

// configMap is a helper that builds a corev1.ConfigMap pre-seeded with the given key/value pairs.
func configMap(namespace, name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
}

// podWebHookForTest returns a minimal podWebHook wired to a fake clientset
// pre-loaded with the supplied ConfigMaps.
func podWebHookForTest(namespace string, cms ...*corev1.ConfigMap) podWebHook {
	viper.Reset()
	initConfig()
	objs := make([]runtime.Object, len(cms))
	for i, cm := range cms {
		objs[i] = cm
	}
	return podWebHook{
		clientset:      fake.NewSimpleClientset(objs...),
		namespace:      namespace,
		mutationID:     "test-mutation-id",
		injectorDir:    "/azure-keyvault/",
		useAuthService: false,
	}
}

// wasInjected returns true if mutatePodSpec injected the azure-keyvault-env init container.
func wasInjected(pod *corev1.Pod) bool {
	for _, ic := range pod.Spec.InitContainers {
		if ic.Name == "copy-azurekeyvault-env" {
			return true
		}
	}
	return false
}

// TestEnvFromConfigMapInjection validates that a pod whose @azurekeyvault values
// arrive exclusively via envFrom.configMapRef is mutated (init container injected).
// This is the primary bug regression test for issue #858.
func TestEnvFromConfigMapInjection(t *testing.T) {
	const ns = "test-ns"

	tests := []struct {
		name        string
		cms         []*corev1.ConfigMap
		containers  []corev1.Container
		wantMutated bool
	}{
		{
			// BUG CASE: all @azurekeyvault values in envFrom ConfigMap — must be mutated.
			name: "envFrom configmap with @azurekeyvault values triggers mutation",
			cms: []*corev1.ConfigMap{
				configMap(ns, "app-config", map[string]string{
					"SECRET_ALPHA": "my-secret-alpha@azurekeyvault",
					"SECRET_BETA":  "my-secret-beta@azurekeyvault",
					"PLAIN_VALUE":  "not-a-secret",
				}),
			},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					EnvFrom: []corev1.EnvFromSource{
						{ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
						}},
					},
				},
			},
			wantMutated: true,
		},
		{
			// envFrom ConfigMap has no @azurekeyvault values — must NOT be mutated.
			name: "envFrom configmap without @azurekeyvault values skips mutation",
			cms: []*corev1.ConfigMap{
				configMap(ns, "plain-config", map[string]string{
					"LOG_LEVEL": "info",
					"TIMEOUT":   "30s",
				}),
			},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					EnvFrom: []corev1.EnvFromSource{
						{ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "plain-config"},
						}},
					},
				},
			},
			wantMutated: false,
		},
		{
			// Optional envFrom ConfigMap that does not exist — must not error or mutate.
			name: "optional envFrom configmap not found skips gracefully",
			cms:  []*corev1.ConfigMap{},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					EnvFrom: []corev1.EnvFromSource{
						{ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "missing-config"},
							Optional:             func(b bool) *bool { return &b }(true),
						}},
					},
				},
			},
			wantMutated: false,
		},
		{
			// Mixed: one envFrom CM without secrets + one with — must still be mutated.
			name: "multiple envFrom sources — mutation triggered by any matching configmap",
			cms: []*corev1.ConfigMap{
				configMap(ns, "plain-config", map[string]string{"LOG_LEVEL": "info"}),
				configMap(ns, "secret-config", map[string]string{"DB_CONN": "db-connection@azurekeyvault"}),
			},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					EnvFrom: []corev1.EnvFromSource{
						{ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "plain-config"},
						}},
						{ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "secret-config"},
						}},
					},
				},
			},
			wantMutated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			pw := podWebHookForTest(ns, tt.cms...)
			pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: tt.containers}}

			if err := pw.mutatePodSpec(context.Background(), pod); err != nil {
				t.Fatalf("mutatePodSpec() error: %v", err)
			}

			got := wasInjected(pod)
			if got != tt.wantMutated {
				t.Errorf("wasInjected = %v, want %v", got, tt.wantMutated)
			}
		})
	}
}

// TestValueFromConfigMapKeyRefInjection validates that a pod whose @azurekeyvault value
// arrives via env[].valueFrom.configMapKeyRef is mutated.
func TestValueFromConfigMapKeyRefInjection(t *testing.T) {
	const ns = "test-ns"

	tests := []struct {
		name        string
		cms         []*corev1.ConfigMap
		containers  []corev1.Container
		wantMutated bool
	}{
		{
			name: "valueFrom.configMapKeyRef pointing to @azurekeyvault triggers mutation",
			cms: []*corev1.ConfigMap{
				configMap(ns, "app-config", map[string]string{
					"my-secret-key": "my-secret@azurekeyvault",
				}),
			},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					Env: []corev1.EnvVar{
						{
							Name: "MY_SECRET",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
									Key:                  "my-secret-key",
								},
							},
						},
					},
				},
			},
			wantMutated: true,
		},
		{
			name: "valueFrom.configMapKeyRef pointing to plain value skips mutation",
			cms: []*corev1.ConfigMap{
				configMap(ns, "app-config", map[string]string{
					"log-level": "info",
				}),
			},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					Env: []corev1.EnvVar{
						{
							Name: "LOG_LEVEL",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
									Key:                  "log-level",
								},
							},
						},
					},
				},
			},
			wantMutated: false,
		},
		{
			// Optional valueFrom.configMapKeyRef with missing CM — must not error.
			name: "optional valueFrom.configMapKeyRef with missing configmap skips gracefully",
			cms:  []*corev1.ConfigMap{},
			containers: []corev1.Container{
				{
					Name:    "app",
					Image:   "myimage",
					Command: []string{"/bin/sh"},
					Env: []corev1.EnvVar{
						{
							Name: "MY_SECRET",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "missing-config"},
									Key:                  "secret-key",
									Optional:             func(b bool) *bool { return &b }(true),
								},
							},
						},
					},
				},
			},
			wantMutated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			pw := podWebHookForTest(ns, tt.cms...)
			pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: tt.containers}}

			if err := pw.mutatePodSpec(context.Background(), pod); err != nil {
				t.Fatalf("mutatePodSpec() error: %v", err)
			}

			got := wasInjected(pod)
			if got != tt.wantMutated {
				t.Errorf("wasInjected = %v, want %v", got, tt.wantMutated)
			}
		})
	}
}
