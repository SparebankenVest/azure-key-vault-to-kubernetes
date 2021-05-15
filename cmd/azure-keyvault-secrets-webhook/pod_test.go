package main

import (
	"context"
	"fmt"
	"testing"

	cmp "github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	fake "k8s.io/client-go/kubernetes/fake"
)

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
