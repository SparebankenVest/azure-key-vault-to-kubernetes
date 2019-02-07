package controller

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"

	// "k8s.io/client-go/tools/record"

	"github.com/SparebankenVest/azure-keyvault-controller/controller/vault"
	azurekeyvaultcontroller "github.com/SparebankenVest/azure-keyvault-controller/pkg/apis/azurekeyvaultcontroller/v1alpha1"
	"github.com/SparebankenVest/azure-keyvault-controller/pkg/client/clientset/versioned/fake"
	informers "github.com/SparebankenVest/azure-keyvault-controller/pkg/client/informers/externalversions"
)

type handlerFixture struct {
	t *testing.T

	client     *fake.Clientset
	kubeclient *k8sfake.Clientset

	// Objects to put in the store.
	azureKeyVaultSecretLister []*azurekeyvaultcontroller.AzureKeyVaultSecret
	secretsLister             []*corev1.Secret

	// Actions expected to happen on the client.
	kubeactions []core.Action
	actions     []core.Action

	// Objects from here preloaded into NewSimpleFake.
	kubeobjects []runtime.Object
	objects     []runtime.Object

	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder

	vaultService vault.Service

	fakeVaultServiceValue string
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	f := &handlerFixture{}
	f.t = t
	f.recorder = &record.FakeRecorder{}
	f.objects = []runtime.Object{}
	f.kubeobjects = []runtime.Object{}
	return f
}

func (f *handlerFixture) run(azureKeyVaultSecretName string) {
	f.runHandler(azureKeyVaultSecretName, true, false)
}

func (f *handlerFixture) runExpectError(azureKeyVaultSecretName string) {
	f.runHandler(azureKeyVaultSecretName, true, true)
}

func (f *handlerFixture) runHandler(azureKeyVaultSecretName string, startInformers bool, expectError bool) {
	h, i, k8sI := f.newHandler()
	if startInformers {
		stopCh := make(chan struct{})
		defer close(stopCh)
		i.Start(stopCh)
		k8sI.Start(stopCh)
	}

	err := h.kubernetesSyncHandler(azureKeyVaultSecretName)
	if !expectError && err != nil {
		f.t.Errorf("error syncing azureKeyVaultSecret: %v", err)
	} else if expectError && err == nil {
		f.t.Error("expected error syncing azureKeyVaultSecret, got nil")
	}

	actions := filterInformerActions(f.client.Actions())
	for i, action := range actions {
		if len(f.actions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(actions)-len(f.actions), actions[i:])
			break
		}

		expectedAction := f.actions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.actions) > len(actions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.actions)-len(actions), f.actions[len(actions):])
	}

	k8sActions := filterInformerActions(f.kubeclient.Actions())
	for i, action := range k8sActions {
		if len(f.kubeactions) < i+1 {
			f.t.Errorf("%d unexpected actions: %+v", len(k8sActions)-len(f.kubeactions), k8sActions[i:])
			break
		}

		expectedAction := f.kubeactions[i]
		checkAction(expectedAction, action, f.t)
	}

	if len(f.kubeactions) > len(k8sActions) {
		f.t.Errorf("%d additional expected actions:%+v", len(f.kubeactions)-len(k8sActions), f.kubeactions[len(k8sActions):])
	}
}

func (f *handlerFixture) newHandler() (*Handler, informers.SharedInformerFactory, kubeinformers.SharedInformerFactory) {
	f.client = fake.NewSimpleClientset(f.objects...)
	f.kubeclient = k8sfake.NewSimpleClientset(f.kubeobjects...)

	i := informers.NewSharedInformerFactory(f.client, noResyncPeriodFunc())
	k8sI := kubeinformers.NewSharedInformerFactory(f.kubeclient, noResyncPeriodFunc())
	azurePollFrequencies := AzurePollFrequency{
		Normal:                       time.Minute * 2,
		Slow:                         time.Minute * 5,
		MaxFailuresBeforeSlowingDown: 5,
	}

	recorder := &record.FakeRecorder{}

	vaultService := &fakeVaultService{
		fakeSecretValue: f.fakeVaultServiceValue,
	}
	handler := NewHandler(f.kubeclient, f.client, k8sI.Core().V1().Secrets().Lister(), i.Azurekeyvaultcontroller().V1alpha1().AzureKeyVaultSecrets().Lister(), recorder, vaultService, azurePollFrequencies)
	handler.clock = &FakeClock{}

	for _, f := range f.azureKeyVaultSecretLister {
		i.Azurekeyvaultcontroller().V1alpha1().AzureKeyVaultSecrets().Informer().GetIndexer().Add(f)
	}

	for _, d := range f.secretsLister {
		k8sI.Core().V1().Secrets().Informer().GetIndexer().Add(d)
	}

	return handler, i, k8sI
}

func (f *handlerFixture) expectUpdateAzureKeyVaultSecretStatusAction(azureKeyVaultSecret *azurekeyvaultcontroller.AzureKeyVaultSecret) {
	azureKeyVaultSecretCopy := azureKeyVaultSecret.DeepCopy()

	action := core.NewUpdateSubresourceAction(schema.GroupVersionResource{Resource: "azureKeyVaultSecrets"}, "status", azureKeyVaultSecret.Namespace, azureKeyVaultSecretCopy)
	f.kubeactions = append(f.kubeactions, action)
}

func (f *handlerFixture) expectUpdateSecretAction(d *corev1.Secret) {
	f.kubeactions = append(f.kubeactions, core.NewUpdateAction(schema.GroupVersionResource{Resource: "secrets"}, d.Namespace, d))
}

func (f *handlerFixture) expectCreateSecretAction(d *corev1.Secret) {
	f.kubeactions = append(f.kubeactions, core.NewCreateAction(schema.GroupVersionResource{Resource: "secrets"}, d.Namespace, d))
}

func (f *handlerFixture) expectDeleteSecretAction(d *corev1.Secret) {
	f.kubeactions = append(f.kubeactions, core.NewDeleteAction(schema.GroupVersionResource{Resource: "secrets"}, d.Namespace, d.Name))
}

// func TestUpdateKeyVaultOutputSecretName(t *testing.T) {
// 	f := newHandlerFixture(t)
// 	azureKeyVaultSecret := newAzureKeyVaultSecret("my-test-vault", "my-kubernetes-secret-name")
// 	d := createNewSecret(azureKeyVaultSecret, *secretData)
// 	t.Logf("secret name: %s", d.Name)

// 	// Clear secret.Name
// 	azureKeyVaultSecret.Spec.Output.Secret.Name = ""
// 	expSecret := createNewSecret(azureKeyVaultSecret, *secretData)
// 	t.Logf("changed secret name: %s", expSecret.Name)

// 	f.fakeVaultServiceValue = string(d.Data[azureKeyVaultSecret.Spec.Output.Secret.DataKey])
// 	f.azureKeyVaultSecretLister = append(f.azureKeyVaultSecretLister, azureKeyVaultSecret)
// 	f.objects = append(f.objects, azureKeyVaultSecret)
// 	f.secretsLister = append(f.secretsLister, d)
// 	f.kubeobjects = append(f.kubeobjects, d)

// 	f.expectCreateSecretAction(expSecret)
// 	f.expectUpdateAzureKeyVaultSecretStatusAction(azureKeyVaultSecret)
// 	// f.expectDeleteSecretAction(d)
// 	f.run(getKey(azureKeyVaultSecret, t))
// }

// func TestUpdateKeyVaultSecretType(t *testing.T) {
// 	f := newHandlerFixture(t)
// 	azureKeyVaultSecret := newAzureKeyVaultSecret("my-test-vault", "my-kubernetes-secret-name")
// 	d := createNewSecret(azureKeyVaultSecret, *secretData)

// 	// Update kubernetes secret type
// 	azureKeyVaultSecret.Spec.Output.Secret.Type = corev1.SecretTypeDockerConfigJson
// 	expSecret := createNewSecret(azureKeyVaultSecret, *secretData)

// 	f.azureKeyVaultSecretLister = append(f.azureKeyVaultSecretLister, azureKeyVaultSecret)
// 	f.objects = append(f.objects, azureKeyVaultSecret)
// 	f.secretsLister = append(f.secretsLister, d)
// 	f.kubeobjects = append(f.kubeobjects, d)

// 	f.expectUpdateSecretAction(expSecret)
// 	f.run(getKey(azureKeyVaultSecret, t))
// }

func TestDoNothing(t *testing.T) {
	f := newHandlerFixture(t)
	azureKeyVaultSecret := newAzureKeyVaultSecret("test", "my-kubernetes-secret-name")
	d := createNewSecret(azureKeyVaultSecret, *secretData)

	f.azureKeyVaultSecretLister = append(f.azureKeyVaultSecretLister, azureKeyVaultSecret)
	f.objects = append(f.objects, azureKeyVaultSecret)
	f.secretsLister = append(f.secretsLister, d)
	f.kubeobjects = append(f.kubeobjects, d)

	f.run(getKey(azureKeyVaultSecret, t))
}

func TestNotControlledByUs(t *testing.T) {
	f := newHandlerFixture(t)
	azureKeyVaultSecret := newAzureKeyVaultSecret("test", "my-kubernetes-secret-name")
	d := createNewSecret(azureKeyVaultSecret, *secretData)

	d.ObjectMeta.OwnerReferences = []metav1.OwnerReference{}

	f.azureKeyVaultSecretLister = append(f.azureKeyVaultSecretLister, azureKeyVaultSecret)
	f.objects = append(f.objects, azureKeyVaultSecret)
	f.secretsLister = append(f.secretsLister, d)
	f.kubeobjects = append(f.kubeobjects, d)

	f.runExpectError(getKey(azureKeyVaultSecret, t))
}
