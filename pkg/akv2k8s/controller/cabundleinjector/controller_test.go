package cabundleinjector

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

var (
	alwaysReady        = func() bool { return true }
	noResyncPeriodFunc = func() time.Duration { return 0 }
)

type fixture struct {
	t *testing.T

	kubeclient *k8sfake.Clientset
	// Objects to put in the store.
	secretLister    []*corev1.Secret
	configMapLister []*corev1.ConfigMap
	namespaceLister []*corev1.Namespace

	// Actions expected to happen on the client.
	kubeactions []core.Action
	// actions     []core.Action

	// Objects from here preloaded into NewSimpleFake.
	kubeobjects []runtime.Object
	objects     []runtime.Object
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{}
	f.t = t
	f.objects = []runtime.Object{}
	f.kubeobjects = []runtime.Object{}
	return f
}

func (f *fixture) newController() (*Controller, []kubeinformers.SharedInformerFactory) {
	f.kubeclient = k8sfake.NewSimpleClientset(f.kubeobjects...)

	k8sInformerSecrets := kubeinformers.NewSharedInformerFactory(f.kubeclient, noResyncPeriodFunc())
	k8sInformerNamespaces := kubeinformers.NewSharedInformerFactory(f.kubeclient, noResyncPeriodFunc())
	k8sInformerConfigMaps := kubeinformers.NewSharedInformerFactory(f.kubeclient, noResyncPeriodFunc())

	// NewController(secretCABundleInformer coreinformers.SecretInformer, namespaceInformer coreinformers.NamespaceInformer, configMapInformer coreinformers.ConfigMapInformer)
	c := NewController(f.kubeclient, record.NewFakeRecorder(100), k8sInformerSecrets.Core().V1().Secrets(), k8sInformerNamespaces.Core().V1().Namespaces(), k8sInformerConfigMaps.Core().V1().ConfigMaps(), "azure-key-vault-env-injection", "akv2k8s", "azure-key-vault-env-injector", "akv2k8s-ca")

	// c.foosSynced = alwaysReady
	// c.deploymentsSynced = alwaysReady
	// c.recorder = &record.FakeRecorder{}

	// for _, f := range f.fooLister {
	// 	i.Samplecontroller().V1alpha1().Foos().Informer().GetIndexer().Add(f)
	// }

	for _, d := range f.secretLister {
		k8sInformerSecrets.Core().V1().Secrets().Informer().GetIndexer().Add(d)
	}

	for _, d := range f.configMapLister {
		k8sInformerConfigMaps.Core().V1().ConfigMaps().Informer().GetIndexer().Add(d)
	}

	for _, d := range f.namespaceLister {
		k8sInformerNamespaces.Core().V1().Namespaces().Informer().GetIndexer().Add(d)
	}

	return c, []kubeinformers.SharedInformerFactory{
		k8sInformerConfigMaps,
		k8sInformerNamespaces,
		k8sInformerSecrets,
	}
}

func createNewSecret(name string, namespace string, secretValue map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: secretValue,
	}
}

func createNewNamespace(name string, addLabel bool) *corev1.Namespace {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	if addLabel {
		ns.Labels = map[string]string{
			"azure-key-vault-env-injection": "enabled",
		}
	}
	return ns
}

func (f *fixture) run(secretName string, namespaceName string) {
	f.runController(secretName, namespaceName, true, false)
}

func (f *fixture) runExpectError(secretName string, namespaceName string) {
	f.runController(secretName, namespaceName, true, true)
}

func (f *fixture) runController(secretName string, namespaceName string, startInformers bool, expectError bool) {
	c, informers := f.newController()
	if startInformers {
		stopCh := make(chan struct{})
		defer close(stopCh)
		for _, informer := range informers {
			informer.Start(stopCh)
		}
	}

	if secretName != "" {
		err := c.syncHandlerSecret(secretName)
		if !expectError && err != nil {
			f.t.Errorf("error syncing foo: %v", err)
		} else if expectError && err == nil {
			f.t.Error("expected error syncing foo, got nil")
		}
	}

	if namespaceName != "" {
		err := c.syncHandlerNewNamespace(namespaceName)
		if !expectError && err != nil {
			f.t.Errorf("error syncing namespace: %v", err)
		} else if expectError && err == nil {
			f.t.Error("expected error syncing namespace, got nil")
		}
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

func getKey(obj interface{}, t *testing.T) string {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		t.Errorf("Unexpected error getting key for object: %v", err)
		return ""
	}
	return key
}

// checkAction verifies that expected and actual actions are equal and both have
// same attached resources
func checkAction(expected, actual core.Action, t *testing.T) {
	if !(expected.Matches(actual.GetVerb(), actual.GetResource().Resource) && actual.GetSubresource() == expected.GetSubresource()) {
		t.Errorf("Expected\n\t%#v\ngot\n\t%#v", expected, actual)
		return
	}

	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		t.Errorf("Action has wrong type. Expected: %t. Got: %t", expected, actual)
		return
	}

	switch a := actual.(type) {
	case core.CreateActionImpl:
		e, _ := expected.(core.CreateActionImpl)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("Action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expObject, object))
		}
	case core.UpdateActionImpl:
		e, _ := expected.(core.UpdateActionImpl)
		expObject := e.GetObject()
		object := a.GetObject()

		if !reflect.DeepEqual(expObject, object) {
			t.Errorf("Action %s %s has wrong object\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expObject, object))
		}
	case core.PatchActionImpl:
		e, _ := expected.(core.PatchActionImpl)
		expPatch := e.GetPatch()
		patch := a.GetPatch()

		if !reflect.DeepEqual(expPatch, patch) {
			t.Errorf("Action %s %s has wrong patch\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expPatch, patch))
		}
	case core.DeleteActionImpl:
		e, _ := expected.(core.DeleteActionImpl)
		expDel := e.GetName()
		del := a.GetName()

		if !reflect.DeepEqual(expDel, del) {
			t.Errorf("Action %s %s has wrong delete\nDiff:\n %s",
				a.GetVerb(), a.GetResource().Resource, diff.ObjectGoPrintSideBySide(expDel, del))
		}
	default:
		t.Errorf("Uncaptured Action %s %s, you should explicitly add a case to capture it",
			actual.GetVerb(), actual.GetResource().Resource)
	}
}

// filterInformerActions filters list and watch actions for testing resources.
// Since list and watch don't change resource state we can filter it to lower
// nose level in our tests.
func filterInformerActions(actions []core.Action) []core.Action {
	ret := []core.Action{}
	for _, action := range actions {
		if len(action.GetNamespace()) == 0 &&
			(action.Matches("list", "secrets") ||
				action.Matches("watch", "secrets") ||
				action.Matches("list", "configmaps") ||
				action.Matches("watch", "configmaps") ||
				action.Matches("list", "namespaces") ||
				action.Matches("watch", "namespaces")) {
			continue
		}
		ret = append(ret, action)
	}

	return ret
}

func (f *fixture) expectCreateNamespaceAction(namespace *corev1.Namespace) {
	f.kubeactions = append(f.kubeactions, core.NewCreateAction(schema.GroupVersionResource{Resource: "namespaces"}, namespace.Name, namespace))
}

func (f *fixture) expectCreateConfigMapAction(cm *corev1.ConfigMap) {
	f.kubeactions = append(f.kubeactions, core.NewCreateAction(schema.GroupVersionResource{Resource: "configmaps"}, cm.Namespace, cm))
}

func (f *fixture) expectRemoveConfigMapAction(cm *corev1.ConfigMap) {
	f.kubeactions = append(f.kubeactions, core.NewDeleteAction(schema.GroupVersionResource{Resource: "configmaps"}, cm.Namespace, cm.Name))
}

func TestCreatesConfigMap(t *testing.T) {
	f := newFixture(t)

	secretValue := map[string]string{
		"caCert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM5akNDQWQ2Z0F3SUJBZ0lRSmFUeUxENnVPM0lYOERKZlZhZ1NtekFOQmdrcWhraUc5dzBCQVFzRkFEQVYKTVJNd0VRWURWUVFERXdwemRtTXRZMkYwTFdOaE1CNFhEVEl3TURNeE9URTBOREV5T1ZvWERUTXdNRE14TnpFMApOREV5T1Zvd0ZURVRNQkVHQTFVRUF4TUtjM1pqTFdOaGRDMWpZVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFECmdnRVBBRENDQVFvQ2dnRUJBTVFFdFRZUG5FSnFoMXc4NFI5MWV0Nng1MFB3NEVZNFpjOUhHRW5KRW1UdEVSOVUKTG44MGg3MUwwdnJUOXpUcTVhZFlsOWRhaDB5T2JJUU1aMU5VYmdPanQvczJnUHNRaFU5QVZPbmNqWG1OK0x2eQo5Q0I4NEFiY1A0U0NLV1pSQWd1NVhQdGlsUlNYbG9NTGxLUU52TWZ2QkpDWlhvcS9pVWZXcmxQOWp1dHQ2V0luCjdKUWxXUmRhdENYby9sWDZ0cFgydy8vMU1XZTN1R1lKcWNyUFlVN2c5N1NjdWJEZCtBanE4RSs2S0FqU3AzVnQKUTU5enpKenRFczNJaVBUU0szbXlrSVNXUWdlSEVUZ3F0cFJiaVdHOW0xdDBDc3FVRVBmMjhIayt4VHVVOWFBeQpZclVhbFkrSmxxc2hybUVLdUsxL2NMMU8zZU95aHRXT2R2SndYNThDQXdFQUFhTkNNRUF3RGdZRFZSMFBBUUgvCkJBUURBZ0trTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQVBCZ05WSFJNQkFmOEUKQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUF0eHp1alVIa3c1VmJyczFNcWl6Vkd2dk9sdVZSQgpzb1NPb3BuakZVdHkyYjV6OUltcHdDeEMwWmppNFVVdVdrMTJHZGxldlE0dTdvbmV5VytZR25qeDNRY1FGQ2plCmpTeU1uM2xsWnpFcVFyLzNpWDVBRUp4NFZDZ3lmNmtiVmdmbnp2aXVrWm83NjUwTCt0V0xiK2JNWllDZ0h1a3YKVi9SNlBxSGdzZDZiSlV4U1lMWElFamtCK0x5cXlSM2RvZDRDNUhpK2dRd0dsK0EyWVd4R0p0SDZVOExYVldYLwpKSDIvUXVIU09uUm9QeVV4MVduUDV6M1NHYWZyR1ZrbVJwTW56UWk3YjFFeTJMQVlENGhCRlJXZSt0bWR3NjRRCmJMbUYwRU85cVVKQjg2bE1LN2pvVUk2TFc5ajF6SWVUREZRN0ZZOUY2VEJiNmZoNVFNak1YdVhYCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
	}

	akvNamespace := createNewNamespace("akv2k8s", false)
	namespace := createNewNamespace("akv2k8s-test", true)
	fakeSecret := createNewSecret("azure-key-vault-env-injector", "akv2k8s", secretValue)

	f.namespaceLister = append(f.namespaceLister, akvNamespace)
	f.namespaceLister = append(f.namespaceLister, namespace)
	f.secretLister = append(f.secretLister, fakeSecret)

	cm := newConfigMap("akv2k8s-ca", namespace.Name, fakeSecret)
	f.expectCreateConfigMapAction(cm)

	f.run(getKey(fakeSecret, t), "")
}

func TestCreatesConfigMapInNewNamespace(t *testing.T) {
	t.Skip("Not finished")
	f := newFixture(t)

	secretValue := map[string]string{
		"caCert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM5akNDQWQ2Z0F3SUJBZ0lRSmFUeUxENnVPM0lYOERKZlZhZ1NtekFOQmdrcWhraUc5dzBCQVFzRkFEQVYKTVJNd0VRWURWUVFERXdwemRtTXRZMkYwTFdOaE1CNFhEVEl3TURNeE9URTBOREV5T1ZvWERUTXdNRE14TnpFMApOREV5T1Zvd0ZURVRNQkVHQTFVRUF4TUtjM1pqTFdOaGRDMWpZVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFECmdnRVBBRENDQVFvQ2dnRUJBTVFFdFRZUG5FSnFoMXc4NFI5MWV0Nng1MFB3NEVZNFpjOUhHRW5KRW1UdEVSOVUKTG44MGg3MUwwdnJUOXpUcTVhZFlsOWRhaDB5T2JJUU1aMU5VYmdPanQvczJnUHNRaFU5QVZPbmNqWG1OK0x2eQo5Q0I4NEFiY1A0U0NLV1pSQWd1NVhQdGlsUlNYbG9NTGxLUU52TWZ2QkpDWlhvcS9pVWZXcmxQOWp1dHQ2V0luCjdKUWxXUmRhdENYby9sWDZ0cFgydy8vMU1XZTN1R1lKcWNyUFlVN2c5N1NjdWJEZCtBanE4RSs2S0FqU3AzVnQKUTU5enpKenRFczNJaVBUU0szbXlrSVNXUWdlSEVUZ3F0cFJiaVdHOW0xdDBDc3FVRVBmMjhIayt4VHVVOWFBeQpZclVhbFkrSmxxc2hybUVLdUsxL2NMMU8zZU95aHRXT2R2SndYNThDQXdFQUFhTkNNRUF3RGdZRFZSMFBBUUgvCkJBUURBZ0trTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQVBCZ05WSFJNQkFmOEUKQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUF0eHp1alVIa3c1VmJyczFNcWl6Vkd2dk9sdVZSQgpzb1NPb3BuakZVdHkyYjV6OUltcHdDeEMwWmppNFVVdVdrMTJHZGxldlE0dTdvbmV5VytZR25qeDNRY1FGQ2plCmpTeU1uM2xsWnpFcVFyLzNpWDVBRUp4NFZDZ3lmNmtiVmdmbnp2aXVrWm83NjUwTCt0V0xiK2JNWllDZ0h1a3YKVi9SNlBxSGdzZDZiSlV4U1lMWElFamtCK0x5cXlSM2RvZDRDNUhpK2dRd0dsK0EyWVd4R0p0SDZVOExYVldYLwpKSDIvUXVIU09uUm9QeVV4MVduUDV6M1NHYWZyR1ZrbVJwTW56UWk3YjFFeTJMQVlENGhCRlJXZSt0bWR3NjRRCmJMbUYwRU85cVVKQjg2bE1LN2pvVUk2TFc5ajF6SWVUREZRN0ZZOUY2VEJiNmZoNVFNak1YdVhYCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
	}

	fakeSecret := createNewSecret("azure-key-vault-env-injector", "akv2k8s", secretValue)
	namespace := createNewNamespace("akv2k8s-test", true)
	existingConfigMap := newConfigMap("akv2k8s-ca", namespace.Name, fakeSecret)

	f.secretLister = append(f.secretLister, fakeSecret)
	f.namespaceLister = append(f.namespaceLister, namespace)
	f.configMapLister = append(f.configMapLister, existingConfigMap)

	newNamespace := createNewNamespace("akv2k8s-test2", true)
	f.kubeobjects = append(f.kubeobjects, newNamespace)

	cm := newConfigMap("akv2k8s-ca", newNamespace.Name, fakeSecret)
	// f.expectCreateNamespaceAction(newNamespace)
	f.expectCreateConfigMapAction(cm)

	f.run(getKey(fakeSecret, t), getKey(namespace, t))
}

func TestRemovesConfigMapInNamespaceWithoutLabel(t *testing.T) {
	t.Skip("Not finished")
	f := newFixture(t)

	secretValue := map[string]string{
		"caCert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM5akNDQWQ2Z0F3SUJBZ0lRSmFUeUxENnVPM0lYOERKZlZhZ1NtekFOQmdrcWhraUc5dzBCQVFzRkFEQVYKTVJNd0VRWURWUVFERXdwemRtTXRZMkYwTFdOaE1CNFhEVEl3TURNeE9URTBOREV5T1ZvWERUTXdNRE14TnpFMApOREV5T1Zvd0ZURVRNQkVHQTFVRUF4TUtjM1pqTFdOaGRDMWpZVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFECmdnRVBBRENDQVFvQ2dnRUJBTVFFdFRZUG5FSnFoMXc4NFI5MWV0Nng1MFB3NEVZNFpjOUhHRW5KRW1UdEVSOVUKTG44MGg3MUwwdnJUOXpUcTVhZFlsOWRhaDB5T2JJUU1aMU5VYmdPanQvczJnUHNRaFU5QVZPbmNqWG1OK0x2eQo5Q0I4NEFiY1A0U0NLV1pSQWd1NVhQdGlsUlNYbG9NTGxLUU52TWZ2QkpDWlhvcS9pVWZXcmxQOWp1dHQ2V0luCjdKUWxXUmRhdENYby9sWDZ0cFgydy8vMU1XZTN1R1lKcWNyUFlVN2c5N1NjdWJEZCtBanE4RSs2S0FqU3AzVnQKUTU5enpKenRFczNJaVBUU0szbXlrSVNXUWdlSEVUZ3F0cFJiaVdHOW0xdDBDc3FVRVBmMjhIayt4VHVVOWFBeQpZclVhbFkrSmxxc2hybUVLdUsxL2NMMU8zZU95aHRXT2R2SndYNThDQXdFQUFhTkNNRUF3RGdZRFZSMFBBUUgvCkJBUURBZ0trTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQVBCZ05WSFJNQkFmOEUKQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUF0eHp1alVIa3c1VmJyczFNcWl6Vkd2dk9sdVZSQgpzb1NPb3BuakZVdHkyYjV6OUltcHdDeEMwWmppNFVVdVdrMTJHZGxldlE0dTdvbmV5VytZR25qeDNRY1FGQ2plCmpTeU1uM2xsWnpFcVFyLzNpWDVBRUp4NFZDZ3lmNmtiVmdmbnp2aXVrWm83NjUwTCt0V0xiK2JNWllDZ0h1a3YKVi9SNlBxSGdzZDZiSlV4U1lMWElFamtCK0x5cXlSM2RvZDRDNUhpK2dRd0dsK0EyWVd4R0p0SDZVOExYVldYLwpKSDIvUXVIU09uUm9QeVV4MVduUDV6M1NHYWZyR1ZrbVJwTW56UWk3YjFFeTJMQVlENGhCRlJXZSt0bWR3NjRRCmJMbUYwRU85cVVKQjg2bE1LN2pvVUk2TFc5ajF6SWVUREZRN0ZZOUY2VEJiNmZoNVFNak1YdVhYCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
	}

	fakeSecret := createNewSecret("azure-key-vault-env-injector", "akv2k8s", secretValue)
	namespace := createNewNamespace("akv2k8s-test", false)
	existingConfigMap := newConfigMap("akv2k8s-ca", namespace.Name, fakeSecret)

	f.secretLister = append(f.secretLister, fakeSecret)
	f.namespaceLister = append(f.namespaceLister, namespace)
	f.configMapLister = append(f.configMapLister, existingConfigMap)

	f.kubeobjects = append(f.kubeobjects, existingConfigMap)

	f.expectRemoveConfigMapAction(existingConfigMap)

	f.run(getKey(fakeSecret, t), getKey(namespace, t))
}
