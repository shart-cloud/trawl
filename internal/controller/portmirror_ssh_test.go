package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/status"
)

func TestSSHDeviceSecretUsesPinnedHostKeyAndPrivateKey(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "switch", Namespace: "trawl-system"},
		Data: map[string][]byte{
			"address": []byte("192.0.2.10"), "username": []byte("monitor"),
			"sshHostKey": []byte("pinned-key"), "sshPrivateKey": []byte("private-key"),
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	reconciler := &PortMirrorReconciler{Client: client, APIReader: client}
	mirror := &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{Namespace: "trawl-system"},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7SSH,
			DeviceRef: corev1.LocalObjectReference{Name: "switch"},
		},
	}
	device, err := reconciler.device(context.Background(), mirror)
	if err != nil {
		t.Fatal(err)
	}
	if device.Address != "192.0.2.10" || device.Username != "monitor" ||
		string(device.SSHHostKey) != "pinned-key" || string(device.SSHPrivateKey) != "private-key" {
		t.Fatalf("SSH credentials were not passed to the provider")
	}
	delete(secret.Data, "sshHostKey")
	if err := client.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.device(context.Background(), mirror); err == nil {
		t.Fatal("SSH mirror accepted a Secret without a pinned host key")
	}
}

func TestMirrorDeviceFailuresKeepTheirSpecificReasons(t *testing.T) {
	if got := deviceFailureReason(fabric.ErrUnsupportedDevice); got != status.ReasonDeviceUnsupported {
		t.Fatalf("unsupported reason = %q", got)
	}
	if got := deviceFailureReason(fabric.ErrUntrustedDevice); got != status.ReasonDeviceUntrusted {
		t.Fatalf("untrusted reason = %q", got)
	}
	if got := deviceConfigureReason(fabric.ErrUnsupportedDevice); got != status.ReasonDeviceUnsupported {
		t.Fatalf("unsupported configure reason = %q", got)
	}
}
