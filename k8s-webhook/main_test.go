package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDigestFromReference(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := digestFromReference("registry.example/app@" + digest)
	if err != nil || got != digest {
		t.Fatalf("expected pinned digest, got %q (%v)", got, err)
	}
	for _, invalid := range []string{"registry.example/app:latest", "app@sha256:short", "app@sha512:0123"} {
		if _, err := digestFromReference(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}

func TestPodImagesIncludesEveryContainerClass(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers:      []corev1.Container{{Name: "init", Image: "init@sha256:x"}},
		Containers:          []corev1.Container{{Name: "app", Image: "app@sha256:x"}},
		EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "debug@sha256:x"}}},
	}}
	if got := len(podImages(pod)); got != 3 {
		t.Fatalf("expected 3 images, got %d", got)
	}
}

func TestCredentialCIDIsContainerScoped(t *testing.T) {
	annotations := map[string]string{
		"cbc.provenance/vc":     "single",
		"cbc.provenance/vc-app": "scoped",
	}
	if got := credentialCID(annotations, "app", 2); got != "scoped" {
		t.Fatalf("expected scoped CID, got %q", got)
	}
	if got := credentialCID(annotations, "other", 2); got != "" {
		t.Fatalf("generic CID must not authorize one image in a multi-image Pod")
	}
}
