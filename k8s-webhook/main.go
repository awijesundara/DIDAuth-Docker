package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type verifyResponse struct {
	Valid bool `json:"valid"`
}
type verifyRequest struct {
	ManifestDigest string `json:"manifest_digest"`
	VCCID          string `json:"vc_cid"`
}
type imageCandidate struct{ name, reference string }

var httpClient = &http.Client{Timeout: 5 * time.Second}

func verify(vcCID, digest string) (bool, error) {
	endpoint := os.Getenv("VERIFIER_URL")
	if endpoint == "" {
		return false, fmt.Errorf("VERIFIER_URL is not configured")
	}
	body, err := json.Marshal(verifyRequest{ManifestDigest: digest, VCCID: vcCID})
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("verifier returned HTTP %d", resp.StatusCode)
	}
	var result verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Valid, nil
}

func digestFromReference(reference string) (string, error) {
	parts := strings.Split(reference, "@")
	if len(parts) != 2 || !strings.HasPrefix(parts[1], "sha256:") || len(parts[1]) != 71 {
		return "", fmt.Errorf("image must be pinned as name@sha256:<64 hex characters>")
	}
	return parts[1], nil
}

func podImages(pod *corev1.Pod) []imageCandidate {
	images := make([]imageCandidate, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	for _, c := range pod.Spec.InitContainers {
		images = append(images, imageCandidate{c.Name, c.Image})
	}
	for _, c := range pod.Spec.Containers {
		images = append(images, imageCandidate{c.Name, c.Image})
	}
	for _, c := range pod.Spec.EphemeralContainers {
		images = append(images, imageCandidate{c.Name, c.Image})
	}
	return images
}

func credentialCID(annotations map[string]string, name string, total int) string {
	if cid := annotations["cbc.provenance/vc-"+name]; cid != "" {
		return cid
	}
	if total == 1 {
		return annotations["cbc.provenance/vc"]
	}
	return ""
}

func admissionResult(review *admissionv1.AdmissionReview, allowed bool, message string) admissionv1.AdmissionReview {
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: review.APIVersion, Kind: review.Kind},
		Response: &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: allowed, Result: &metav1.Status{Message: message}},
	}
}

func admit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
		return
	}
	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		json.NewEncoder(w).Encode(admissionResult(&review, false, "cannot decode Pod: "+err.Error()))
		return
	}
	images := podImages(&pod)
	if len(images) == 0 {
		json.NewEncoder(w).Encode(admissionResult(&review, false, "Pod contains no images"))
		return
	}
	for _, image := range images {
		digest, err := digestFromReference(image.reference)
		if err != nil {
			json.NewEncoder(w).Encode(admissionResult(&review, false, image.name+": "+err.Error()))
			return
		}
		cid := credentialCID(pod.Annotations, image.name, len(images))
		if cid == "" {
			json.NewEncoder(w).Encode(admissionResult(&review, false, image.name+": missing credential CID annotation"))
			return
		}
		valid, err := verify(cid, digest)
		if err != nil || !valid {
			if err == nil {
				err = fmt.Errorf("credential is not valid")
			}
			json.NewEncoder(w).Encode(admissionResult(&review, false, image.name+": "+err.Error()))
			return
		}
	}
	json.NewEncoder(w).Encode(admissionResult(&review, true, "all container image credentials are valid"))
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	http.HandleFunc("/validate", admit)
	http.HandleFunc("/health", health)
	server := &http.Server{
		Addr: ":8443", Handler: nil,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
	log.Fatal(server.ListenAndServeTLS("/tls/tls.crt", "/tls/tls.key"))
}
