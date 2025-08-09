package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type verifyResp struct {
	Valid bool `json:"valid"`
}

func verify(vcCID, digest, contract string) (bool, error) {
	url := os.Getenv("VERIFIER_URL")
	payload := fmt.Sprintf(`{"manifest_digest":"%s","contract_address":"%s","vc_cid":"%s"}`, digest, contract, vcCID)
	resp, err := http.Post(url, "application/json", io.NopCloser(strings.NewReader(payload)))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out verifyResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Valid, nil
}

func admit(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pod := corev1.Pod{}
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ann := pod.Annotations
	vcCID := ann["vc.cid"]
	digest := ann["vc.manifestDigest"]
	contract := ann["vc.contractAddress"]
	ok, err := verify(vcCID, digest, contract)
	allow := ok && err == nil
	var message string
	if err != nil {
		message = err.Error()
	}
	response := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: review.APIVersion, Kind: review.Kind},
		Response: &admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: allow,
			Result:  &metav1.Status{Message: message},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/validate", admit)
	log.Fatal(http.ListenAndServeTLS(":8443", "/tls/tls.crt", "/tls/tls.key", nil))
}
