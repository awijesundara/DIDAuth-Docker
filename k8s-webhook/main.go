package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type verifyResp struct {
	Valid bool `json:"valid"`
}

type verifyReq struct {
	ManifestDigest  string `json:"manifest_digest"`
	ContractAddress string `json:"contract_address"`
	VCCid           string `json:"vc_cid"`
}

// httpClient bounds how long a single verification call may take. Without a
// timeout, an unresponsive issuer-api would hang the admission request
// indefinitely; the API server's own webhook timeout would eventually fail
// the request, but a local timeout lets us fail fast and produces a clearer
// error message.
var httpClient = &http.Client{Timeout: 5 * time.Second}

func verify(vcCID, digest, contract string) (bool, error) {
	url := os.Getenv("VERIFIER_URL")
	// Build the request body with encoding/json rather than string
	// formatting: pod annotations are attacker-controlled (any user who can
	// create a pod controls them), so naively interpolating them into a
	// JSON string literal would let a value containing a `"` inject
	// arbitrary fields into the verifier request.
	body, err := json.Marshal(verifyReq{ManifestDigest: digest, ContractAddress: contract, VCCid: vcCID})
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
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
