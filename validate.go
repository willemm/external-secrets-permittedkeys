package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil"

	admv1 "k8s.io/api/admission/v1"
	// "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
)

func validateHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		Log.Error(nil, "no request body", "req", req)
		http.Error(rw, "no request body", http.StatusBadRequest)
		return
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		Log.Error(err, "failed to read request body", "req", req)
		http.Error(rw, fmt.Sprintf("internal server error: %v", err), http.StatusInternalServerError)
		return
	}
	if len(body) == 0 {
		Log.Error(nil, "empty request body", "req", req)
		http.Error(rw, "empty request body", http.StatusBadRequest)
		rw.Write([]byte("Empty request body"))
		return
	}
	// Sanity check
	if req.URL.Path != "/validate" {
		Log.Error(nil, "invalid path", "path", req.URL.Path)
		http.Error(rw, "invalid path", http.StatusBadRequest)
	}
	Log.Info("got validation request", "req", req)

	ar := admv1.AdmissionReview{}
	if err := json.Unmarshal(body, &ar); err != nil {
		Log.Error(err, "failed to parse body")
		http.Error(rw, fmt.Sprintf("failed to parse body: %v", err), http.StatusBadRequest)
		return
	}

	es := esv1alpha1.ExternalSecret{}
	if err := json.Unmarshal(ar.Request.Object.Raw, &es); err != nil {
		Log.Error(err, "failed to unmarshal externalsecret from request")
		http.Error(rw, fmt.Sprintf("failed to parse externalsecret: %v", err), http.StatusBadRequest)
		return
	}
	result := admv1.AdmissionReview{
		Response: &admv1.AdmissionResponse{
			Allowed: true,
			Result: &metav1.Status {
				Message: "",
			},
		},
	}
	for _, s := range es.Spec.Data {
		Log.Info("TODO check if remoteRef is allowed", "s", s, "remoteRef", s.RemoteRef.Key)
	}
	resp, err := json.Marshal(result)
	if err != nil {
		Log.Error(err, "failed to encode response", "result", result)
		http.Error(rw, fmt.Sprintf("failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := rw.Write(resp); err != nil {
		Log.Error(err, "failed to write response", "result", result)
		http.Error(rw, fmt.Sprintf("failed to write response: %v", err), http.StatusInternalServerError)
		return
	}
}
