package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"

	// corev1 "k8s.io/api/core/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"regexp"
)

var (
	kube = getClient()
)

func getClient() corev1client.CoreV1Interface {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return clientset.CoreV1()
}

func validateHandler(rw http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if req.Body == nil {
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
	namespace := es.ObjectMeta.Namespace
	ns, err := kube.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		Log.Error(err, "failed to get namespace", "namespace", namespace)
		http.Error(rw, fmt.Sprintf("failed to get namespace %s: %v", namespace, err), http.StatusInternalServerError)
		return
	}
	allowed := true
	message := ""
	nspatt, ok := ns.ObjectMeta.Annotations["externalsecrets.kubernetes-client.io/permitted-key-name"]
	if ok {
		for _, s := range es.Spec.Data {
			matched, err := regexp.MatchString(nspatt, s.RemoteRef.Key)
			if err != nil {
				Log.Error(err, "failed to parse match pattern", "pattern", nspatt)
				http.Error(rw, fmt.Sprintf("failed to parse match pattern %s: %v", nspatt, err), http.StatusInternalServerError)
				return
			}
			if !matched {
				allowed = false
				message = message + fmt.Sprintf("key %s does not match pattern %s\n", s.RemoteRef.Key, nspatt)
			}
		}
	}
	result := admv1.AdmissionReview{
		Response: &admv1.AdmissionResponse{
			UID:     ar.Request.UID,
			Allowed: allowed,
			Result: &metav1.Status{
				Message: message,
			},
		},
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
