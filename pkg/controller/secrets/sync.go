package secrets

import (
	"context"
	"k8s.io/klog"
	
	corev1 "k8s.io/api/core/v1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	
)

func (c *Controller) Sync(ctx context.Context, secret *corev1.Secret) error {
	klog.Infof("%v", secret.Data)
	namespace := secret.ObjectMeta.Namespace
	// Figure out if certificate has associated cert manager certificate
	crtName := secret.Labels[v1alpha1.CertificateNameKey]
	crt, _ := c.certificateLister.Certificates(namespace).Get(crtName)
	if crt == nil {
		klog.Info("Associated cert manager cert does not exist with this secret")
		// Decode the certificate in the secret
		x509crt, error := kube.SecretTLSCertName(c.secretLister, namespace, secret.ObjectMeta.Name, "tls.crt")
		if error != nil {
			klog.Infof("Error occurred: %v", error)
			return nil
		}
		klog.Infof("The certificate: %v", x509crt[0])
		// Create the cert manager certificate
		/*crt = &v1alpha1.Certificate{
			TypeMeta: metav1.TypeMeta
			ObjectMeta: metav1.ObjectMeta{
				Name: 
				Namespace: namespace,
			},
			Spec: v1alpha1.CertificateSpec{
				SecretName: secret.ObjectMeta.Name
			},
			Status: v1alpha1.CertificateStatus{

			}
		}*/
		return nil
	}
	return nil
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// 
}
