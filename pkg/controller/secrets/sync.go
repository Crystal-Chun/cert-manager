package secrets

import (
	"context"
	"k8s.io/klog"
	
	corev1 "k8s.io/api/core/v1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	
)

func (c *Controller) Sync(ctx context.Context, secret *corev1.Secret) {
	klog.Infof("%v", secret)
	namespace := secret.ObjectMeta.Namespace
	// Figure out if certificate has associated cert manager certificate
	crtName := secret.Labels[v1alpha1.CertificateNameKey]
	crt, _ := c.certificateLister().Certificate(namespace).Get(crtName)
	if crtName == nil || crt == nil {
		klog.Info("Associated cert manager cert does not exist with this secret")
		// Decode the certificate in the secret
		//x509crt := kube.SecretTLSCertName(c.secretLister, namespace, secret.ObjectMeta.Name, )
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
	}
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// "github.com/jetstack/cert-manager/pkg/util/kube"
}
