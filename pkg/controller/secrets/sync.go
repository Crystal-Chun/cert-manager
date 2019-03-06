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
		klog.Infof("Cert length: %d", len(x509crt))
		klog.Infof("The certificate: %v", x509crt[0])
		klog.Infof("Not Before: %s", x509crt[0].NotBefore.String())
		klog.Infof("Not After: %s", x509crt[0].NotAfter.String())
		klog.Info("IsCa: ", x509crt[0].IsCA)
		klog.Info("DNS Names: ", x509crt[0].DNSNames)
		klog.Infof("The namespace: %s", namespace)
		klog.Info("EmailAddresses ", x509crt[0].EmailAddresses)
		klog.Info("IP Addresses: ", x509crt[0].IPAddresses)
		klog.Info("Issuer: ", x509crt[0].Issuer)
		klog.Info("Subject: ", x509crt[0].Subject)
		/* Info for certificate needed
		- Cert spec
			- duration/expiration: notBefore, notAfter
			- Issuer reference
			- Common Name
			- dns names
			- isCA - need to verify that both isCa and basicConstraintsvalid is true
			- keyAlgorithm -- opt
			- keySize -- opt
			- secretName
		- Cert status 
			- Condition
			- notAfter - expiration of cert stored in secret 
		- ObjectMeta
			- namespace 
			- name
		*/
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
