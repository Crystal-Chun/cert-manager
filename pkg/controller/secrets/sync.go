package secrets

import (
	"context"
	"k8s.io/klog"
	"time"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	
)

const (
	createCertificate	 	= 	"create-certificate"
	certificateName			= 	"certificate-name"
	certificateKeyName 		= 	"certificate-key"
)

func (c *Controller) Sync(ctx context.Context, secret *corev1.Secret) error {
	namespace := secret.ObjectMeta.Namespace
	certManagerCert := secret.Labels[v1alpha1.CertificateNameKey]
	existingCertificate, _ := c.certificateLister.Certificates(namespace).Get(certManagerCert)

	createLabel := secret.Labels[createCertificate]

	// If a cert manager Certificate doesn't exist and the label exists, create a cert-manager Certificate from this secret
	if existingCertificate == nil && createLabel == "installer" {
		klog.Info("Creating cert-manager Certificate for installer-based certificate")
		
		keyName := secret.Labels[certificateKeyName]
		
		// Get the certificates in the secret
		certificates, error := kube.SecretTLSCertName(c.secretLister, namespace, secret.ObjectMeta.Name, keyName)
		klog.Infof("Cert length: %d", len(certificates))

		if error != nil {
			klog.Infof("Error occurred getting the certificate from the secret: %v", error)
			return nil
		}
		// Fail here if cert length less than 1? 
		cert := certificates[0]
		// Get values for the cert-manager certificate object.
		secretName := secret.ObjectMeta.Name

		certName := secret.Labels[certificateName]
		if certName == "" {
			certName = secretName
		}

		commonName := cert.Subject.CommonName
		isCA := cert.IsCA

		duration := cert.NotAfter.Sub(time.Now())
		
		durationObject := &metav1.Duration {
			Duration: duration,
		}
		// Check duration less than one hour and duration less than renewBefore - check if validation func already exists

		// Check if there's a validation function for this
		keyAlgorithm := cert.PublicKeyAlgorithm.String()
		var cmKeyAlgorithm v1alpha1.KeyAlgorithm
		if keyAlgorithm == "rsa" || keyAlgorithm == "RSA" {
			cmKeyAlgorithm = v1alpha1.RSAKeyAlgorithm
		} else if keyAlgorithm == "ecdsa" || keyAlgorithm == "ECDSA" {
			cmKeyAlgorithm = v1alpha1.ECDSAKeyAlgorithm
		} else {
			klog.Infof("Invalid key algorithm %s", keyAlgorithm)
			return nil
		}

		// I'm confused, are all SANS also DNSNames?
		dnsNames := make([]string, 0)
		if commonName != "" {
			dnsNames = append(dnsNames, commonName)
		}

		if len(cert.DNSNames) > 0 {
			for _, dnsName := range cert.DNSNames {
				klog.Info("Dns name: %s", dnsName)
				dnsNames = append(dnsNames, dnsName)
			}
		} else {
			// The certificate doesn't have any dns names, so append the common name at least
			for _, dnsName := range dnsNames {
				cert.DNSNames = append(cert.DNSNames, dnsName)
			}
			certificates[0].DNSNames = cert.DNSNames
			secret.Data[keyName], _ = append(pki.EncodeX509(certificates[0]), pki.EncodeX509Chain(certificates)...)
			c.Client.CoreV1().Secrets(namespace).Update(secret)
		}

		// Create the certificate object.
		crt := &v1alpha1.Certificate {
			ObjectMeta: metav1.ObjectMeta {
				Name: certName,
				Namespace: namespace,
			},
			Spec: v1alpha1.CertificateSpec {
				CommonName: commonName,
				DNSNames: dnsNames,
				IsCA: isCA,
				SecretName: secretName,
				IssuerRef: v1alpha1.ObjectReference {
					Kind: "ClusterIssuer",
					Name: "icp-ca-issuer",
				},
				KeyAlgorithm: cmKeyAlgorithm,
				Duration: durationObject,
			},
		}
		
		c.CMClient.CertmanagerV1alpha1().Certificates(namespace).Create(crt)
		klog.Infof("Created the certificate object: %v", crt)

		return nil
	}
	return nil
}
