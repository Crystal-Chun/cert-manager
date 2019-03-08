package secrets

import (
	"context"
	"k8s.io/klog"
	"time"
	"strings"
	"crypto/x509"
	"crypto/rsa"
	"fmt"
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
			klog.Info("Length of dns names: ", len(cert.DNSNames))
			
			for _, dnsName := range cert.DNSNames {
				klog.Info("Dns name: %s", dnsName)
				dnsNames = append(dnsNames, dnsName)
			}
		} 

		dnsNames = removeDuplicates(dnsNames)
		keySize, err := determineKeySize(cert.SignatureAlgorithm, cmKeyAlgorithm)
		if err != nil {
			klog.Info(err)
			return nil
		}
		key, _ := kube.SecretTLSKeyRef(c.secretLister, namespace, secretName, "tls.key")
		//key = rsa.PrivateKey(key)
		key = key.(rsa.PublicKey)
		//klog.Infof("Private key: %v", key)
		klog.Infof("Public key: %v", key)
		klog.Infof("The potential key size: %v", key.N)
		klog.Infof("The key size from size func: %d", key.Size())
		/*klog.Infof("Public key: %v", key.Public())
		klog.Infof("The potential key size: %v", key.Public().N)
		klog.Infof("The key size from size func: %d", key.Public().Size())*/
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
				KeySize: keySize,
				Duration: durationObject,
			},
		}
		
		c.CMClient.CertmanagerV1alpha1().Certificates(namespace).Create(crt)
		klog.Infof("Created the certificate object: %v", crt)

		// Update secret metadata
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations[v1alpha1.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
		secret.Annotations[v1alpha1.IssuerKindAnnotationKey] = crt.Spec.IssuerRef.Kind
		secret.Annotations[v1alpha1.CommonNameAnnotationKey] = cert.Subject.CommonName
		secret.Annotations[v1alpha1.AltNamesAnnotationKey] = strings.Join(cert.DNSNames, ",")
		secret.Annotations[v1alpha1.IPSANAnnotationKey] = strings.Join(pki.IPAddressesToString(cert.IPAddresses), ",")

		// Always set the certificate name label on the target secret
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels[v1alpha1.CertificateNameKey] = crt.Name
		c.Client.CoreV1().Secrets(namespace).Update(secret)
		return nil
	}
	return nil
}

func removeDuplicates(in []string) []string {
	var found []string
Outer:
	for _, i := range in {
		for _, i2 := range found {
			if i2 == i {
				continue Outer
			}
		}
		found = append(found, i)
	}
	return found
}

func determineKeySize(sigAlgo x509.SignatureAlgorithm, algo v1alpha1.KeyAlgorithm) (int, error) {
	var keySize int
	switch algo {
	case v1alpha1.RSAKeyAlgorithm:
		switch sigAlgo {
		case x509.SHA512WithRSA:
			keySize = 4096
		case x509.SHA384WithRSA:
			keySize = 3072
		case x509.SHA256WithRSA:
			keySize = 2048
		default:
			return 0, fmt.Errorf("No key size available for unsupported signature algorithm: %s", sigAlgo.String())
		}
	case v1alpha1.ECDSAKeyAlgorithm:
		switch sigAlgo {
		case x509.ECDSAWithSHA512:
			keySize = 512
		case x509.ECDSAWithSHA384:
			keySize = 384
		case x509.ECDSAWithSHA256:
			keySize = 256
		default:
			return 0, fmt.Errorf("No key size available for unsupported signature algorithm: %s", sigAlgo.String())
		}
	}
	return keySize, nil
}