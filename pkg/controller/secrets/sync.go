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
	"k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	
)

const (
	createCertificate	 	= 	"create-certificate"
	certificateName			= 	"certificate-name"
)

func (c *Controller) Sync(ctx context.Context, secret *corev1.Secret) error {
	namespace := secret.ObjectMeta.Namespace
	certManagerCert := secret.Labels[v1alpha1.CertificateNameKey]
	existingCertificate, _ := c.certificateLister.Certificates(namespace).Get(certManagerCert)

	createLabel := secret.Labels[createCertificate]

	// If a cert manager Certificate doesn't exist and the label exists, create a cert-manager Certificate from this secret
	if existingCertificate == nil && createLabel == "installer" {
		klog.V(4).Info("Creating cert-manager Certificate for installer-based certificate")
		
		cert, err := getCertificate(c.secretLister, ctx, secret)
		if err != nil {
			klog.Infof("Error occurred: %s", err)
			return nil
		}
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
		
		// Check for ipaddresses here
		ips := make([]string, 0)
		if len(cert.IPAddresses) > 0 {
			klog.Infof("Length of IP addresses: %d", len(cert.IPAddresses))
			for _, ipAddress := range cert.IPAddresses {
				klog.Info("IP: %s", ipAddress.String())
				ips = append(ips, ipAddress.String())
			}
		}
		ips = removeDuplicates(ips)
		
		keyAlgorithm, _ := getKeyAlgorithm(cert)

		key, _ := kube.SecretTLSKeyRef(c.secretLister, namespace, secretName, "tls.key")

		klog.Infof("The key size from size func: %d", key.Public().(*rsa.PublicKey).Size())
		publicKeySize := key.Public().(*rsa.PublicKey).Size()
		keySize, err := determineKeySize(publicKeySize, keyAlgorithm)
		if err != nil {
			klog.Info(err)
			return nil
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
				IPAddresses: ips,
				IsCA: isCA,
				SecretName: secretName,
				IssuerRef: v1alpha1.ObjectReference {
					Kind: "ClusterIssuer",
					Name: "icp-ca-issuer",
				},
				KeyAlgorithm: keyAlgorithm,
				KeySize: keySize,
				Duration: durationObject,
			},
		}
		
		c.CMClient.CertmanagerV1alpha1().Certificates(namespace).Create(crt)
		klog.Infof("Created the certificate object: %v", crt)

		updateSecret(c.Client.CoreV1().Secrets(namespace), crt, secret)
		return nil
	}
	return nil
}

// Gets the certificate from the secret
func getCertificate(secretLister corelisters.SecretLister, ctx context.Context, secret *corev1.Secret) (*x509.Certificate, error) {
	cert, err := kube.SecretTLSCert(secretLister, secret.ObjectMeta.Namespace, secret.ObjectMeta.Name)

	if err != nil {
		klog.Infof("Error occurred getting the certificate from the secret: %v", err)
		return nil, fmt.Errorf("Error occurred getting the certificate from the secret: %v", err)
	}

	/*if len(certificates) < 1 {
		errMsg := "Error, couldn't get at least one certificate from secret."
		klog.Info(errMsg)
		return nil, fmt.Errorf("%s", errMsg)
	}*/
	 
	return cert, nil
}

// Check if there's a validation function for this
func getKeyAlgorithm(cert *x509.Certificate) (v1alpha1.KeyAlgorithm, error) {
	keyAlgorithm := cert.PublicKeyAlgorithm.String()
	var cmKeyAlgorithm v1alpha1.KeyAlgorithm
	if keyAlgorithm == "rsa" || keyAlgorithm == "RSA" {
		cmKeyAlgorithm = v1alpha1.RSAKeyAlgorithm
	} else if keyAlgorithm == "ecdsa" || keyAlgorithm == "ECDSA" {
		cmKeyAlgorithm = v1alpha1.ECDSAKeyAlgorithm
	} else {
		klog.Infof("Invalid key algorithm %s", keyAlgorithm)
		// what to return here?
		return v1alpha1.RSAKeyAlgorithm, fmt.Errorf("Invalid key algorithm %s", keyAlgorithm)
	}
	return cmKeyAlgorithm, nil
}

func updateSecret(secrets v1.SecretInterface, crt *v1alpha1.Certificate, secret *corev1.Secret) {
	// Update secret metadata
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[v1alpha1.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	secret.Annotations[v1alpha1.IssuerKindAnnotationKey] = crt.Spec.IssuerRef.Kind
	secret.Annotations[v1alpha1.CommonNameAnnotationKey] = crt.Spec.CommonName
	secret.Annotations[v1alpha1.AltNamesAnnotationKey] = strings.Join(crt.Spec.DNSNames, ",")
	secret.Annotations[v1alpha1.IPSANAnnotationKey] = strings.Join(crt.Spec.IPAddresses, ",")

	// Always set the certificate name label on the target secret
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	secret.Labels[v1alpha1.CertificateNameKey] = crt.Name
	secrets.Update(secret)
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

func determineKeySize(n int, algo v1alpha1.KeyAlgorithm) (int, error) {
	var keySize int
	switch algo {
	case v1alpha1.RSAKeyAlgorithm:
		switch n {
		case 512:
			keySize = 4096
		case 384: // Unable to match this right now 
			keySize = 3072
		case 256:
			keySize = 2048
		default:
			return 0, fmt.Errorf("No key size available for unsupported signature algorithm: %d", n)
		}
	case v1alpha1.ECDSAKeyAlgorithm: // not tested
		switch n {
		case 521, 384, 256:
			keySize = n
		default:
			return 0, fmt.Errorf("No key size available for unsupported signature algorithm: %d", n)
		}
	}
	return keySize, nil
}
