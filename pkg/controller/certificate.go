/*
Copyright The KubeDB Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package controller

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"

	"github.com/appscode/go/log"
	cm_api "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/pkg/errors"
	"gomodules.xyz/cert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Controller) manageTLS(mongodb *api.MongoDB) error {
	if mongodb.Spec.TLS == nil {
		return nil
	}

	if mongodb.Spec.TLS.IssuerRef.Kind == cm_api.IssuerKind {
		_, err := c.CertManagerClient.CertmanagerV1alpha2().Issuers(mongodb.Namespace).Get(mongodb.Spec.TLS.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Infoln(err)
			return err
		}
	} else if mongodb.Spec.TLS.IssuerRef.Kind == cm_api.ClusterIssuerKind {
		_, err := c.CertManagerClient.CertmanagerV1alpha2().ClusterIssuers().Get(mongodb.Spec.TLS.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			log.Infoln(err)
			return err
		}
	} else {
		return errors.New("mongodb.Spec.TLS.Client.IssuerRef.Kind must be either Issuer or ClusterIssuer")
	}

	if mongodb.Spec.ReplicaSet == nil && mongodb.Spec.ShardTopology == nil {
		// Standalone server
		if err := c.manageStandaloneServerCert(mongodb); err != nil {
			log.Infoln(err)
			return err
		}
	} else if mongodb.Spec.ReplicaSet != nil && mongodb.Spec.ShardTopology == nil {
		// ReplicaSet server
		if err := c.manageCertSecretForReplicaSet(mongodb); err != nil {
			log.Infoln(err)
			return err
		}
	} else if mongodb.Spec.ShardTopology != nil {
		// Shard Topology
		if err := c.manageCertSecretsForShard(mongodb); err != nil {
			log.Infoln(err)
			return err
		}
	}
	// for stash/user
	if err := c.manageExternalClientCert(mongodb); err != nil {
		log.Infoln(err)
		return err
	}
	// for prometheus exporter
	if err := c.manageExporterClientCert(mongodb); err != nil {
		log.Infoln(err)
		return err
	}

	return nil
}

// createCaCertificate returns generated caKey, caCert, err in order.
func createCaCertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	cfg := cert.Config{
		CommonName:   "ca",
		Organization: []string{"kubedb:ca"},
	}

	caKey, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.New("failed to generate key for CA certificate")
	}

	caCert, err := cert.NewSelfSignedCACert(cfg, caKey)
	if err != nil {
		return nil, nil, errors.New("failed to generate CA certificate")
	}

	//caKeyByte := cert.EncodePrivateKeyPEM(caKey)
	//caCertByte := cert.EncodeCertPEM(caCert)

	return caKey, caCert, nil
}

// createPEMCertificate returns generated Key, Cert, err in order.
func createPEMCertificate(caKey *rsa.PrivateKey, caCert *x509.Certificate, cfg cert.Config) ([]byte, error) {
	privateKey, err := cert.NewPrivateKey()
	if err != nil {
		return nil, errors.New("failed to generate key for client certificate")
	}

	certificate, err := cert.NewSignedCert(cfg, privateKey, caCert, caKey)
	if err != nil {
		return nil, errors.New("failed to sign client certificate")
	}

	keyBytes := cert.EncodePrivateKeyPEM(privateKey)
	certBytes := cert.EncodeCertPEM(certificate)
	pemBytes := append(certBytes, keyBytes...)

	return pemBytes, nil
}

// createServerPEMCertificate returns generated Key, Cert, err in order.
// xref: https://docs.mongodb.com/manual/core/security-x.509/#member-x-509-certificates
func createServerPEMCertificate(mongodb *api.MongoDB, caKey *rsa.PrivateKey, caCert *x509.Certificate) ([]byte, error) {
	cfg := cert.Config{
		CommonName:   mongodb.OffshootName(),
		Organization: []string{"kubedb:server"},
		AltNames: cert.AltNames{
			DNSNames: []string{
				"localhost",
				fmt.Sprintf("%v.%v.svc", mongodb.OffshootName(), mongodb.Namespace),
				mongodb.OffshootName(),
				mongodb.ServiceName(),
			},
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	return createPEMCertificate(caKey, caCert, cfg)
}

// createPEMCertificate returns generated Key, Cert, err in order.
// xref: https://docs.mongodb.com/manual/tutorial/configure-x509-client-authentication/
func createClientPEMCertificate(mongodb *api.MongoDB, caKey *rsa.PrivateKey, caCert *x509.Certificate) ([]byte, error) {
	cfg := cert.Config{
		CommonName:   "root",
		Organization: []string{"kubedb:client"},
		AltNames: cert.AltNames{
			DNSNames: []string{
				"localhost",
				fmt.Sprintf("%v.%v.svc", mongodb.OffshootName(), mongodb.Namespace),
				mongodb.OffshootName(),
				mongodb.ServiceName(),
			},
			IPs: []net.IP{net.ParseIP("127.0.0.1")},
		},
		Usages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	return createPEMCertificate(caKey, caCert, cfg)
}
