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
	"fmt"
	"kubedb.dev/apimachinery/apis/catalog/v1alpha1"
	"strings"
	"time"

	api "kubedb.dev/apimachinery/apis/kubedb/v1alpha1"

	"github.com/appscode/go/log"
	cm_api "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	core "k8s.io/api/core/v1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	cm_util "kmodules.xyz/cert-manager-util/certmanager/v1alpha2"
	kutil "kmodules.xyz/client-go"
	core_util "kmodules.xyz/client-go/core/v1"
	"gomodules.xyz/version"
)

const (
	ExternalClientSecretSuffix = "-client-cert"
	ExporterClientSecretSuffix = "-exporter-cert"
	ServerSecretSuffix         = "-server-cert"
	PEMSecretSuffix            = "-pem"
	ClientCertOrganization     = api.DatabaseNamePrefix + ":client"
	CertificateCN              = "root"
)

// Client certificate related codes
func (c *Controller) manageExternalClientCert(mongoDB *api.MongoDB) error {
	clientCertName := mongoDB.Name + ExternalClientSecretSuffix
	if err := c.ensureClientCert(mongoDB, clientCertName); err != nil {
		log.Infoln(err)
		return err
	}

	// create Client PEM secret
	generatedCertSecret := c.getSecretSpec(mongoDB, clientCertName)
	if _, err := c.createOrPatchPEMSecretFromCertSecret(mongoDB, generatedCertSecret.ObjectMeta, api.MongoClientFileName); err != nil {
		log.Infoln(err)
		return err
	}
	return nil
}

func (c *Controller) manageExporterClientCert(mongoDB *api.MongoDB) error {
	if err := c.ensureClientCert(mongoDB, mongoDB.Name+ExporterClientSecretSuffix); err != nil {
		log.Infoln(err)
		return err
	}
	return nil
}

func (c *Controller) ensureClientCert(mongoDB *api.MongoDB, certName string) error {
	certVerb, err := c.createOrPatchClientCert(mongoDB, certName)
	if err != nil {
		return err
	}

	if certVerb != kutil.VerbUnchanged {
		log.Infoln("external client-certificates ", certVerb)
	}

	// wait for certificate secret to be created
	generatedCertSecret := c.getSecretSpec(mongoDB, certName)
	err = c.getSecret(generatedCertSecret.ObjectMeta)
	if err != nil && kerr.IsNotFound(err) {
		//wait for  secret
		err = wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
			if !c.isMongoDBExist(mongoDB) {
				return true, fmt.Errorf("MongoDB %s/%s does not exist", mongoDB.Namespace, mongoDB.Name)
			}
			err := c.getSecret(generatedCertSecret.ObjectMeta)
			if err == nil {
				return true, nil
			} else if kerr.IsNotFound(err) {
				return false, nil
			}
			return true, err
		})
	}
	if err == nil {
		//set mongodb as the owner of the certificate-secret
		if err := c.AddOwnerReferenceToGeneratedSecret(mongoDB, generatedCertSecret.ObjectMeta); err != nil {
			log.Infoln(err)
			return err
		}
	}
	return err
}

func (c *Controller) createOrPatchClientCert(mongoDB *api.MongoDB, certName string) (kutil.VerbType, error) {
	cert := c.getCertSpec(mongoDB, certName, mongoDB.GvrSvcName(mongoDB.OffshootName()))
	cert.Spec.Organization = []string{ClientCertOrganization}
	ref := metav1.NewControllerRef(mongoDB, api.SchemeGroupVersion.WithKind(api.ResourceKindMongoDB))
	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)
	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})
	return vt, err
}

func (c *Controller) getCertSpec(mongoDB *api.MongoDB, certName string, gvrName string) cm_api.Certificate {
	return cm_api.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: mongoDB.GetNamespace(),
			Labels:    mongoDB.GetLabels(),
		},
		Spec: cm_api.CertificateSpec{
			CommonName:   CertificateCN, //not Service name
			Organization: []string{api.ResourceKindMongoDB},
			DNSNames: []string{
				api.LocalHost,
				mongoDB.Name,
				c.getServiceURL(mongoDB),
				certName,
				fmt.Sprintf("%v.%v", certName, mongoDB.GvrSvcName(gvrName)),
				fmt.Sprintf("%v.%v.%v.svc", certName, mongoDB.GvrSvcName(gvrName), mongoDB.Namespace),
				fmt.Sprintf("%v.%v.%v.svc.cluster.local", certName, mongoDB.GvrSvcName(gvrName), mongoDB.Namespace),
				fmt.Sprintf("%v.*", certName), //unnecessary
			},
			IPAddresses: []string{api.LocalHostIP},
			SecretName:  certName, //Secret where issued certificates will be saved
			IssuerRef: cmmeta.ObjectReference{
				Name: mongoDB.Spec.TLS.IssuerRef.Name,
				Kind: mongoDB.Spec.TLS.IssuerRef.Kind,
			},
			IsCA: false,
			Usages: []cm_api.KeyUsage{
				cm_api.UsageDigitalSignature,
				cm_api.UsageKeyEncipherment,
				cm_api.UsageClientAuth,
			},
		},
	}
}

// ReplicaSet Server Cert related codes
func (c *Controller) manageCertSecretForReplicaSet(mongoDB *api.MongoDB) error {
	for i := 0; i < int(*mongoDB.Spec.Replicas); i++ {
		if err := c.manageGenericCertificateSecret(mongoDB, fmt.Sprintf("%v-%d", mongoDB.Name, i), mongoDB.Name); err != nil {
			log.Infoln(err)
			return err
		}
	}
	return nil
}

// Sharded Server Cert related codes
func (c *Controller) manageCertSecretsForShard(mongoDB *api.MongoDB) error {
	// for config server
	for i := 0; i < int(mongoDB.Spec.ShardTopology.ConfigServer.Replicas); i++ {
		if err := c.manageGenericCertificateSecret(mongoDB, fmt.Sprintf("%v-%d", mongoDB.ConfigSvrNodeName(), i), mongoDB.ConfigSvrNodeName()); err != nil {
			log.Infoln(err)
			return err
		}
	}

	//for shards
	for i := 0; i < int(mongoDB.Spec.ShardTopology.Shard.Shards); i++ {
		shardName := mongoDB.ShardNodeName(int32(i))
		for j := 0; j < int(mongoDB.Spec.ShardTopology.Shard.Replicas); j++ {
			if err := c.manageGenericCertificateSecret(mongoDB, fmt.Sprintf("%v-%d", shardName, j), shardName); err != nil {
				log.Infoln(err)
				return err
			}
		}
	}
	//for mongos
	for i := 0; i < int(mongoDB.Spec.ShardTopology.Mongos.Replicas); i++ {
		if err := c.manageGenericCertificateSecret(mongoDB, fmt.Sprintf("%v-%d", mongoDB.MongosNodeName(), i), mongoDB.MongosNodeName()); err != nil {
			log.Infoln(err)
			return err
		}
	}

	return nil
}

//Common between replicas and shards
func (c *Controller) manageGenericCertificateSecret(mongoDB *api.MongoDB, certName string, gvrServiceName string) error {
	certVerb, err := c.ensureGenericCertificateSecret(mongoDB, certName, gvrServiceName)
	if err != nil {
		return err
	}

	if certVerb != kutil.VerbUnchanged {
		log.Infoln("certificate ", certName, " ", certVerb)
	}

	// wait for certificate secret to be created
	generatedCertSecretMeta := metav1.ObjectMeta{
		Name:      certName,
		Namespace: mongoDB.Namespace,
	}
	err = c.getSecret(generatedCertSecretMeta)
	if err != nil && kerr.IsNotFound(err) {
		//wait for  secret
		err = wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
			if !c.isMongoDBExist(mongoDB) {
				return true, fmt.Errorf("MongoDB %s/%s does not exist", mongoDB.Namespace, mongoDB.Name)
			}
			err := c.getSecret(generatedCertSecretMeta)
			if err == nil {
				return true, nil
			} else if kerr.IsNotFound(err) {
				return false, nil
			}
			return true, err
		})
	}
	if err == nil {
		//set mongodb as the owner of the certificate-secret
		if err := c.AddOwnerReferenceToGeneratedSecret(mongoDB, generatedCertSecretMeta); err != nil {
			log.Infoln(err)
			return err
		}
	}
	return nil
}

func (c *Controller) ensureGenericCertificateSecret(mongoDB *api.MongoDB, certName string, gvrServiceName string) (kutil.VerbType, error) {
	cert := c.getCertSpec(mongoDB, certName, gvrServiceName)
	cert.Spec.Usages = append(cert.Spec.Usages, cm_api.UsageServerAuth) //adding serverAuth (clientAuth already present) to make the cert generic
	cert.Spec.CommonName = certName
	ref := metav1.NewControllerRef(mongoDB, api.SchemeGroupVersion.WithKind(api.ResourceKindMongoDB))
	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)
	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})
	return vt, err
}

//Standalone server cert related codes
func (c *Controller) manageStandaloneServerCert(mongoDB *api.MongoDB) error {
	certVerb, err := c.ensureStandaloneServerCert(mongoDB)
	if err != nil {
		return err
	}

	if certVerb != kutil.VerbUnchanged {
		log.Infoln("standalone server-certificates ", certVerb)
	}
	// wait for certificate secret to be created
	generatedCertSecret := c.getSecretSpec(mongoDB, mongoDB.Name+ServerSecretSuffix)
	err = c.getSecret(generatedCertSecret.ObjectMeta)
	if err != nil && kerr.IsNotFound(err) {
		//wait for  secret
		err = wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
			if !c.isMongoDBExist(mongoDB) {
				return true, fmt.Errorf("MongoDB %s/%s does not exist", mongoDB.Namespace, mongoDB.Name)
			}
			err := c.getSecret(generatedCertSecret.ObjectMeta)
			if err == nil {
				return true, nil
			} else if kerr.IsNotFound(err) {
				return false, nil
			}
			return true, err
		})
	}
	if err == nil {
		//set mongodb as the owner of the certificate-secret
		if err := c.AddOwnerReferenceToGeneratedSecret(mongoDB, generatedCertSecret.ObjectMeta); err != nil {
			log.Infoln(err)
			return err
		}
	}

	return err
}

func (c *Controller) ensureStandaloneServerCert(mongodb *api.MongoDB) (kutil.VerbType, error) {
	var duration, renewBefore *metav1.Duration
	var organization, uriSANs []string
	dnsNames, ipAddresses, err := c.getServiceHosts(mongodb)
	if mongodb.Spec.TLS.Certificate != nil {
		dnsNames = append(dnsNames, mongodb.Spec.TLS.Certificate.DNSNames...)
		ipAddresses = append(dnsNames, mongodb.Spec.TLS.Certificate.IPAddresses...)
		duration = mongodb.Spec.TLS.Certificate.Duration
		renewBefore = mongodb.Spec.TLS.Certificate.RenewBefore
		organization = mongodb.Spec.TLS.Certificate.Organization
		uriSANs = mongodb.Spec.TLS.Certificate.URISANs
	}
	if err != nil {
		return kutil.VerbUnchanged, err
	}
	cert := cm_api.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mongodb.GetName() + ServerSecretSuffix,
			Namespace: mongodb.GetNamespace(),
			Labels:    mongodb.GetLabels(),
		},
		TypeMeta: metav1.TypeMeta{
			Kind: cm_api.CertificateKind,
		},
		Spec: cm_api.CertificateSpec{
			//CommonName:   c.getServiceURL(mongodb), //Service name
			CommonName:   "root", //Service name
			Organization: append(organization, "kubedb:server"),
			Duration:     duration, //Default
			RenewBefore:  renewBefore,
			DNSNames:     dnsNames,    // including Service URL, and localhost
			IPAddresses:  ipAddresses, //including 127.0.0.1
			URISANs:      uriSANs,
			SecretName:   mongodb.Name + ServerSecretSuffix, //Secret where issued certificates will be saved
			IssuerRef: cmmeta.ObjectReference{
				Name: mongodb.Spec.TLS.IssuerRef.Name,
				Kind: mongodb.Spec.TLS.IssuerRef.Kind,
			},
			IsCA: false,
			Usages: []cm_api.KeyUsage{
				cm_api.UsageDigitalSignature,
				cm_api.UsageKeyEncipherment,
				cm_api.UsageServerAuth,
			},
		},
	}

	ref := metav1.NewControllerRef(mongodb, api.SchemeGroupVersion.WithKind(api.ResourceKindMongoDB))
	core_util.EnsureOwnerReference(&cert.ObjectMeta, ref)

	_, vt, err := cm_util.CreateOrPatchCertificate(c.CertManagerClient.CertmanagerV1alpha2(), cert.ObjectMeta, func(in *cm_api.Certificate) *cm_api.Certificate {
		in.Spec = cert.Spec
		return in
	})

	return vt, err
}

func (c *Controller) isMongoDBExist(mongoDB *api.MongoDB) bool {
	_, err := c.ExtClient.KubedbV1alpha1().MongoDBs(mongoDB.Namespace).Get(mongoDB.Name, metav1.GetOptions{})
	return err == nil
}

func (c *Controller) getSecretSpec(mongoDB *api.MongoDB, secretName string) *core.Secret {
	return &core.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: mongoDB.Namespace,
		},
	}
}

func (c *Controller) createOrPatchPEMSecretFromCertSecret(mongoDB *api.MongoDB, certSecretMeta metav1.ObjectMeta, pemKey string) (*core.Secret, error) {
	serverBytes, err := c.getPEMBytesFromSecret(certSecretMeta)
	if err != nil {
		return nil, err
	}
	//ca.crt is also needed in conjunction to pem bytes
	rootCABytes, err := c.getCABytesFromSecret(certSecretMeta)
	if err != nil {
		return nil, err
	}

	newPEMSecret := c.getSecretSpec(mongoDB, certSecretMeta.Name+PEMSecretSuffix)
	//create the Server PEM secret
	secret, _, err := core_util.CreateOrPatchSecret(c.Client, newPEMSecret.ObjectMeta, func(secret *core.Secret) *core.Secret {
		ref := metav1.NewControllerRef(mongoDB, api.SchemeGroupVersion.WithKind(api.ResourceKindMongoDB))
		core_util.EnsureOwnerReference(&secret.ObjectMeta, ref)
		secret.Data = map[string][]byte{
			pemKey:                   serverBytes, // ie = mongo.pem, client.pem
			api.MongoTLSCertFileName: rootCABytes,
		}
		return secret
	})
	return secret, err
}

func (c *Controller) getPEMBytesFromSecret(secretMeta metav1.ObjectMeta) ([]byte, error) {
	secret, err := c.Client.CoreV1().Secrets(secretMeta.Namespace).Get(secretMeta.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return append(secret.Data[core.TLSCertKey], secret.Data[core.TLSPrivateKeyKey]...), nil
}

func (c *Controller) getCABytesFromSecret(secretMeta metav1.ObjectMeta) ([]byte, error) {
	secret, err := c.Client.CoreV1().Secrets(secretMeta.Namespace).Get(secretMeta.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data[api.MongoTLSCertFileName], nil
}

func (c *Controller) getTLSArgs(mongoDB *api.MongoDB, mgVersion *v1alpha1.MongoDBVersion) ([]string,error) {
	var sslArgs []string
	sslMode := string(mongoDB.Spec.SSLMode)
	if mongoDB.Spec.SSLMode == api.SSLModeRequireSSL {
		sslArgs = []string{
			fmt.Sprintf("--sslMode=%v", sslMode),
			fmt.Sprintf("--sslCAFile=%v/%v", api.MongoCertDirectory, api.MongoTLSCertFileName),
			fmt.Sprintf("--sslPEMKeyFile=%v/%v", api.MongoCertDirectory, api.MongoPemFileName),
		}

		breakingVer, err := version.NewVersion("4.2")
		if err != nil {
			return nil, err
		}
		currentVer, err := version.NewVersion(mgVersion.Spec.Version)
		if err != nil {
			return nil, err
		}

		//xREF: https://github.com/docker-library/mongo/issues/367
		if currentVer.GreaterThanOrEqual(breakingVer) {
			var tlsMode = sslMode
			if strings.Contains(sslMode,"SSL"){
				tlsMode = strings.Replace(sslMode, "SSL", "TLS",1)
			} //ie. requireSSL => requireTLS
			sslArgs = []string{
				fmt.Sprintf("--tlsMode=%v", tlsMode),
				fmt.Sprintf("--tlsCAFile=%v/%v", api.MongoCertDirectory, api.MongoTLSCertFileName),
				fmt.Sprintf("--tlsCertificateKeyFile=%v/%v", api.MongoCertDirectory, api.MongoPemFileName),
			}
		}
	}
	return sslArgs, nil
}