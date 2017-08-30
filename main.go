package main

import (
	"context"
	"log"
	"os"

	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/ericchiang/k8s"
	"github.com/ericchiang/k8s/api/v1"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns"
	"gopkg.in/yaml.v2"
)

const (
	DefaultConfigSecret = "letsencrypt"
	DefaultNamespace    = "default"
	DefaultInterval     = "1h"
	DefaultProvider     = "route53"
)

func GetEnv(key, defaultVal string) string {
	if os.Getenv(key) == "" {
		return defaultVal
	}
	return os.Getenv(key)
}

type Config struct {
	Account struct {
		Email string `yaml:"email"`
		Key   string `yaml:"key"`
	} `yaml:"account"`
	Certificates []struct {
		Domains []string `yaml:"domains"`
		Secret  string   `yaml:"secret"`
	} `yaml:"certificates"`
}

func NewConfig(client *k8s.Client, namespace, secret string) (*Config, error) {
	config, err := client.CoreV1().GetSecret(context.TODO(), secret, namespace)
	if err != nil {
		return nil, err
	}

	var c Config
	err = yaml.Unmarshal(config.GetData()["config.yaml"], &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

type AcmeUser struct {
	Email        string
	Registration *acme.RegistrationResource
	Key          crypto.PrivateKey
}

func (u AcmeUser) GetEmail() string {
	return u.Email
}

func (u AcmeUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func ParseRsaKey(pemIn string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemIn))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseCertificateFromPEM(inPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(inPem))
	if block == nil {
		return nil, errors.New("Unable to decode pem from byte array")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func main() {
	// get our environment config
	namespace := GetEnv("NAMESPACE", DefaultNamespace)
	secret := GetEnv("CONFIG_SECRET", DefaultConfigSecret)
	provider := GetEnv("PROVIDER", DefaultProvider)
	intervalStr := GetEnv("INTERVAL", DefaultInterval)
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Fatal(err)
	}

	// Get a new incluster client
	client, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatal(err)
	}

	// parse our yaml config, from Secret
	config, err := NewConfig(client, namespace, secret)
	if err != nil {
		log.Fatal(err)
	}

	for {

		// for certificate in the config
		for _, cert := range config.Certificates {
			log.Println("Working on: ", cert.Domains)

			// attempt to get an existing secret
			existingCert, err := client.CoreV1().GetSecret(context.TODO(), cert.Secret, namespace)

			var expiresIn float64
			isNew := false

			if apiErr, ok := err.(*k8s.APIError); ok {
				// it wasn't found...
				if apiErr.Code == http.StatusNotFound {
					log.Println("Secret doesn't exist, brand new certificate")
					expiresIn = 0
					isNew = true
				} else {
					// some other error, need to abort
					log.Fatal(err)
				}
			} else {
				// it was found!
				parsedCert, err := ParseCertificateFromPEM(existingCert.GetData()["tls.crt"])
				if err != nil {
					log.Fatal("Error decoding certificate: ", err)
				}

				// seconds until expiration
				expiresIn = parsedCert.NotAfter.Sub(time.Now()).Seconds()
			}

			// check to see if we expire less than a month for now
			if expiresIn >= 60*60*24*30*1 {
				// This expires past our current window, no need to renew.
				log.Println("Expires more than a month from now, all fine! continuing, expiresIn:", expiresIn)
				continue
			}
			log.Println("Expires less than a month from now, renewing")

			// get an AcmeUser
			var user AcmeUser
			user.Email = config.Account.Email
			user.Key, err = ParseRsaKey(config.Account.Key)
			if err != nil {
				log.Fatal(err)
			}

			// new ACME client
			var acme_client, errr = acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", &user, acme.RSA2048)
			if errr != nil {
				log.Fatal(err)
			}

			// exclude unused challenges, HTTP01 and TLSSNI01
			acme_client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

			// attempt to register
			reg, err := acme_client.Register()
			if err != nil {
				log.Fatal(err)
			}
			user.Registration = reg

			// always agree to the TOS
			err = acme_client.AgreeToTOS()
			if err != nil {
				log.Fatal(err)
			}

			// instantiates the route53 provider
			challenge_provider, err := dns.NewDNSChallengeProviderByName(provider)

			if err != nil {
				log.Fatal(err)
			}

			// sets the route53 provider
			acme_client.SetChallengeProvider(acme.DNS01, challenge_provider)

			// obtain our certificates, automatically rolling in a new private key
			certificates, failures := acme_client.ObtainCertificate(cert.Domains, true, nil, false)

			// more than a single domain failed for some reason
			if len(failures) > 0 {
				log.Println("The following domains failed to verify, so we couldn't renew our certificate:")
				log.Println(failures)
				continue
			}

			// prepare our data
			stringData := make(map[string]string)
			stringData["tls.crt"] = string(certificates.Certificate[:])
			stringData["tls.key"] = string(certificates.PrivateKey[:])
			secretType := "tls"

			tlsSecret := &v1.Secret{
				Metadata: &metav1.ObjectMeta{
					Name:      &cert.Secret,
					Namespace: &namespace,
				},
				StringData: stringData,
				Type:       &secretType,
			}

			// if it's new, create it, else update it.
			if isNew {
				_, err = client.CoreV1().CreateSecret(context.TODO(), tlsSecret)
			} else {
				_, err = client.CoreV1().UpdateSecret(context.TODO(), tlsSecret)
			}

			if err != nil {
				log.Fatal(err)
			}
		}

		time.Sleep(interval)
	}
}
