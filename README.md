# kube-certdaemon
Simple daemon to fetch and refresh Let's Encrypt certs stored in k8s secrets

Originally written by [Omeryl](https://github.com/Omeryl). Thanks!

## Using it

Build the container:
```
$ docker build -t certdaemon .
```
Or take your chances with `gliderlabs/certdaemon`.

Create a config secret as defined below on Kubernetes. Then deploy using
something like `run/manifest.yaml`.

## Config

Environment variables:
* `NAMESPACE` - k8s namespace to use. default is `default`
* `CONFIG_SECRET` - k8s secret with config (see below). default is `letsencrypt`
* `INTERVAL` - interval for checking if certs need updating. ex: "30m". default is `1h`
* `PROVIDER` - lego provider to use for dns challenge. default is `route53`

Other environment variables will need to be provided based on your provider.
For example, `route53` will need:

* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY`

The secret defined by `CONFIG_SECRET` should have a key called `config.yaml`
that looks like this:

```
account:
  key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  email: test@gmail.com
certificates:
  - domains: ['mcidentify.com', 'www.mcidentify.com', 'yay.mcidentify.com']
    secret: main-tls
  - domains: ['sandbox.mcidentify.com']
    secret: sandbox-tls
```

The field `account` represents a Let's Encrypt account that will be created if
it doesn't exist. It's simplest to just create a new private key for a new account.
