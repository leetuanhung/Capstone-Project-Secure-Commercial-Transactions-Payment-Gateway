# TLS Certificates for Local Development

This directory contains TLS certificates for HTTPS in development.

## Generating Self-Signed Certificates (Windows/PowerShell)

```powershell
# Set empty OPENSSL_CONF to avoid config path issues
$env:OPENSSL_CONF=""

# Generate private key and self-signed certificate (valid 365 days)
openssl req -x509 -newkey rsa:2048 -nodes `
  -keyout localhost.key `
  -out localhost.crt `
  -days 365 `
  -subj "/CN=localhost"
```

**Note:** Self-signed certs will show warnings in browsers. For trusted local certs, use [mkcert](https://github.com/FiloSottile/mkcert):
```powershell
choco install mkcert
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

## Files (Not Committed to Git)
- `localhost.key` — Private key (keep secret)
- `localhost.crt` — Public certificate

## Production
In production, use:
- **Let's Encrypt / Certbot** for automated cert renewal
- **Cloud provider managed TLS** (AWS ACM, Azure Key Vault, GCP Certificate Manager)
- Store private keys in **KMS/HSM** or secrets manager
- Terminate TLS at load balancer/CDN for better performance and key management

Do **not** commit private keys or production certificates to version control.
