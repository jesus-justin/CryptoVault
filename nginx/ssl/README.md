# Local SSL Certificates

Generate local self-signed certificates for Docker/Nginx:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=Dev/L=Local/O=CryptoVault/CN=localhost"
```

These files are for local development only and are ignored by git.
