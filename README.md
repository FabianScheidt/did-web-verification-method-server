# did:web Verification Method Server

Serves an existing PEM certificate as [did:web verification method](https://www.w3.org/TR/did-core/#verification-methods).

Verifiable credentials contain a proof section, which contains a cryptographic signature of the credential's contents.
A verifier needs to obtain the issuer's public key in order to validate the proof. The public key is usually accompanied
by a certificate that identifies the issuer.

This service exposes an existing PEM certificate as DID document containing the verification method for the 
_JsonWebKey2020_ proof type. In accordance with the DID specification, the public key is exposed as a JSON Web Key
(JWK, RFC7517). The _x5u_ property is added to the JWK, in order to provide the full certificate chain. Optionally,
known root certificates are added.

The DID document will be exposed on any valid did:web URL. The certificate chain will be linked accordingly. Examples:
- `did:web:example.com` -> https://example.com/.well-known/did.json
- `did:web:example.com:hello:world` -> https://example.com/hello/world/did.json

## Configuration Option

The service is configured via environment variables.

| Configuration          | Description                                                                |
|------------------------|----------------------------------------------------------------------------|
| `CERTIFICATE`          | PEM-formatted certificate chain (required)                                 |
| `PORT`                 | Port to expose the service (defaults to 3000)                              |
| `ADD_ROOT_CERTIFICATE` | Enable to add root certificate to the certificate chain (defaults to true) |
