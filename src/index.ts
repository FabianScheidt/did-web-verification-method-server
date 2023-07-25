import * as process from "process";
import * as tls from "tls";
import * as express from "express";
import { Request, Response } from "express";
import { JWK } from "node-jose";
import { pki } from "node-forge";

// Configuration
if (!process.env.CERTIFICATE) {
  throw new Error("Environment Variable CERTIFICATE needs to be set!");
}
const CERT = process.env.CERTIFICATE;
const PORT = process.env.PORT ?? 3000;
const ADD_ROOT_CERT = process.env.ADD_ROOT_CERTIFICATE
  ? process.env.ADD_ROOT_CERTIFICATE.toLowerCase() === "true"
  : true;

// Build list of available root certificates
const ROOT_CERTS: pki.Certificate[] = [];
for (const rootCert of tls.rootCertificates) {
  try {
    ROOT_CERTS.push(pki.certificateFromPem(rootCert));
  } catch (e) {}
}

function getJwksDid(req: Request, res: Response): void {
  JWK.asKey(CERT, "pem").then((result) => {
    const key = result.toJSON();

    const pathSegments = req.path.split("/");
    pathSegments.shift();
    pathSegments.pop();

    // Determine did:web of the current page
    // https://w3c-ccg.github.io/did-method-web/#did-method-operations
    let did = `did:web:` + req.hostname;
    if (req.path !== "/.well-known/did.json") {
      did += ":" + pathSegments.join(":");
    }

    // Determine URL to x5u
    // https://datatracker.ietf.org/doc/html/rfc7517#section-4.6
    const basePath = pathSegments.join("/");
    const x5u = `${req.protocol}://${req.hostname}/${basePath}/certificate-chain.pem`;

    // Determine some verification algorithm as specified for JSON Web Key 2020
    // https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/#jose-conformance
    const alg = {
      "RSA": "PS256",
      "EC": "ES256",
      "OKP": "EdDSA",
    }[result.kty];

    // Assemble DID document
    // https://www.w3.org/TR/did-core/#verification-methods
    const payload = {
      "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/suites/jws-2020/v1"
      ],
      id: did,
      verificationMethod: [
        {
          id: did,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: {
            ...key,
            alg,
            x5u,
          },
        },
      ],
    };

    res.header("Content-Type", "application/json").send(payload);
  });
}

function getCert(req: Request, res: Response): void {
  if (!ADD_ROOT_CERT) {
    res.header("Content-Type", "application/x-pem-file").send(CERT);
    return;
  }

  // Extract certificates
  const certsRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const certMatches = certsRegex[Symbol.matchAll](CERT);
  const certs = [...certMatches].map((c) => c[0]);

  // Iterate over certificates and try to find a matching root certificate
  const outputCerts: string[] = [];
  for (const cert of certs) {
    outputCerts.push(cert);
    const certObj = pki.certificateFromPem(cert);
    const rootCert = ROOT_CERTS.find((r) => r.issued(certObj));
    if (rootCert) {
      outputCerts.push(pki.certificateToPem(rootCert));
      break;
    }
  }

  const payload = outputCerts.join("\n");
  res.header("Content-Type", "application/x-pem-file").send(payload);
}

const app = express();
app.set("json spaces", 2);
app.set("trust proxy", true);
app.get("/**/did.json", getJwksDid);
app.get("/**/certificate-chain.pem", getCert);
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}!`);
});
