import { Request, Response } from "express";
import { pki } from "node-forge";
import * as tls from "tls";

export function getCertificateChain(
  cert: string,
  addRootCert: boolean,
): string {
  if (!addRootCert) {
    return cert;
  }

  // Build list of available root certificates
  const ROOT_CERTS: pki.Certificate[] = [];
  const certParseErrors: Set<string> = new Set();
  for (const rootCert of tls.rootCertificates) {
    try {
      ROOT_CERTS.push(pki.certificateFromPem(rootCert));
    } catch (e: unknown) {
      if (!(e instanceof Error)) {
        throw e;
      }
      certParseErrors.add(e.message);
    }
  }
  if (certParseErrors.size > 0) {
    console.warn(
      "Not all known root certificates were parsed. This may not be an issue:" +
        ["", ...certParseErrors].join("\n -> "),
    );
  }

  // Extract certificates
  const certsRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const certMatches = certsRegex[Symbol.matchAll](cert);
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

  return outputCerts.join("\n");
}

export function getCertificateChainHandler(cert: string, addRootCert: boolean) {
  const payload = getCertificateChain(cert, addRootCert);
  return (req: Request, res: Response): void => {
    res.header("Content-Type", "application/x-pem-file").send(payload);
  };
}
