import { Request, Response } from "express";
import { pki } from "node-forge";
import * as tls from "tls";

export function getCertificateChainHandler(cert: string, addRootCert: boolean) {
  // Build list of available root certificates
  const ROOT_CERTS: pki.Certificate[] = [];
  for (const rootCert of tls.rootCertificates) {
    try {
      ROOT_CERTS.push(pki.certificateFromPem(rootCert));
    } catch (e) {}
  }

  // Return Handler
  return (req: Request, res: Response): void => {
    if (!addRootCert) {
      res.header("Content-Type", "application/x-pem-file").send(cert);
      return;
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

    const payload = outputCerts.join("\n");
    res.header("Content-Type", "application/x-pem-file").send(payload);
  };
}
