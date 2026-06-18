import { Request, Response } from "express";
import * as crypto from "crypto";
import * as tls from "tls";

export function getCertificateChain(
  cert: string,
  addRootCert: boolean,
): string {
  if (!addRootCert) {
    return cert;
  }

  // Extract certificates
  const certsRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const certMatches = certsRegex[Symbol.matchAll](cert);
  const certs = [...certMatches].map((c) => c[0]);

  // Iterate over certificates and try to find a matching root certificate
  const outputCerts: string[] = [];
  for (const certPem of certs) {
    outputCerts.push(certPem);
    const certObj = new crypto.X509Certificate(certPem);
    const match = tls.rootCertificates.find((rootCertPem) =>
      certObj.checkIssued(new crypto.X509Certificate(rootCertPem)),
    );
    if (match) {
      outputCerts.push(match);
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
