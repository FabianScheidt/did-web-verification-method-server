import { Request, Response } from "express";
import { JWK } from "node-jose";

export interface JsonWebKey2020VerificationMethod {
  id: string;
  type: "JsonWebKey2020";
  controller: string;
  publicKeyJwk: {
    kid: string;
    alg?: string;
    x5u: string;
    [el: string]: string | undefined;
  };
}

export interface DidDocument<VerificationMethodType> {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethodType;
}

export async function getDidDocument(
  cert: string,
  req: { protocol: string; hostname: string; path: string },
): Promise<DidDocument<[JsonWebKey2020VerificationMethod]>> {
  const jwk = await JWK.asKey(cert, "pem");
  const key = jwk.toJSON();
  const kid = "kid" in key ? String(key.kid) : "key";

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
    RSA: "PS256",
    EC: "ES256",
    OKP: "EdDSA",
  }[jwk.kty];

  // Assemble DID document
  // https://www.w3.org/TR/did-core/#verification-methods
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#${kid}`,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          ...key,
          kid,
          alg,
          x5u,
        },
      },
    ],
  };
}

export function getDidDocumentHandler(cert: string) {
  return (req: Request, res: Response): void => {
    getDidDocument(cert, req).then((payload) => {
      res.header("Content-Type", "application/json").send(payload);
    });
  };
}
