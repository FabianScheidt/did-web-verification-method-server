import { Request, Response } from "express";
import { JWK } from "node-jose";

export function getDidDocumentHandler(cert: string) {
  return (req: Request, res: Response): void => {
    JWK.asKey(cert, "pem").then((result) => {
      const key = result.toJSON();
      const kid = "kid" in key ? key.kid : "key";

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
      }[result.kty];

      // Assemble DID document
      // https://www.w3.org/TR/did-core/#verification-methods
      const payload = {
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

      res.header("Content-Type", "application/json").send(payload);
    });
  };
}
