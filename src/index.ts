import * as process from "process";
import * as express from "express";
import { Request, Response } from "express";
import { JWK } from "node-jose";

if (!process.env.CERTIFICATE) {
  throw new Error("Environment Variable CERTIFICATE needs to be set!");
}
const CERT = process.env.CERTIFICATE;
const PORT = process.env.PORT ?? 3000;

function getJwksDid(req: Request, res: Response): void {
  JWK.asKey(CERT, "pem").then((result) => {
    const key = result.toJSON();

    const pathSegments = req.path.split("/");
    pathSegments.shift();
    pathSegments.pop();

    let did = `did:web:` + req.hostname;
    if (req.path !== "/.well-known/did.json") {
      did += ":" + pathSegments.join(":");
    }

    const basePath = pathSegments.join("/");
    const x5u = `${req.protocol}://${req.hostname}/${basePath}/certificate-chain.pem`;

    const payload = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      verificationMethod: [
        {
          "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
          id: did,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: {
            ...key,
            x5u,
          },
        },
      ],
    };

    res.header("Content-Type", "application/json").send(payload);
  });
}

function getCert(req: Request, res: Response): void {
  res.header("Content-Type", "application/x-pem-file").send(CERT);
}

const app = express();
app.set("json spaces", 2);
app.get("/**/did.json", getJwksDid);
app.get("/**/certificate-chain.pem", getCert);
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}!`);
});
