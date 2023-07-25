import * as process from "process";
import * as express from "express";
import { getDidDocumentHandler } from "./did-document";
import { getCertificateChainHandler } from "./certificate-chain";

if (!process.env.CERTIFICATE) {
  throw new Error("Environment Variable CERTIFICATE needs to be set!");
}
const CERT = process.env.CERTIFICATE;
const PORT = process.env.PORT ?? 3000;
const ADD_ROOT_CERT = process.env.ADD_ROOT_CERTIFICATE
  ? process.env.ADD_ROOT_CERTIFICATE.toLowerCase() === "true"
  : true;

const app = express();
app.set("json spaces", 2);
app.set("trust proxy", true);

app.get("/**/did.json", getDidDocumentHandler(CERT));
app.get(
  "/**/certificate-chain.pem",
  getCertificateChainHandler(CERT, ADD_ROOT_CERT),
);

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}!`);
});
