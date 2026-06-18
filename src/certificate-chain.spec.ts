import { describe, test } from "node:test";
import * as assert from "node:assert/strict";
import { readFileSync } from "fs";
import { join } from "path";
import * as crypto from "crypto";
import { getCertificateChain } from "./certificate-chain";

const exampleCert = readFileSync(
  join(__dirname, "./test_fixtures/iana.org.pem"),
  "utf-8",
);
const certCount = (pem: string) =>
  (pem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;

describe("getCertificateChain", () => {
  test("returns cert unchanged when addRootCert is false", () => {
    assert.strictEqual(getCertificateChain(exampleCert, false), exampleCert);
  });

  test("appends exactly one root cert when addRootCert is true", () => {
    const result = getCertificateChain(exampleCert, true);
    assert.strictEqual(certCount(result), certCount(exampleCert) + 1);
  });

  test("appends the correct root cert when addRootCert is true", () => {
    const result = getCertificateChain(exampleCert, true);
    const certs =
      result.match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
      ) ?? [];
    const lastCert = new crypto.X509Certificate(certs[certs.length - 1]);
    const cn = lastCert.subject
      .split("\n")
      .find((l) => l.startsWith("CN="))
      ?.slice(3);
    assert.strictEqual(cn, "Sectigo Public Server Authentication Root R46");
  });
});
