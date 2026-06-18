import { describe, test } from "node:test";
import * as assert from "node:assert/strict";
import { readFileSync } from "fs";
import { join } from "path";
import { getDidDocument } from "./did-document";

const exampleCert = readFileSync(
  join(__dirname, "./test_fixtures/iana.org.pem"),
  "utf-8",
);

describe("getDidDocument", () => {
  test("returns correct DID document for /.well-known/did.json", async () => {
    const req = {
      protocol: "https",
      hostname: "example.com",
      path: "/.well-known/did.json",
    };
    const doc = await getDidDocument(exampleCert, req);

    assert.deepStrictEqual(doc["@context"], [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ]);
    assert.strictEqual(doc.id, "did:web:example.com");
    assert.strictEqual(doc.verificationMethod.length, 1);

    const [vm] = doc.verificationMethod;
    assert.strictEqual(vm.type, "JsonWebKey2020");
    assert.strictEqual(vm.controller, "did:web:example.com");
    assert.ok(vm.id.startsWith("did:web:example.com#"));
  });

  test("publicKeyJwk matches the public key of the certificate", async () => {
    const req = {
      protocol: "https",
      hostname: "example.com",
      path: "/.well-known/did.json",
    };
    const doc = await getDidDocument(exampleCert, req);
    const { publicKeyJwk } = doc.verificationMethod[0];

    assert.deepStrictEqual(publicKeyJwk, {
      kid: "*.iana.org",
      kty: "RSA",
      alg: "PS256",
      x5t: "c4OoniEraBePUH-yyrpX4fooyYI",
      x5u: "https://example.com/.well-known/certificate-chain.pem",
      n: "nb393rXK5TpVl0fi_aY3KOSrpg8Yt5pp8DMQvwFk5e59trFb9W3yP9265qG7OESbjIg_GBArvYu2VawOLawu4-1c9DFYaNLFmAaChIVLJIlNzUvTeBHwrTooLNS05Zn_0H2NLT8keFVPgQILMg7hL0SUji6h7byZC4MMpcymtKg5-ye1GFDJhH6sdPJmCeskNluXUfscMgj1aRO6y8rkkgE0fHi35UqdmZeUBMN_APtl24Sf1146aHcMMPKr5lszJW-1m0UAULANgTnU2A0297xG2vMD5I8PB5Gy_dcuxgsss61TPD8ojJwZTkkzemnElnMfCG1PH5glkAcT4qVR0Fy2BXVnhQ2R5gAcTOJxdvCVeHOpW4gKy-wZ572bzxKG0EUrc3icQZBd1HCXHNc66lLHewgM13mvWCNPM3Ilwm-HqME-KmXp3U4DpbQdfgazNT84EpsjJ6Ux7JYnoh3EI3M6oCnUmJRIujMiiRwaVpDd8tJcjsiqqJSxSqkhMMa22WmiH_ZxtgxMkjqUqT6h3QSSyTOTym7dYfM8p36SCNAda9FRB2YuwIhzPfTIdqfhYIuClzoPdZLoTtFVedGB55Akrop-S58AeOsgBbI_nQmh3xu8feKlpghaNkbZ-tsOnaJzpfQDzdQoMc5vDKRoiVhWAruLw2uzvoYf9tGmLjU",
      e: "AQAB",
    });
  });

  test("derives DID segments and x5u from custom path", async () => {
    const req = {
      protocol: "https",
      hostname: "example.com",
      path: "/foo/bar/did.json",
    };
    const doc = await getDidDocument(exampleCert, req);

    assert.strictEqual(doc.id, "did:web:example.com:foo:bar");

    const [vm] = doc.verificationMethod;
    assert.strictEqual(vm.controller, "did:web:example.com:foo:bar");
    assert.strictEqual(
      vm.publicKeyJwk.x5u,
      "https://example.com/foo/bar/certificate-chain.pem",
    );
  });
});
