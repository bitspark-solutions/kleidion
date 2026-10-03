import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

import { derivePrivateKeyStd, deriveVerifier } from "../src/srp/params";
import { deriveClientSession, expectedServerProof } from "../src/srp/client";
import { deriveServerSession, B_of } from "../src/srp/server";

interface GoldenVector {
  username: string;
  salt: string;
  x: string;
  verifier: string;
  clientEphemeral: { secret: string; public: string };
  serverEphemeral: { secret: string; public: string };
  session: { key: string; M1_clientProof: string; M2_serverProof: string };
}

const golden: GoldenVector = JSON.parse(
  readFileSync(join(__dirname, "vectors", "srp-golden.json"), "utf8"),
);

describe("SRP-6a golden interop vector (ref: secure-remote-password@0.3.1)", () => {
  it("derives the same verifier v = g^x mod N", () => {
    expect(deriveVerifier(golden.x)).toBe(golden.verifier.toLowerCase());
  });

  it("client derives the same session key K", () => {
    const cs = deriveClientSession(
      golden.clientEphemeral.secret,
      golden.serverEphemeral.public,
      golden.salt,
      golden.username,
      golden.x,
    );
    expect(cs.key).toBe(golden.session.key.toLowerCase());
  });

  it("client derives the same proof M1", () => {
    const cs = deriveClientSession(
      golden.clientEphemeral.secret,
      golden.serverEphemeral.public,
      golden.salt,
      golden.username,
      golden.x,
    );
    expect(cs.proof).toBe(golden.session.M1_clientProof.toLowerCase());
  });

  it("server derives the same session key K", () => {
    const ss = deriveServerSession(
      golden.serverEphemeral.secret,
      golden.clientEphemeral.public,
      golden.salt,
      golden.username,
      golden.verifier,
      golden.session.M1_clientProof,
    );
    expect(ss.key).toBe(golden.session.key.toLowerCase());
  });

  it("server validates the client proof M1", () => {
    const ss = deriveServerSession(
      golden.serverEphemeral.secret,
      golden.clientEphemeral.public,
      golden.salt,
      golden.username,
      golden.verifier,
      golden.session.M1_clientProof,
    );
    expect(ss.clientProofValid).toBe(true);
  });

  it("server derives the same proof M2", () => {
    const ss = deriveServerSession(
      golden.serverEphemeral.secret,
      golden.clientEphemeral.public,
      golden.salt,
      golden.username,
      golden.verifier,
      golden.session.M1_clientProof,
    );
    expect(ss.proof).toBe(golden.session.M2_serverProof.toLowerCase());
  });

  it("client's expectedServerProof matches M2", () => {
    expect(
      expectedServerProof(
        golden.clientEphemeral.public,
        golden.session.M1_clientProof,
        golden.session.key,
      ),
    ).toBe(golden.session.M2_serverProof.toLowerCase());
  });

  it("server public ephemeral B = k*v + g^b reproduces the captured B", () => {
    const B = B_of(BigInt("0x" + golden.serverEphemeral.secret), BigInt("0x" + golden.verifier));
    // pad to 256 bytes
    expect(B.toString(16).padStart(512, "0")).toBe(golden.serverEphemeral.public.toLowerCase().padStart(512, "0"));
  });
});

describe("SRP-6a standard private-key derivation", () => {
  it("derivePrivateKeyStd then verifier is self-consistent", () => {
    const salt = golden.salt;
    const username = golden.username;
    const password = "correct horse battery staple";
    const x = derivePrivateKeyStd(salt, username, password);
    const v = deriveVerifier(x);
    expect(x).toMatch(/^[0-9a-f]{64}$/);
    expect(v).toMatch(/^[0-9a-f]+$/);
  });
});
