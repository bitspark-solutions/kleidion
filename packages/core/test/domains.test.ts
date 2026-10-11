import { describe, expect, it } from "vitest";
import {
  baseDomain,
  domainsEquivalent,
  hostnameFrom,
  normalizeTitle,
} from "../src/domains.js";

describe("normalizeTitle", () => {
  it("trims, lowercases and collapses internal whitespace", () => {
    expect(normalizeTitle("  GitHub   Corp ")).toBe("github corp");
  });
});

describe("hostnameFrom", () => {
  it("extracts host from a full URL", () => {
    expect(hostnameFrom("https://Accounts.Google.com/signin?x=1")).toBe("accounts.google.com");
  });
  it("strips a numeric port", () => {
    expect(hostnameFrom("localhost:8080")).toBe("localhost");
  });
  it("handles bare hosts and paths without protocol", () => {
    expect(hostnameFrom("example.com/login")).toBe("example.com");
  });
});

describe("baseDomain", () => {
  it("reduces subdomains to the registrable domain", () => {
    expect(baseDomain("mail.google.com")).toBe("google.com");
    expect(baseDomain("www.example.com")).toBe("example.com");
    expect(baseDomain("example.com")).toBe("example.com");
  });
  it("keeps known two-level public suffixes", () => {
    expect(baseDomain("shop.co.uk")).toBe("shop.co.uk");
    expect(baseDomain("www.shop.co.uk")).toBe("shop.co.uk");
  });
});

describe("domainsEquivalent", () => {
  it("matches exact and www-normalized hosts", () => {
    expect(domainsEquivalent("example.com", "example.com")).toBe(true);
    expect(domainsEquivalent("https://www.example.com", "example.com")).toBe(true);
  });
  it("matches a subdomain against its parent registrable host", () => {
    expect(domainsEquivalent("https://mail.google.com", "google.com")).toBe(true);
    expect(domainsEquivalent("accounts.google.com", "https://www.google.com")).toBe(true);
  });
  it("matches sibling subdomains of the same base domain (gmail <-> google login)", () => {
    expect(domainsEquivalent("mail.google.com", "https://accounts.google.com")).toBe(true);
  });
  it("does not cross unrelated domains", () => {
    expect(domainsEquivalent("evil-google.com", "google.com")).toBe(false);
    expect(domainsEquivalent("notgithub.com", "github.com")).toBe(false);
  });
  it("rejects empty inputs", () => {
    expect(domainsEquivalent("", "example.com")).toBe(false);
  });
});

