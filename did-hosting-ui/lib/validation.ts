/**
 * Inline form validation, written against the rules the control plane
 * enforces, so a form says what is wrong before it is sent rather than after.
 *
 * Each validator returns the message to show, or `null` when the input is
 * acceptable. They mirror, and never loosen, the server: the server's answer
 * is still the final word.
 */

import { splitAgentName } from "./api/acl";

/**
 * First path segments the server reserves for its own routes
 * (`did-hosting-common/src/server/mnemonic.rs` `RESERVED_NAMES`).
 */
export const RESERVED_FIRST_SEGMENTS = [
  ".well-known",
  "api",
  "auth",
  "dids",
  "stats",
  "acl",
  "health",
] as const;

const SEGMENT = /^[a-z0-9-]+$/;

/**
 * A custom DID path, per the server's `validate_custom_path`: no leading or
 * trailing `/`, no empty segment, at most 255 characters, each segment 2–63
 * of `a-z`, `0-9` and `-` starting and ending with a letter or digit, and a
 * first segment that is not reserved. An empty path is fine here — the form
 * then asks for a random name.
 */
export function didPathError(path: string): string | null {
  if (path === "") return null;
  if (path.length > 255) return "The path can be at most 255 characters.";
  if (path.startsWith("/") || path.endsWith("/")) return "The path can't start or end with “/”.";
  const segments = path.split("/");
  for (const [i, seg] of segments.entries()) {
    if (seg === "") return "The path can't contain “//”.";
    if (seg.length < 2 || seg.length > 63) {
      return `“${seg}” must be 2–63 characters long.`;
    }
    if (!SEGMENT.test(seg)) {
      return `“${seg}” may contain only lowercase letters, digits and hyphens.`;
    }
    if (!/^[a-z0-9]/.test(seg) || !/[a-z0-9]$/.test(seg)) {
      return `“${seg}” must start and end with a letter or digit.`;
    }
    if (i === 0 && (RESERVED_FIRST_SEGMENTS as readonly string[]).includes(seg)) {
      return `“${seg}” is reserved and can't be the first part of a path.`;
    }
  }
  return null;
}

/**
 * A hosting domain name, per the server's `normalize_domain_name`: a
 * lowercase DNS host (letters, digits, `-`, `.`), optionally `:port`, and
 * optionally a `/path-prefix` of lowercase letters, digits, `-`, `_`, `.`.
 * No IP literals, no scheme, no surrounding whitespace.
 */
export function domainNameError(input: string): string | null {
  if (input === "") return "Enter a host name, like example.com.";
  if (input.trim() !== input) return "Remove the spaces around the name.";
  if (input.length > 253) return "A domain name can be at most 253 characters.";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    return "Enter just the host name, without https://.";
  }
  if (input.startsWith("/") || input.endsWith("/")) return "The name can't start or end with “/”.";
  const slash = input.indexOf("/");
  const hostPort = slash === -1 ? input : input.slice(0, slash);
  const path = slash === -1 ? null : input.slice(slash + 1);

  const colon = hostPort.lastIndexOf(":");
  const host = colon === -1 ? hostPort : hostPort.slice(0, colon);
  if (colon !== -1) {
    const port = hostPort.slice(colon + 1);
    if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
      return "The port must be a number from 1 to 65535.";
    }
  }
  if (host !== host.toLowerCase()) return `Use lowercase: ${input.toLowerCase()}`;
  if (!/^[a-z0-9.-]+$/.test(host)) {
    return "The host may contain only letters, digits, hyphens and dots.";
  }
  if (/^\d+(\.\d+){3}$/.test(host)) return "Use a DNS host name, not an IP address.";
  if (host.split(".").some((label) => label === "")) return "The host has an empty part (“..”).";
  if (host.split(".").some((label) => label.startsWith("-") || label.endsWith("-"))) {
    return "Each part of the host must start and end with a letter or digit.";
  }
  if (path !== null) {
    if (path.includes("//")) return "The path can't contain “//”.";
    if (!/^[a-z0-9._/-]+$/.test(path)) {
      return "The path may contain only lowercase letters, digits, “-”, “_”, “.” and “/”.";
    }
  }
  return null;
}

/** `did:<method>:<method-specific-id>`, per DID Core's syntax. */
const DID_SYNTAX = /^did:[a-z0-9]+:(?:[A-Za-z0-9._%-]*:)*[A-Za-z0-9._%-]+$/;

/** Whether `input` has the shape of a DID. */
export function looksLikeDid(input: string): boolean {
  return DID_SYNTAX.test(input);
}

/** An ACL subject: a DID, or an agent name hosted here (`example.com/@alice`). */
export function aclSubjectError(input: string): string | null {
  const v = input.trim();
  if (v === "") return null; // the button stays disabled; nothing to say yet
  if (v.includes("/@")) {
    return splitAgentName(v)
      ? null
      : "An agent name looks like example.com/@alice — a host, then /@, then the name.";
  }
  if (!v.startsWith("did:")) {
    return "Enter a DID (did:method:…) or an agent name (example.com/@alice).";
  }
  return looksLikeDid(v) ? null : "That is not a valid DID — expected did:method:identifier.";
}

/** A blank-or-non-negative number field (a quota). `integer` refuses decimals. */
export function quotaError(input: string, opts: { integer?: boolean } = {}): string | null {
  const v = input.trim();
  if (v === "") return null;
  const ok = opts.integer ? /^\d+$/.test(v) : /^\d+(\.\d+)?$/.test(v);
  if (!ok)
    return opts.integer
      ? "Enter a whole number, or leave blank."
      : "Enter a number, or leave blank.";
  return null;
}
