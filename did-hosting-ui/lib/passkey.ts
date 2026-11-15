/**
 * Browser WebAuthn credential helpers.
 *
 * Thin wrappers around navigator.credentials.create/get that handle
 * ArrayBuffer <-> base64url conversions for JSON transport to the server.
 */

import type {
  AuthenticatorAssertionResponseLogin as AssertionJson,
  AuthenticatorAttestationResponseRegistration as AttestationJson,
} from "./trust-tasks/_shared/components";

export type { AssertionJson, AttestationJson };

/** A credential descriptor as the server sends it: `id` base64url. */
interface CredentialDescriptorJson {
  id: string;
  type: "public-key";
  transports?: AuthenticatorTransport[];
}

/** `PublicKeyCredentialCreationOptions` as JSON: binary members base64url. */
interface CreationOptionsJson extends Omit<
  PublicKeyCredentialCreationOptions,
  "challenge" | "user" | "excludeCredentials"
> {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
  excludeCredentials?: CredentialDescriptorJson[];
}

/** `PublicKeyCredentialRequestOptions` as JSON: binary members base64url. */
interface RequestOptionsJson extends Omit<
  PublicKeyCredentialRequestOptions,
  "challenge" | "allowCredentials"
> {
  challenge: string;
  allowCredentials?: CredentialDescriptorJson[];
}

function base64urlToBuffer(b64: string): ArrayBuffer {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function descriptors(list: CredentialDescriptorJson[] | undefined) {
  return list?.map((cred) => ({ ...cred, id: base64urlToBuffer(cred.id) }));
}

/** The server's `publicKey` options, which arrive typed as the open schema
 *  they are; WebAuthn validates the members, this checks the shape it reads. */
function asOptions<T extends { challenge: string }>(publicKey: unknown): T {
  if (
    !publicKey ||
    typeof publicKey !== "object" ||
    typeof (publicKey as { challenge?: unknown }).challenge !== "string"
  ) {
    throw new Error("The server sent no WebAuthn options");
  }
  return publicKey as T;
}

/**
 * Create a passkey credential (registration).
 *
 * Takes the server's CreationChallengeResponse options and returns
 * a serialised RegisterPublicKeyCredential suitable for JSON POST.
 */
export async function createPasskeyCredential(options: {
  publicKey: unknown;
}): Promise<AttestationJson> {
  // Decode base64url fields that the browser expects as ArrayBuffer
  const json = asOptions<CreationOptionsJson>(options.publicKey);
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...json,
    challenge: base64urlToBuffer(json.challenge),
    user: { ...json.user, id: base64urlToBuffer(json.user.id) },
    excludeCredentials: descriptors(json.excludeCredentials),
  };

  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Credential creation cancelled or failed");
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: "public-key",
    response: {
      attestationObject: bufferToBase64url(response.attestationObject),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
    },
  };
}

/**
 * Get a passkey credential (authentication / login).
 *
 * Takes the server's RequestChallengeResponse options and returns
 * a serialised PublicKeyCredential suitable for JSON POST.
 */
export async function getPasskeyCredential(options: {
  publicKey: unknown;
}): Promise<AssertionJson> {
  const json = asOptions<RequestOptionsJson>(options.publicKey);
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...json,
    challenge: base64urlToBuffer(json.challenge),
    allowCredentials: descriptors(json.allowCredentials),
  };

  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Credential retrieval cancelled or failed");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: "public-key",
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
  };
}
