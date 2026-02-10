/**
 * Browser WebAuthn credential helpers.
 *
 * Thin wrappers around navigator.credentials.create/get that handle
 * ArrayBuffer <-> base64url conversions for JSON transport to the server.
 */

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

/**
 * Create a passkey credential (registration).
 *
 * Takes the server's CreationChallengeResponse options and returns
 * a serialised RegisterPublicKeyCredential suitable for JSON POST.
 */
export async function createPasskeyCredential(
  options: any,
): Promise<any> {
  // Decode base64url fields that the browser expects as ArrayBuffer
  const publicKey = options.publicKey;
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  publicKey.user.id = base64urlToBuffer(publicKey.user.id);

  if (publicKey.excludeCredentials) {
    for (const cred of publicKey.excludeCredentials) {
      cred.id = base64urlToBuffer(cred.id);
    }
  }

  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Credential creation cancelled or failed");
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
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
export async function getPasskeyCredential(
  options: any,
): Promise<any> {
  const publicKey = options.publicKey;
  publicKey.challenge = base64urlToBuffer(publicKey.challenge);

  if (publicKey.allowCredentials) {
    for (const cred of publicKey.allowCredentials) {
      cred.id = base64urlToBuffer(cred.id);
    }
  }

  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("Credential retrieval cancelled or failed");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64url(response.authenticatorData),
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
  };
}
