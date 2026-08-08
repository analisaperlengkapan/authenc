// Drives the browser half of a WebAuthn registration.
//
// `navigator.credentials` is a browser API that speaks ArrayBuffers, and the
// server speaks JSON. Something has to convert between them. Doing it here, in
// forty lines the server hosts itself, is smaller and easier to read than the
// `web-sys` bindings and the wasm-bindgen glue the same conversion needs on the
// Rust side — and none of the security lives here. Every value this file
// produces is verified on the server against a challenge the server chose and
// stored; a tampered response fails there.
//
// No CDN, no bundler, no dependencies. The previous console pulled Font Awesome
// from a third-party origin with no integrity hash, into an admin console.

'use strict';

/** base64url → Uint8Array. The encoding WebAuthn uses everywhere. */
function fromBase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Uint8Array | ArrayBuffer → base64url, unpadded. */
function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Call a Leptos server function and return its JSON result. */
async function callServerFn(endpoint, body) {
  const response = await fetch(`/api/sfn/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // The session and ceremony cookies travel with it; nothing here reads them.
    credentials: 'same-origin',
    body: JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || `request failed with ${response.status}`);
  }
  return text ? JSON.parse(text) : null;
}

/** Turn the server's challenge into what `navigator.credentials` expects. */
function decodeCreationOptions(challenge) {
  const options = challenge.publicKey;
  return {
    publicKey: {
      ...options,
      challenge: fromBase64Url(options.challenge),
      user: { ...options.user, id: fromBase64Url(options.user.id) },
      excludeCredentials: (options.excludeCredentials ?? []).map((credential) => ({
        ...credential,
        id: fromBase64Url(credential.id),
      })),
    },
  };
}

/** Turn the authenticator's answer back into JSON the server can parse. */
function encodeCredential(credential) {
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    // `webauthn-rs` reads this to learn how the credential was obtained.
    extensions: credential.getClientExtensionResults(),
    response: {
      attestationObject: toBase64Url(credential.response.attestationObject),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
    },
  };
}

async function registerPasskey() {
  const challenge = await callServerFn('mfa/passkey/register/begin');
  const credential = await navigator.credentials.create(decodeCreationOptions(challenge));
  if (!credential) {
    throw new Error('the authenticator returned nothing');
  }

  const label = window.prompt('Name this passkey', 'Passkey') ?? 'Passkey';
  await callServerFn('mfa/passkey/register/finish', {
    label,
    credential: encodeCredential(credential),
  });

  // A full reload, so the page re-renders from the server with the new key in
  // the list rather than this file reaching into the Leptos DOM.
  window.location.reload();
}

function wire() {
  const button = document.getElementById('register-passkey');
  if (!button || button.dataset.wired === 'true') {
    return;
  }
  button.dataset.wired = 'true';

  button.addEventListener('click', async () => {
    const problem = document.getElementById('passkey-error');
    if (problem) {
      problem.textContent = '';
    }

    if (!window.PublicKeyCredential) {
      if (problem) {
        problem.textContent = 'This browser does not support passkeys.';
      }
      return;
    }

    button.disabled = true;
    try {
      await registerPasskey();
    } catch (error) {
      // `NotAllowedError` is the user cancelling or the ceremony timing out,
      // which is not a failure worth alarming them about.
      const cancelled = error && error.name === 'NotAllowedError';
      if (problem) {
        problem.textContent = cancelled
          ? 'Registration was cancelled.'
          : `Could not register a passkey: ${error.message ?? error}`;
      }
    } finally {
      button.disabled = false;
    }
  });
}

// The button arrives with the server-rendered HTML, and again after Leptos
// hydrates and on client-side navigation — hence both hooks and the `wired`
// guard above.
document.addEventListener('DOMContentLoaded', wire);
window.addEventListener('load', wire);
document.addEventListener('click', wire, { capture: true, once: false });
