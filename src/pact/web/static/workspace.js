const output = document.querySelector("#output");
const sessionStatus = document.querySelector("#session-status");
const worker = new Worker("/static/pyodide-worker.js");
const pending = new Map();
let identity = JSON.parse(localStorage.getItem("pact.identity") || "null");
let identityPassword = null;
let signedManifest = null;
let nonceBase64 = null;
let probeSet = null;

function pageButtons() {
  return [...document.querySelectorAll("[data-page-button]")];
}

function pages() {
  return [...document.querySelectorAll("[data-page]")];
}

function setPage(name) {
  for (const section of pages()) {
    section.hidden = section.dataset.page !== name;
  }
  for (const button of pageButtons()) {
    if (button.dataset.pageButton === name) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  }
}

function updateSession() {
  const authenticated = Boolean(identity);
  sessionStatus.textContent = authenticated
    ? identityPassword
      ? `Identity unlocked: ${identity.key_id}`
      : `Identity locked: ${identity.key_id}`
    : "No identity loaded.";
  for (const button of pageButtons()) {
    if (button.dataset.pageButton !== "identity") {
      button.disabled = !authenticated;
    }
  }
}

for (const button of pageButtons()) {
  button.onclick = () => setPage(button.dataset.pageButton);
}

worker.onmessage = (event) => {
  const { id, ok, result, error } = event.data;
  const callbacks = pending.get(id);
  if (!callbacks) {
    return;
  }
  pending.delete(id);
  if (ok) {
    callbacks.resolve(result);
  } else {
    callbacks.reject(new Error(error));
  }
};

function callPython(name, args = [], feature = null) {
  const id = crypto.randomUUID();
  const promise = new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
  });
  worker.postMessage({ id, name, args, feature });
  return promise;
}

function registryUrl() {
  return document.querySelector("#registry-url").value.trim();
}

function requireIdentity() {
  if (!identity) {
    setPage("identity");
    throw new Error("Create or import an identity first.");
  }
  return identity;
}

function password() {
  const value =
    identityPassword || document.querySelector("#identity-password").value;
  if (!value) {
    setPage("identity");
    throw new Error("Unlock the identity with its password first.");
  }
  return value;
}

function rememberPassword() {
  identityPassword = password();
  updateSession();
}

function show(value) {
  output.textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function readBase64(input) {
  const file = input.files[0];
  if (!file) {
    throw new Error("Choose a file first.");
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function readText(input) {
  const file = input.files[0];
  if (!file) {
    throw new Error("Choose a file first.");
  }
  return await file.text();
}

async function readImportFile(file) {
  const text = await file.text();
  const trimmed = text.trimStart();
  if (trimmed.startsWith("{")) {
    return JSON.parse(text);
  }
  if (!trimmed.includes("ENCRYPTED PRIVATE KEY")) {
    throw new Error(
      "Choose a browser identity JSON export or a CLI encrypted PKCS#8 PEM export."
    );
  }
  return {
    registry_url: registryUrl(),
    encrypted_pkcs8_b64: btoa(text)
  };
}

function selectedFileStem(input) {
  const file = input.files[0];
  if (!file) {
    return "pact";
  }
  return file.name.replace(/\.[^.]+$/, "");
}

function download(name, content, type = "application/json") {
  const blob = new Blob([content], { type });
  downloadBlob(name, blob);
}

function downloadBase64(name, content, type = "application/octet-stream") {
  const binary = atob(content);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  downloadBlob(name, new Blob([bytes], { type }));
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

async function registryJson(path, options = {}) {
  const response = await fetch(`${registryUrl()}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.detail || response.statusText);
  }
  return body;
}

async function challenge(purpose, boundKeyId = null) {
  return await registryJson("/api/v1/challenges", {
    method: "POST",
    body: JSON.stringify({
      purpose,
      difficulty: 4,
      ...(boundKeyId ? { bound_key_id: boundKeyId } : {})
    })
  });
}

async function browserFingerprint() {
  const values = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory || null,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: [
      screen.width,
      screen.height,
      screen.colorDepth,
      devicePixelRatio
    ]
  };
  const encoded = new TextEncoder().encode(
    `${registryUrl()}:${JSON.stringify(values)}`
  );
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function signedMutation(purpose, payload, boundKeyId = null) {
  const currentIdentity = requireIdentity();
  const issued = await challenge(purpose, boundKeyId);
  return JSON.parse(
    await callPython("create_mutation_request", [
      registryUrl(),
      currentIdentity.encrypted_pkcs8_b64,
      password(),
      JSON.stringify(issued),
      JSON.stringify(payload)
    ])
  );
}

async function run(handler) {
  try {
    show("Working...");
    await handler();
  } catch (error) {
    show(`Error: ${error.message}`);
  }
}

document.querySelector("#create-identity").onclick = () =>
  run(async () => {
    identity = JSON.parse(
      await callPython("create_identity", [registryUrl(), password()])
    );
    rememberPassword();
    localStorage.setItem("pact.identity", JSON.stringify(identity));
    updateSession();
    setPage("claims");
    show(identity);
  });

document.querySelector("#unlock-identity").onclick = () =>
  run(async () => {
    const currentIdentity = requireIdentity();
    await callPython("import_identity", [
      registryUrl(),
      currentIdentity.encrypted_pkcs8_b64,
      password()
    ]);
    rememberPassword();
    show("Identity unlocked for this browser session.");
  });

document.querySelector("#show-identity").onclick = () =>
  run(async () => {
    identity =
      identity || JSON.parse(localStorage.getItem("pact.identity") || "null");
    if (!identity) {
      throw new Error("No browser identity is stored.");
    }
    show({
      registry_url: identity.registry_url,
      key_id: identity.key_id,
      public_jwk: identity.public_jwk
    });
  });

document.querySelector("#export-identity").onclick = () =>
  run(async () => {
    if (!identity) {
      throw new Error("No browser identity is stored.");
    }
    download("pact-identity.json", JSON.stringify(identity, null, 2));
    show("Encrypted identity downloaded.");
  });

document.querySelector("#identity-import").onchange = (event) =>
  run(async () => {
    const imported = await readImportFile(event.target.files[0]);
    const publicIdentity = JSON.parse(await callPython("import_identity", [
      registryUrl(),
      imported.encrypted_pkcs8_b64,
      password()
    ]));
    identity = {
      ...imported,
      registry_url: publicIdentity.registry_url,
      key_id: publicIdentity.key_id,
      public_jwk: publicIdentity.public_jwk
    };
    rememberPassword();
    localStorage.setItem("pact.identity", JSON.stringify(identity));
    updateSession();
    setPage("claims");
    show("Identity imported and verified.");
  });

document.querySelector("#register-profile").onclick = () =>
  run(async () => {
    const displayName = document.querySelector("#display-name").value.trim();
    const request = await signedMutation("profile_registration", {
      ...(displayName ? { display_name: displayName } : {}),
      hosted_account: false,
      device_fingerprint: await browserFingerprint()
    });
    const profile = await registryJson("/api/v1/profiles", {
      method: "POST",
      body: JSON.stringify(request)
    });
    show(profile);
  });

document.querySelector("#sign-content").onclick = () =>
  run(async () => {
    const registry = await registryJson("/api/v1/registry");
    const content = await readBase64(document.querySelector("#content-file"));
    const currentIdentity = requireIdentity();
    const result = JSON.parse(
      await callPython("sign_content", [
        registryUrl(),
        currentIdentity.encrypted_pkcs8_b64,
        password(),
        content,
        registry.root_fingerprint,
        document.querySelector("#mime-type").value || "text/plain",
        document.querySelector("#canonicalization").value
      ])
    );
    signedManifest = result.manifest_json;
    nonceBase64 = result.nonce_b64;
    const stem = selectedFileStem(document.querySelector("#content-file"));
    download(`${stem}.manifest.json`, signedManifest);
    downloadBase64(`${stem}.nonce`, nonceBase64);
    show(result);
  });

document.querySelector("#go-register-claim").onclick = () => setPage("claims");

document.querySelector("#register-claim").onclick = () =>
  run(async () => {
    if (!signedManifest) {
      signedManifest = await readText(
        document.querySelector("#claim-manifest-file")
      );
    }
    const currentIdentity = requireIdentity();
    const request = await signedMutation(
      "claim_registration",
      { signed_manifest_json: signedManifest },
      currentIdentity.key_id
    );
    const claim = await registryJson("/api/v1/claims", {
      method: "POST",
      body: JSON.stringify(request)
    });
    show(claim);
  });

document.querySelector("#revoke-claim").onclick = () =>
  run(async () => {
    const claimId = document.querySelector("#revoke-claim-id").value.trim();
    if (!claimId) {
      throw new Error("Enter the claim ID to revoke.");
    }
    const request = await signedMutation(
      "claim_revocation",
      {
        claim_id: claimId,
        reason:
          document.querySelector("#revoke-reason").value.trim() ||
          "revoked by claimant"
      },
      requireIdentity().key_id
    );
    const claim = await registryJson(`/api/v1/claims/${claimId}/revoke`, {
      method: "POST",
      body: JSON.stringify(request)
    });
    show(claim);
  });

document.querySelector("#verify-manifest").onclick = () =>
  run(async () => {
    const manifest =
      signedManifest || (await readText(document.querySelector("#manifest-file")));
    const parsed = JSON.parse(manifest);
    const profile = await registryJson(
      `/api/v1/profiles/${parsed.manifest.claimant_key_id}`
    );
    const result = await callPython("verify_manifest_json", [
      manifest,
      JSON.stringify(profile.public_jwk),
      document.querySelector("#verify-content-file").files[0]
        ? await readBase64(document.querySelector("#verify-content-file"))
        : null,
      document.querySelector("#nonce-file").files[0]
        ? await readBase64(document.querySelector("#nonce-file"))
        : nonceBase64
    ]);
    show(result);
  });

document.querySelector("#audit-manifest").onclick = () =>
  run(async () => {
    const manifest =
      signedManifest || (await readText(document.querySelector("#manifest-file")));
    const result = await callPython("privacy_audit", [
      manifest,
      document.querySelector("#verify-content-file").files[0]
        ? await readBase64(document.querySelector("#verify-content-file"))
        : null,
      document.querySelector("#nonce-file").files[0]
        ? await readBase64(document.querySelector("#nonce-file"))
        : nonceBase64
    ]);
    show(result);
  });

document.querySelector("#watermark-text").onclick = () =>
  run(async () => {
    const result = JSON.parse(
      await callPython("watermark_text", [
        document.querySelector("#watermark-text-input").value,
        document.querySelector("#watermark-secret").value,
        JSON.stringify(
          document
            .querySelector("#watermark-methods")
            .value.split(",")
            .map((method) => method.trim())
            .filter(Boolean)
        ),
        document.querySelector("#canary-phrase").value || null
      ])
    );
    download(
      "pact-watermarked.txt",
      result.transformed_content,
      "text/plain"
    );
    show(result);
  });

document.querySelector("#watermark-image").onclick = () =>
  run(async () => {
    const registry = await registryJson("/api/v1/registry");
    const imageBase64 = await readBase64(
      document.querySelector("#watermark-image-file")
    );
    const result = JSON.parse(
      await callPython(
        "watermark_image",
        [
          imageBase64,
          document.querySelector("#watermark-image-mime-type").value ||
            "image/png",
          document.querySelector("#watermark-claim-id").value,
          registry.root_fingerprint
        ],
        "image-watermarks"
      )
    );
    download(
      "pact-watermarked-image.b64",
      result.image_b64,
      "text/plain"
    );
    show(result);
  });

document.querySelector("#embed-document").onclick = () =>
  run(async () => {
    const mimeType =
      document.querySelector("#document-mime-type").value || "application/pdf";
    const documentBase64 = await readBase64(document.querySelector("#document-file"));
    const storeBase64 = await readBase64(
      document.querySelector("#manifest-store-file")
    );
    const result = await callPython(
      mimeType === "application/pdf"
        ? "embed_pdf_manifest"
        : "embed_zip_document_manifest",
      mimeType === "application/pdf"
        ? [documentBase64, storeBase64]
        : [documentBase64, mimeType, storeBase64],
      "documents"
    );
    show(result);
  });

document.querySelector("#extract-document").onclick = () =>
  run(async () => {
    const mimeType =
      document.querySelector("#document-mime-type").value || "application/pdf";
    const documentBase64 = await readBase64(document.querySelector("#document-file"));
    const result = await callPython(
      mimeType === "application/pdf"
        ? "extract_pdf_manifest"
        : "extract_zip_document_manifest",
      [documentBase64],
      "documents"
    );
    show(result);
  });

document.querySelector("#create-probes").onclick = () =>
  run(async () => {
    const result = await callPython("create_probes", [
      JSON.stringify([document.querySelector("#protected-text").value]),
      JSON.stringify([document.querySelector("#control-text").value]),
      document.querySelector("#target-model").value
    ]);
    probeSet = result;
    download("pact-probes.json", result);
    show(result);
  });

document.querySelector("#analyze-probes").onclick = () =>
  run(async () => {
    if (!probeSet) {
      throw new Error("Create probes first.");
    }
    const result = await callPython("analyze_probes", [
      probeSet,
      document.querySelector("#responses-jsonl").value
    ]);
    download("pact-probe-evidence.json", result);
    show(result);
  });

updateSession();
setPage(identity ? "claims" : "identity");
show(
  identity
    ? "Identity loaded. Choose an action page."
    : "Pyodide worker ready. Create or import an identity to begin."
);
