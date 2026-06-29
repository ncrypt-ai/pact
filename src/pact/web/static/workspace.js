const workspaceMessage = document.querySelector("#workspace-message");
const sessionStatus = document.querySelector("#session-status");
const worker = new Worker("/static/pyodide-worker.js");
const pending = new Map();
const identityStorageKey = "pact.identity";
const identitiesStorageKey = "pact.identities";
const selectedIdentityStorageKey = "pact.selectedIdentity";
const passcodeStorageKey = "pact.passcode";
function parseStoredJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key) || "null") || fallback;
  } catch {
    return fallback;
  }
}

function identityLabel(record) {
  const name = record.display_name || record.key_id || "Unregistered profile";
  const key = record.key_id ? `${record.key_id.slice(0, 12)}...` : "pending";
  return `${name} (${key})`;
}

function savedIdentities() {
  const stored = parseStoredJson(identitiesStorageKey, []);
  const identities = Array.isArray(stored) ? stored.filter(Boolean) : [];
  const legacy = parseStoredJson(identityStorageKey, null);
  if (legacy && !identities.some((item) => item.key_id === legacy.key_id)) {
    identities.unshift(legacy);
    saveIdentities(identities);
  }
  return identities;
}

function saveIdentities(identities) {
  localStorage.setItem(identitiesStorageKey, JSON.stringify(identities));
}

function selectedIdentityKey() {
  return localStorage.getItem(selectedIdentityStorageKey);
}

function savedIdentity() {
  const identities = savedIdentities();
  if (!identities.length) {
    return null;
  }
  const selectedKey = selectedIdentityKey();
  if (selectedKey) {
    const selected = identities.find((item) => item.key_id === selectedKey);
    if (selected) {
      return selected;
    }
  }
  return identities[0];
}

function saveIdentity(record) {
  const identities = savedIdentities();
  const index = identities.findIndex((item) => item.key_id === record.key_id);
  if (index === -1) {
    identities.unshift(record);
  } else {
    identities[index] = { ...identities[index], ...record };
  }
  saveIdentities(identities);
  localStorage.setItem(selectedIdentityStorageKey, record.key_id);
  localStorage.setItem(identityStorageKey, JSON.stringify(record));
}

function forgetSavedPasscode() {
  localStorage.removeItem(passcodeStorageKey);
}

let identity = savedIdentity();
let identityPassword = null;
let creatingIdentity = !identity;
let signedManifest = null;
let nonceBase64 = null;

const policyPermissions = [
  ["cawg.data_mining", "Data mining"],
  ["cawg.ai_inference", "AI inference"],
  ["cawg.ai_generative_training", "Generative AI training"],
  ["cawg.ai_training", "Non-generative AI training"],
  ["pact.commercial_training", "Commercial training"],
  ["pact.noncommercial_training", "Noncommercial training"],
  ["pact.fine_tuning", "Fine tuning"],
  ["pact.embedding", "Embeddings"],
  ["pact.model_evaluation", "Model evaluation"],
  ["pact.synthetic_data", "Synthetic-data generation"],
  ["pact.search_indexing", "Search indexing"],
  ["pact.redistribution", "Redistribution"]
];

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

function setVisible(selector, visible) {
  const element = document.querySelector(selector);
  if (element) {
    element.hidden = !visible;
  }
}

function embeddedProofSupported(mimeType) {
  return (
    mimeType.startsWith("text/") ||
    [
      "text/html",
      "application/xhtml+xml",
      "application/xml",
      "text/xml",
      "image/svg+xml",
      "application/pdf",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/epub+zip"
    ].includes(mimeType)
  );
}

function updateSigningOptions() {
  setVisible("#text-protection-options", true);
  setVisible("#image-protection-options", true);
  setVisible("#embedded-proof-options", true);
}

function updateMutationOptions() {
  setVisible("#mutation-embedded-proof-options", true);
}

function updateSession() {
  const profiles = savedIdentities();
  const hasProfile = !creatingIdentity && Boolean(identity || savedIdentity());
  const unlocked = Boolean(identity && identityPassword);
  sessionStatus.textContent = hasProfile
    ? identityPassword
      ? `Signed in as ${identityLabel(identity)}.`
      : profiles.length > 1
        ? "Choose a saved profile and enter its passcode."
        : "Saved profile found."
    : "No profile loaded.";
  document.querySelector("#logout-identity").hidden = !hasProfile;
  for (const button of pageButtons()) {
    if (button.dataset.pageButton !== "identity") {
      button.disabled = !unlocked;
    }
  }
  updateIdentityControls();
}

function updateIdentityControls() {
  const profiles = savedIdentities();
  const hasProfile = !creatingIdentity && Boolean(identity || savedIdentity());
  const unlocked = Boolean(identity && identityPassword);
  const selectorField = document.querySelector("#saved-profiles-field");
  const selector = document.querySelector("#identity-selector");
  const displayNameField = document.querySelector("#identity-display-name-field");
  const guidance = document.querySelector("#identity-guidance");
  const passcodeHint = document.querySelector("#identity-passcode-hint");
  const continueButton = document.querySelector("#continue-identity");
  const newButton = document.querySelector("#new-identity");

  selectorField.hidden = profiles.length === 0 || creatingIdentity;
  selector.replaceChildren();
  for (const record of profiles) {
    const option = document.createElement("option");
    option.value = record.key_id;
    option.textContent = identityLabel(record);
    option.selected = identity && record.key_id === identity.key_id;
    selector.append(option);
  }

  displayNameField.hidden = hasProfile;
  newButton.hidden = profiles.length === 0;
  if (hasProfile && !unlocked) {
    continueButton.textContent = "Unlock saved profile";
    passcodeHint.textContent = "Required to decrypt the selected saved profile before PACT can show private profile information, sign files, register edits, or download a recovery file.";
    guidance.textContent = profiles.length > 1
      ? "Choose the profile you want to use, enter its passcode, then press Unlock saved profile."
      : "Saved profile is locked. Enter its passcode, then press Unlock saved profile.";
  } else if (hasProfile) {
    continueButton.textContent = "Continue to signing";
    passcodeHint.textContent = "This profile is already unlocked in this tab.";
    guidance.textContent = `Profile is unlocked for this tab session: ${identityLabel(identity)}.`;
  } else {
    continueButton.textContent = "Create profile";
    passcodeHint.textContent = "Required to encrypt this browser profile. PACT cannot recover it for you.";
    guidance.textContent = profiles.length
      ? "Create a new browser profile, or choose a saved profile above to unlock it."
      : "No browser profile is saved here. Choose a passcode, optionally add a display name, then press Create profile.";
  }
}

function showSavedBrowserProfile() {
  const current = creatingIdentity ? null : identity || savedIdentity();
  if (!current) {
    clearElement(document.querySelector("#browser-profile-summary"));
    return;
  }
  identity = current;
  renderObject("#browser-profile-summary", "Saved browser profile", [
    ["What this is", "The private signing profile saved in this browser."],
    ["Profile ID", current.key_id],
    ["Registry", current.registry_url],
    [
      "Status",
      identityPassword ? "Unlocked for this tab session" : "Locked. Enter passcode to use it."
    ],
    [
      "Next action",
      identityPassword ? "Continue to signing." : "Enter passcode and press Unlock saved profile."
    ]
  ]);
}

for (const button of pageButtons()) {
  button.onclick = () => setPage(button.dataset.pageButton);
}

function buildPolicyControls(containerId) {
  const container = document.querySelector(containerId);
  if (!container) {
    return;
  }
  const table = document.createElement("table");
  table.className = "policy-table";
  const head = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const heading of ["Use", "Permission", "Conditions", "License URL"]) {
    const cell = document.createElement("th");
    cell.textContent = heading;
    headRow.append(cell);
  }
  head.append(headRow);
  table.append(head);
  const body = document.createElement("tbody");
  for (const [permission, label] of policyPermissions) {
    const rowElement = document.createElement("tr");
    rowElement.dataset.permission = permission;
    const labelCell = document.createElement("td");
    labelCell.textContent = label;
    const valueCell = document.createElement("td");
    const select = document.createElement("select");
    select.className = "policy-value";
    for (const [value, text] of [
      ["notAllowed", "Not allowed"],
      ["allowed", "Allowed"],
      ["constrained", "Allowed with conditions"]
    ]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = text;
      select.append(option);
    }
    valueCell.append(select);
    const conditionCell = document.createElement("td");
    const condition = document.createElement("input");
    condition.className = "policy-condition";
    condition.placeholder = "Required if conditional";
    conditionCell.append(condition);
    const licenseCell = document.createElement("td");
    const license = document.createElement("input");
    license.className = "policy-license";
    license.type = "url";
    license.placeholder = "Optional";
    licenseCell.append(license);
    rowElement.append(labelCell, valueCell, conditionCell, licenseCell);
    body.append(rowElement);
  }
  table.append(body);
  container.append(table);
}

buildPolicyControls("#sign-policy");
buildPolicyControls("#mutation-policy");

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

function publicBaseUrl() {
  return document.body.dataset.publicBaseUrl || registryUrl();
}

function requireIdentity() {
  if (!identity) {
    setPage("identity");
    throw new Error("Create or open your profile first.");
  }
  return identity;
}

function password() {
  const value =
    identityPassword ||
    document.querySelector("#identity-passcode").value ||
    document.querySelector("#identity-import-password").value;
  if (!value) {
    setPage("identity");
    throw new Error(
      "Enter the passcode for the selected saved profile to unlock its private signing key."
    );
  }
  return value;
}

function rememberPassword() {
  identityPassword = password();
  forgetSavedPasscode();
  updateSession();
}

function plainError(error) {
  const message = error && error.message ? error.message : String(error);
  if (
    message.includes("already registered to another claimant profile") ||
    message.includes("claimant profile already exists")
  ) {
    return "A profile already exists for this browser or signing key. Open the saved browser profile with its passcode, or import your recovery file instead of creating a new profile.";
  }
  if (message.includes("Traceback")) {
    const lines = message
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    return lines[lines.length - 1].replace(/^[A-Za-z]+Error:\s*/, "");
  }
  if (message.includes("internal server error")) {
    return "Something went wrong on the registry. Try again or check the server logs.";
  }
  return message.replace(/^Error:\s*/, "");
}

function clearValidation() {
  for (const element of document.querySelectorAll("[aria-invalid='true']")) {
    element.removeAttribute("aria-invalid");
  }
}

function validationError(element, text) {
  if (element) {
    element.setAttribute("aria-invalid", "true");
    element.focus();
  }
  throw new Error(text);
}

function selectIdentity(keyId) {
  const selected = savedIdentities().find((item) => item.key_id === keyId);
  if (!selected) {
    return;
  }
  identity = selected;
  identityPassword = null;
  creatingIdentity = false;
  localStorage.setItem(selectedIdentityStorageKey, selected.key_id);
  localStorage.setItem(identityStorageKey, JSON.stringify(selected));
  document.querySelector("#identity-passcode").value = "";
  clearElement(document.querySelector("#public-profile-summary"));
  updateSession();
  showSavedBrowserProfile();
  setPage("identity");
  message(
    `Selected ${identityLabel(selected)}. Enter this profile's passcode to unlock private profile information.`
  );
}

function message(text, level = "info") {
  workspaceMessage.textContent = text;
  workspaceMessage.dataset.level = level;
}

function clearElement(element) {
  element.replaceChildren();
  element.hidden = true;
}

function resultElement(id) {
  const element = document.querySelector(id);
  clearElement(element);
  element.hidden = false;
  return element;
}

function row(label, value) {
  const item = document.createElement("p");
  const strong = document.createElement("strong");
  strong.textContent = `${label}: `;
  item.append(strong, value == null || value === "" ? "—" : String(value));
  return item;
}

function callout(text) {
  const paragraph = document.createElement("p");
  paragraph.className = "bottom-line";
  paragraph.textContent = text;
  return paragraph;
}

function renderObject(target, title, values) {
  const element = resultElement(target);
  const heading = document.createElement("h3");
  heading.textContent = title;
  element.append(heading);
  for (const [label, value] of values) {
    element.append(row(label, value));
  }
  return element;
}

function renderList(target, title, rows, emptyText) {
  const element = resultElement(target);
  const heading = document.createElement("h3");
  heading.textContent = title;
  element.append(heading);
  if (!rows.length) {
    element.append(row("Status", emptyText));
    return element;
  }
  const list = document.createElement("ol");
  for (const values of rows) {
    const item = document.createElement("li");
    for (const [label, value] of values) {
      item.append(row(label, value));
    }
    list.append(item);
  }
  element.append(list);
  return element;
}

function renderProfile(target, profile, evidence = null) {
  const authLevel = evidence ? evidence.trust_tier : "unauthenticated_device";
  const trustLabels =
    evidence && evidence.trust_labels && evidence.trust_labels.length
      ? evidence.trust_labels.join(", ")
      : "unauthenticated_device";
  const element = renderObject(target, "Public registry profile", [
    ["Display name", profile.display_name || "Anonymous"],
    ["Profile ID", profile.key_id],
    ["Created", profile.created_at],
    ["Auth level", authLevel],
    ["Verified domains", (profile.verified_domains || []).join(", ") || "None"],
    ["Hosted account", profile.hosted_account ? "Yes" : "No"],
    ["Third-party attested", profile.third_party_attested ? "Yes" : "No"],
    ["Documented rights", profile.documented_rights ? "Yes" : "No"],
    ["Replacement key", profile.replacement_key_id || "None"],
    ["Trust tier", authLevel],
    ["Trust labels", trustLabels],
    ["Active claims", evidence ? evidence.active_claim_count : "Not loaded"],
    ["Revoked claims", evidence ? evidence.revoked_claim_count : "Not loaded"],
    ["Open disputes", evidence ? evidence.open_disputes : "Not loaded"],
    ["Upheld disputes", evidence ? evidence.upheld_disputes : "Not loaded"],
    ["Rejected disputes", evidence ? evidence.rejected_disputes : "Not loaded"],
    ["Certificates", evidence ? evidence.certificate_count : "Not loaded"],
    ["Key rotations", evidence ? evidence.rotation_count : "Not loaded"]
  ]);
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Raw profile data";
  const raw = document.createElement("pre");
  raw.textContent = JSON.stringify({ profile, evidence }, null, 2);
  details.append(summary, raw);
  element.append(details);
}

function renderClaims(claims) {
  renderList(
    "#claims-result",
    "Published claims",
    claims.map((claim) => [
      ["Claim ID", claim.claim_id],
      ["Registered", claim.registered_at],
      [
        "Source URL",
        claim.signed_manifest &&
        claim.signed_manifest.manifest &&
        claim.signed_manifest.manifest.source_url
          ? claim.signed_manifest.manifest.source_url
          : "—"
      ],
      ["Status", claim.revoked_at ? "Revoked" : "Active"],
      ["Revocation reason", claim.revocation_reason || "—"]
    ]),
    "No published claims found for this profile."
  );
}

function claimRows(claim) {
  const manifest =
    claim.signed_manifest && claim.signed_manifest.manifest
      ? claim.signed_manifest.manifest
      : {};
  return [
    ["Claim ID", claim.claim_id],
    ["Profile ID", claim.claimant_key_id],
    ["Registered", claim.registered_at],
    ["Source URL", manifest.source_url || "—"],
    ["MIME type", manifest.mime_type || "—"],
    ["Status", claim.revoked_at ? "Revoked" : "Active"],
    ["Revocation reason", claim.revocation_reason || "—"]
  ];
}

function renderClaim(target, claim, disputes = []) {
  const element = renderObject(target, "Published claim", [
    ...claimRows(claim),
    ["Verification page", `${publicBaseUrl()}/verify/claim/${claim.claim_id}`],
    ["Open disputes", disputes.length]
  ]);
  if (disputes.length) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Disputes";
    details.append(summary);
    for (const dispute of disputes) {
      details.append(row("Dispute", `${dispute.status}: ${dispute.reason}`));
      details.append(row("Dispute ID", dispute.dispute_id));
    }
    element.append(details);
  }
}

function renderDisputes(target, disputes) {
  renderList(
    target,
    "Disputes",
    disputes.map((dispute) => [
      ["Dispute ID", dispute.dispute_id],
      ["Claim ID", dispute.claim_id],
      ["Status", dispute.status],
      ["Opened", dispute.opened_at],
      ["Misuse URL", dispute.misuse_url || "—"],
      ["Reason", dispute.reason],
      ["Resolution", dispute.resolution_note || "—"]
    ]),
    "No disputes found."
  );
}

function claimIdFromInspection(result) {
  const reference = result.reference || {};
  const verification = result.registry_verification || {};
  const manifest = result.manifest || {};
  return reference.claim_id || verification.claim_id || manifest.claim_id || null;
}

function claimantKeyFromInspection(result) {
  const claim = result.registry_claim || {};
  const manifest = result.manifest || {};
  return claim.claimant_key_id || manifest.claimant_key_id || null;
}

async function inspectionContext(result) {
  const claimId = claimIdFromInspection(result);
  const claimantKey = claimantKeyFromInspection(result);
  const context = {
    claimDisputes: [],
    claimantDisputes: [],
    claimantEvidence: null
  };
  if (claimId) {
    const disputes = await registryJson(`/api/v1/claims/${claimId}/disputes`);
    context.claimDisputes = disputes.disputes || [];
  }
  if (claimantKey) {
    const evidence = await registryJson(`/api/v1/profiles/${claimantKey}/evidence`);
    const disputes = await registryJson(`/api/v1/profiles/${claimantKey}/disputes`);
    context.claimantEvidence = evidence;
    context.claimantDisputes = disputes.disputes || [];
  }
  return context;
}

function renderInspection(result, context = {}) {
  const reference = result.reference || {};
  const manifest = result.manifest || {};
  const claim = result.registry_claim || {};
  const verification = result.registry_verification || {};
  const claimDisputes = context.claimDisputes || [];
  const claimantDisputes = context.claimantDisputes || [];
  const claimantEvidence = context.claimantEvidence || null;
  const element = resultElement("#inspect-result");
  const title = document.createElement("h3");
  title.textContent = "Bottom line";
  element.append(title);
  if (!result.recognized) {
    element.append(callout("No PACT proof or claim reference was found in this file."));
  } else if (verification.revoked) {
    element.append(callout("A claim exists, but it has been revoked."));
  } else if (verification.disputed) {
    element.append(callout("A claim exists, but there are open or upheld disputes."));
  } else if (verification.label === "content_claim_verified") {
    element.append(callout("The claim is current and this file matches the signed content commitment."));
  } else if (verification.label === "claim_verified_content_unchecked") {
    element.append(callout("The claim is current, but this page has not checked the file content."));
  } else if (verification.label === "claim_verified_content_private") {
    element.append(callout("The claim is current, but the content check key is private. Ask the claimant for the nonce to verify this exact file."));
  } else if (verification.label === "content_mismatch") {
    element.append(callout("The claim is current, but this file does not match the signed content commitment."));
  } else if (reference.claim_id || manifest.claim_id) {
    element.append(callout("A claim reference exists, but registry verification is incomplete."));
  } else {
    element.append(callout("PACT metadata was found, but no registry claim was confirmed."));
  }
  const details = document.createElement("details");
  details.open = true;
  const summary = document.createElement("summary");
  summary.textContent = "What PACT found";
  details.append(summary);
  for (const [label, value] of [
    ["Recognized", result.recognized ? "Yes" : "No"],
    ["Carrier", reference.carrier || "None found"],
    ["Claim ID", claimIdFromInspection(result) || "None found"],
    ["What was proven", verification.label || "No registry verification"],
    ["Claim signature", verification.manifest_signature_valid ?? "Not checked"],
    ["Content binding", verification.content_binding_valid ?? "Not checked"],
    ["Public content check key", verification.public_nonce_available ?? "Unknown"],
    ["Source URL", manifest.source_url || "None provided"],
    ["Requested protection", policySummary(manifest.policy)],
    [
      "Claimed actions",
      manifestActions(manifest).map(actionSummary).join("; ") ||
        "None claimed"
    ],
    [
      "Source ingredients",
      manifestIngredients(manifest).map(ingredientSummary).join("; ") ||
        "None claimed"
    ],
    ["Profile ID", claimantKeyFromInspection(result) || "Unknown"],
    ["Registered", claim.registered_at || "Unknown"],
    ["Registry status", verification.label || "Not verified through registry"],
    ["Trust level", verification.trust_tier || (claimantEvidence ? claimantEvidence.trust_tier : "Unknown")],
    ["Trust labels", (verification.trust_labels || []).join(", ") || "None"],
    ["Content binding", verification.content_binding_valid],
    ["Revoked", verification.revoked],
    ["Disputed", verification.disputed],
    ["Disputes on this media", claimDisputes.length],
    ["Disputes on profile media", claimantDisputes.length],
    ["Profile active claims", claimantEvidence ? claimantEvidence.active_claim_count : "Unknown"]
  ]) {
    details.append(row(label, value));
  }
  element.append(details);
  if (claimDisputes.length) {
    const disputes = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Disputes against this media";
    disputes.append(summary);
    for (const dispute of claimDisputes) {
      disputes.append(row("Dispute", `${dispute.status}: ${dispute.reason}`));
      disputes.append(row("Misuse URL", dispute.misuse_url || "—"));
    }
    element.append(disputes);
  }
  const claimId = claimIdFromInspection(result);
  if (claimId && verification.public_nonce_available) {
    const reportButton = document.createElement("button");
    reportButton.type = "button";
    reportButton.className = "secondary-action";
    reportButton.textContent = "Report possible provenance avoidance";
    reportButton.onclick = () => submitAvoidanceReport(result, claimId);
    element.append(reportButton);
  } else if (claimId && verification.public_nonce_available === false) {
    element.append(callout("Reporting disabled: this claim uses private content verification."));
  }
  console.log(result);
}

async function submitAvoidanceReport(result, claimId) {
  const observedUrl = window.prompt("Where did you see it? URL or blank:") || "";
  const description = window.prompt("What looks suspicious?") || "";
  if (!description.trim() && !observedUrl.trim()) {
    throw new Error("Add a URL or a short description before reporting.");
  }
  const response = await registryJson("/api/v1/reports/avoidance", {
    method: "POST",
    body: JSON.stringify({
      claim_id: claimId,
      observed_url: observedUrl.trim() || null,
      reason: "possible_avoidance",
      description: description.trim() || null,
      evidence: {
        kind: "hash_only",
        digest: result.input ? result.input.sha256 : "unknown",
        mime_type: result.input ? result.input.mime_type : null
      }
    })
  });
  const element = resultElement("#inspect-result");
  element.append(callout(`Report submitted: ${response.report_id}`));
}

function policySummary(policy) {
  if (!policy) {
    return "Unknown";
  }
  if (policy.label === "cawg.training-mining" && policy.entries) {
    return policySummary(policy.entries);
  }
  const entries = Object.entries(policy);
  if (entries.length > 1) {
    const blocked = entries
      .filter(([, entry]) => entry.use === "notAllowed")
      .map(([permission]) => permission);
    const allowed = entries
      .filter(([, entry]) => entry.use === "allowed")
      .map(([permission]) => permission);
    const constrained = entries
      .filter(([, entry]) => entry.use === "constrained")
      .map(([permission]) => permission);
    return [
      blocked.length ? `${blocked.length} not allowed` : null,
      allowed.length ? `${allowed.length} allowed` : null,
      constrained.length ? `${constrained.length} conditional` : null
    ].filter(Boolean).join(", ");
  }
  const training =
    policy["cawg.ai_generative_training"] ||
    policy["cawg.ai_training"] ||
    policy["cawg.data_mining"];
  if (!training) {
    return "No explicit AI-training permission found";
  }
  if (training.use === "notAllowed") {
    return "AI training not allowed";
  }
  if (training.use === "allowed") {
    return "AI training allowed";
  }
  if (training.use === "constrained") {
    return `AI training constrained: ${training.constraint_info || "see proof"}`;
  }
  return String(training.use || "Unknown");
}

function collectPolicy(containerId) {
  const policy = {};
  for (const rowElement of document.querySelectorAll(`${containerId} tr[data-permission]`)) {
    const permission = rowElement.dataset.permission;
    const value = rowElement.querySelector(".policy-value").value;
    const condition = rowElement.querySelector(".policy-condition").value.trim();
    const license = rowElement.querySelector(".policy-license").value.trim();
    if (value === "constrained" && !condition) {
      validationError(
        rowElement.querySelector(".policy-condition"),
        `Add conditions for ${rowElement.firstChild.textContent}.`
      );
    }
    policy[permission] = {
      use: value,
      ...(condition ? { constraint_info: condition } : {}),
      ...(license ? { licensing_url: license } : {})
    };
  }
  return policy;
}

function manifestActions(manifest) {
  if (
    !manifest ||
    !manifest.actions ||
    !Array.isArray(manifest.actions.actions)
  ) {
    return [];
  }
  return manifest.actions.actions;
}

function manifestIngredients(manifest) {
  if (
    !manifest ||
    !manifest.ingredients ||
    !Array.isArray(manifest.ingredients.ingredients)
  ) {
    return [];
  }
  return manifest.ingredients.ingredients;
}

function actionSummary(action) {
  const parts = [action.action || "unknown action"];
  if (action.description) {
    parts.push(action.description);
  }
  if (action.when) {
    parts.push(action.when);
  }
  return parts.join(" — ");
}

function ingredientSummary(ingredient) {
  const parts = [ingredient.claim_id || "unknown source"];
  if (ingredient.relationship) {
    parts.push(ingredient.relationship);
  }
  if (ingredient.title) {
    parts.push(ingredient.title);
  }
  return parts.join(" — ");
}

async function run(handler) {
  try {
    clearValidation();
    message("Working...");
    await handler();
  } catch (error) {
    console.error(error);
    message(plainError(error), "error");
  }
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

async function readFileBase64(file) {
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

function textToBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function canonicalDomainPayload(domain) {
  return JSON.stringify({
    claimant_key_id: requireIdentity().key_id,
    domain,
    registry_url: registryUrl().replace(/\/+$/g, "")
  });
}

async function domainVerificationRecord(domainValue) {
  const domain = domainValue.trim().replace(/\.$/, "").toLowerCase();
  if (!domain || !domain.includes(".")) {
    throw new Error("Enter a domain name to verify.");
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalDomainPayload(domain))
  );
  return {
    domain,
    txt_name: `_pact-challenge.${domain}`,
    txt_value: `pact-domain-verification=${base64Url(new Uint8Array(digest))}`
  };
}

async function readImportFile(file) {
  const text = await file.text();
  const trimmed = text.trimStart();
  if (trimmed.startsWith("{")) {
    return JSON.parse(text);
  }
  if (!trimmed.includes("ENCRYPTED PRIVATE KEY")) {
    throw new Error("Choose a recovery JSON file or CLI identity export.");
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

function selectedFileName(input, suffix) {
  const file = input.files[0];
  if (!file) {
    return `pact${suffix}`;
  }
  const dot = file.name.lastIndexOf(".");
  if (dot <= 0) {
    return `${file.name}${suffix}`;
  }
  return `${file.name.slice(0, dot)}${suffix}${file.name.slice(dot)}`;
}

function selectedWatermarkMethods() {
  return [
    ...document.querySelectorAll("input[name='text-watermark-method']:checked")
  ].map((input) => input.value);
}

function renderWatermarkPreview(result) {
  const element = resultElement("#watermark-preview");
  const heading = document.createElement("h3");
  heading.textContent = "Text watermark preview";
  element.append(heading);
  for (const embedding of result.embeddings || []) {
    const report = embedding.quality_report || {};
    const details = document.createElement("details");
    details.open = true;
    const summary = document.createElement("summary");
    summary.textContent = `${report.method_id || "watermark"} changed ${
      report.changed_characters || 0
    } characters`;
    details.append(summary);
    details.append(row("Changed lines", report.changed_lines || 0));
    details.append(row("Warnings", (report.warnings || []).join(", ") || "None"));
    const diff = document.createElement("pre");
    diff.textContent = report.unified_diff || "No visible diff.";
    details.append(diff);
    element.append(details);
  }
}

function inferMimeType(file) {
  return inferMimeTypeFrom(file, "#mime-type");
}

function inferMimeTypeFrom(file, selector) {
  if (document.querySelector(selector).value) {
    return document.querySelector(selector).value;
  }
  if (file && file.type) {
    return file.type;
  }
  return "text/plain";
}

function validateSignForm(file, mimeType) {
  if (!file) {
    validationError(document.querySelector("#content-file"), "Choose a file to sign.");
  }
  if (
    document.querySelector("#protect-text-before-signing").checked &&
    !mimeType.startsWith("text/")
  ) {
    validationError(
      document.querySelector("#protect-text-before-signing"),
      "Text watermarking is only available for text files."
    );
  }
  if (document.querySelector("#protect-text-before-signing").checked) {
    if (!document.querySelector("#watermark-secret").value.trim()) {
      validationError(
        document.querySelector("#watermark-secret"),
        "Enter a watermark secret before signing with text watermarking."
      );
    }
    const methods = selectedWatermarkMethods();
    if (!methods.length) {
      validationError(
        document.querySelector("#protect-text-before-signing"),
        "Choose at least one text watermark mode."
      );
    }
    if (
      methods.includes("canary") &&
      !document.querySelector("#canary-phrase").value.trim()
    ) {
      validationError(
        document.querySelector("#canary-phrase"),
        "Enter a canary phrase or turn off the canary watermark mode."
      );
    }
  }
  if (
    document.querySelector("#protect-image-after-publish").checked &&
    !mimeType.startsWith("image/")
  ) {
    validationError(
      document.querySelector("#protect-image-after-publish"),
      "Image watermarking is only available for image files."
    );
  }
  if (
    document.querySelector("#protect-image-after-publish").checked &&
    !document.querySelector("#publish-after-signing").checked
  ) {
    validationError(
      document.querySelector("#publish-after-signing"),
      "Image watermarking requires publishing because the watermark points to the registry claim."
    );
  }
  if (
    document.querySelector("#download-embedded-proof").checked &&
    !embeddedProofSupported(mimeType)
  ) {
    validationError(
      document.querySelector("#download-embedded-proof"),
      "Embedded proof downloads are not available for this file type."
    );
  }
}

async function inspectFile(file, mimeType) {
  const form = new FormData();
  form.append("file", file);
  if (mimeType) {
    form.append("mime_type", mimeType);
  }
  const response = await fetch(`${registryUrl()}/api/v1/inspect`, {
    method: "POST",
    body: form
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.detail || response.statusText);
  }
  return result;
}

async function previousProofForMutation(editedFile, editedMimeType) {
  const proofFile = document.querySelector("#mutation-proof-file").files[0];
  if (proofFile) {
    return await inspectFile(proofFile, "application/json");
  }
  const originalFile = document.querySelector("#mutation-original-file").files[0];
  if (originalFile) {
    return await inspectFile(
      originalFile,
      inferMimeTypeFrom(originalFile, "#mutation-original-mime-type")
    );
  }
  return await inspectFile(editedFile, editedMimeType);
}

async function downloadEmbeddedProofCopy(fileInput, mimeType, manifestJson, nonceB64 = null) {
  const file = fileInput.files[0];
  if (!file) {
    return null;
  }
  const result = JSON.parse(
    await callPython(
      "embed_signed_manifest_carrier",
      [await readBase64(fileInput), mimeType, manifestJson, nonceB64],
      "documents"
    )
  );
  const filename = selectedFileName(fileInput, ".pact");
  downloadBase64(filename, result.asset_b64, result.mime_type);
  return filename;
}

function download(name, content, type = "application/json") {
  downloadBlob(name, new Blob([content], { type }));
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
  let body = {};
  try {
    body = await response.json();
  } catch {
    body = { detail: response.statusText };
  }
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

async function unlockIdentity() {
  const currentIdentity = requireIdentity();
  const publicIdentity = JSON.parse(await callPython("import_identity", [
    registryUrl(),
    currentIdentity.encrypted_pkcs8_b64,
    password()
  ]));
  identity = {
    ...currentIdentity,
    registry_url: publicIdentity.registry_url,
    key_id: publicIdentity.key_id,
    public_jwk: publicIdentity.public_jwk
  };
  saveIdentity(identity);
  creatingIdentity = false;
  rememberPassword();
}

async function requireUnlockedIdentity() {
  identity = creatingIdentity ? null : identity || savedIdentity();
  if (!identity) {
    throw new Error("No browser profile is stored.");
  }
  if (!identityPassword) {
    const passcode = document.querySelector("#identity-passcode").value;
    if (!passcode) {
      setPage("identity");
      throw new Error(
        "Enter this saved profile's passcode to unlock its private signing key before showing private profile information."
      );
    }
    await unlockIdentity();
    updateSession();
    showSavedBrowserProfile();
  }
  return identity;
}

async function createIdentity() {
  identityPassword = document.querySelector("#identity-passcode").value;
  if (!identityPassword) {
    throw new Error("Choose a passcode before creating a profile.");
  }
  identity = JSON.parse(
    await callPython("create_identity", [registryUrl(), identityPassword])
  );
  saveIdentity(identity);
  creatingIdentity = false;
  rememberPassword();
}

async function ensureProfile({ allowDisplayName = true } = {}) {
  const displayName = allowDisplayName
    ? document.querySelector("#identity-display-name").value.trim()
    : "";
  const response = await fetch(`${registryUrl()}/api/v1/profiles/${identity.key_id}`);
  if (response.ok) {
    const profile = await response.json();
    if (displayName && profile.display_name !== displayName) {
      const request = await signedMutation("profile_update", {
        display_name: displayName
      });
      return await registryJson(`/api/v1/profiles/${identity.key_id}/update`, {
        method: "POST",
        body: JSON.stringify(request)
      });
    }
    return profile;
  }
  if (response.status !== 404 && response.status !== 400) {
    const body = await response.json();
    throw new Error(body.detail || response.statusText);
  }
  const request = await signedMutation("profile_registration", {
    ...(displayName ? { display_name: displayName } : {}),
    hosted_account: false,
    device_fingerprint: await browserFingerprint()
  });
  return await registryJson("/api/v1/profiles", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

async function loadOwnProfile() {
  await requireUnlockedIdentity();
  try {
    const profile = await registryJson(`/api/v1/profiles/${identity.key_id}`);
    const evidence = await registryJson(`/api/v1/profiles/${identity.key_id}/evidence`);
    identity = {
      ...identity,
      display_name: profile.display_name || identity.display_name || null
    };
    saveIdentity(identity);
    updateSession();
    renderProfile("#public-profile-summary", profile, evidence);
  } catch (error) {
    renderObject("#public-profile-summary", "Public registry profile", [
      ["What this is", "The public record other people can look up."],
      ["Profile ID", identity.key_id],
      ["Registry status", "No public profile found yet"],
      ["Next step", "Press Continue to signing to register this browser profile."]
    ]);
  }
}

async function publishSignedManifest(manifestJson) {
  const request = await signedMutation(
    "claim_registration",
    { signed_manifest_json: manifestJson },
    requireIdentity().key_id
  );
  return await registryJson("/api/v1/claims", {
    method: "POST",
    body: JSON.stringify(request)
  });
}

async function continueIdentity() {
  identity = creatingIdentity ? null : identity || savedIdentity();
  const hadSavedProfile = Boolean(identity);
  if (hadSavedProfile) {
    await unlockIdentity();
  } else {
    await createIdentity();
  }
  const profile = await ensureProfile({ allowDisplayName: !hadSavedProfile });
  const evidence = await registryJson(`/api/v1/profiles/${identity.key_id}/evidence`);
  identity = {
    ...identity,
    display_name: profile.display_name || identity.display_name || null
  };
  saveIdentity(identity);
  updateSession();
  showSavedBrowserProfile();
  renderProfile("#public-profile-summary", profile, evidence);
  setPage("sign");
  message(
    hadSavedProfile
      ? "Saved profile unlocked. Choose a file to sign."
      : "Profile created. Choose a file to sign."
  );
}

document.querySelector("#continue-identity").onclick = () =>
  run(async () => {
    await continueIdentity();
  });

document.querySelector("#identity-selector").onchange = (event) =>
  selectIdentity(event.target.value);

document.querySelector("#new-identity").onclick = () =>
  run(async () => {
    creatingIdentity = true;
    identity = null;
    identityPassword = null;
    document.querySelector("#identity-passcode").value = "";
    document.querySelector("#identity-display-name").value = "";
    clearElement(document.querySelector("#browser-profile-summary"));
    clearElement(document.querySelector("#public-profile-summary"));
    updateSession();
    message("Choose a passcode for the new browser profile.");
  });

document.querySelector("#show-identity").onclick = () =>
  run(async () => {
    await requireUnlockedIdentity();
    await loadOwnProfile();
    message("Public registry profile shown below.");
  });

document.querySelector("#show-domain-record").onclick = () =>
  run(async () => {
    requireIdentity();
    const record = await domainVerificationRecord(
      document.querySelector("#verify-domain-name").value
    );
    renderObject("#domain-verification-result", "DNS TXT record", [
      ["Name", record.txt_name],
      ["Type", "TXT"],
      ["Value", record.txt_value],
      ["Next step", "Create this record in public DNS, then press Verify DNS record."]
    ]);
    message("DNS TXT record ready.");
  });

document.querySelector("#verify-domain").onclick = () =>
  run(async () => {
    requireIdentity();
    const record = await domainVerificationRecord(
      document.querySelector("#verify-domain-name").value
    );
    const request = await signedMutation(
      "domain_verification",
      {
        domain: record.domain,
        txt_value: record.txt_value
      },
      requireIdentity().key_id
    );
    const profile = await registryJson("/api/v1/domains/verify", {
      method: "POST",
      body: JSON.stringify(request)
    });
    const evidence = await registryJson(`/api/v1/profiles/${profile.key_id}/evidence`);
    renderProfile("#domain-verification-result", profile, evidence);
    await loadOwnProfile();
    message("Domain verified and trust profile updated.");
  });

document.querySelector("#complete-hosted-login").onclick = () =>
  run(async () => {
    requireIdentity();
    const payload = {
      ...(document.querySelector("#hosted-login-token").value.trim()
        ? { login_token: document.querySelector("#hosted-login-token").value.trim() }
        : {})
    };
    const request = await signedMutation(
      "hosted_account_authorization",
      payload,
      requireIdentity().key_id
    );
    const profile = await registryJson("/api/v1/profiles/me/hosted-login", {
      method: "POST",
      body: JSON.stringify(request)
    });
    const evidence = await registryJson(`/api/v1/profiles/${profile.key_id}/evidence`);
    renderProfile("#hosted-account-result", profile, evidence);
    await loadOwnProfile();
    message("Hosted account login submitted.");
  });

document.querySelector("#authorize-hosted-account").onclick = () =>
  run(async () => {
    requireIdentity();
    const keyId =
      document.querySelector("#authorize-hosted-key-id").value.trim() ||
      requireIdentity().key_id;
    const payload = {
      target_key_id: keyId,
      ...(document.querySelector("#authorize-hosted-provider").value.trim()
        ? { provider: document.querySelector("#authorize-hosted-provider").value.trim() }
        : {}),
      ...(document.querySelector("#authorize-hosted-note").value.trim()
        ? { note: document.querySelector("#authorize-hosted-note").value.trim() }
        : {})
    };
    const request = await signedMutation(
      "account_authorization",
      payload,
      requireIdentity().key_id
    );
    const profile = await registryJson(`/api/v1/profiles/${keyId}/hosted-authorize`, {
      method: "POST",
      body: JSON.stringify(request)
    });
    const evidence = await registryJson(`/api/v1/profiles/${profile.key_id}/evidence`);
    renderProfile("#hosted-account-result", profile, evidence);
    if (profile.key_id === requireIdentity().key_id) {
      await loadOwnProfile();
    }
    message("Hosted account approved.");
  });

document.querySelector("#attest-third-party").onclick = () =>
  run(async () => {
    requireIdentity();
    const keyId = document.querySelector("#third-party-key-id").value.trim();
    if (!keyId) {
      throw new Error("Enter the profile ID to attest.");
    }
    const payload = {
      target_key_id: keyId,
      documented_rights: document.querySelector("#third-party-documented-rights").checked,
      ...(document.querySelector("#third-party-provider").value.trim()
        ? { provider: document.querySelector("#third-party-provider").value.trim() }
        : {}),
      ...(document.querySelector("#third-party-note").value.trim()
        ? { note: document.querySelector("#third-party-note").value.trim() }
        : {})
    };
    const request = await signedMutation(
      "third_party_attestation",
      payload,
      requireIdentity().key_id
    );
    const profile = await registryJson(`/api/v1/profiles/${keyId}/third-party-attest`, {
      method: "POST",
      body: JSON.stringify(request)
    });
    const evidence = await registryJson(`/api/v1/profiles/${profile.key_id}/evidence`);
    renderProfile("#third-party-result", profile, evidence);
    message("Third-party attestation submitted.");
  });

document.querySelector("#export-identity").onclick = () =>
  run(async () => {
    await requireUnlockedIdentity();
    download(
      "pact-profile-recovery.json",
      JSON.stringify(
        {
          ...identity
        },
        null,
        2
      )
    );
    message("Recovery file downloaded. Keep it private.");
  });

document.querySelector("#identity-import").onchange = (event) =>
  run(async () => {
    const imported = await readImportFile(event.target.files[0]);
    if (imported.passcode) {
      identityPassword = imported.passcode;
    }
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
    saveIdentity(identity);
    creatingIdentity = false;
    updateSession();
    showSavedBrowserProfile();
    await loadOwnProfile();
    setPage("sign");
    message("Profile imported. Choose a file to sign.");
  });

document.querySelector("#rotate-key").onclick = () =>
  run(async () => {
    const currentIdentity = requireIdentity();
    const replacement = JSON.parse(
      await callPython("rotate_identity", [
        registryUrl(),
        currentIdentity.encrypted_pkcs8_b64,
        password()
      ])
    );
    const issued = await challenge("key_rotation", currentIdentity.key_id);
    const request = JSON.parse(
      await callPython("create_rotation_request", [
        registryUrl(),
        currentIdentity.encrypted_pkcs8_b64,
        replacement.encrypted_pkcs8_b64,
        password(),
        JSON.stringify(issued),
        JSON.stringify({ reason: "Rotated from browser profile settings." })
      ])
    );
    await registryJson("/api/v1/rotations", {
      method: "POST",
      body: JSON.stringify(request)
    });
    identity = {
      registry_url: replacement.registry_url,
      key_id: replacement.replacement_key_id,
      public_jwk: replacement.public_jwk,
      encrypted_pkcs8_b64: replacement.encrypted_pkcs8_b64
    };
    saveIdentity(identity);
    await loadOwnProfile();
    message("Signing key rotated. Future claims will use the new key.");
  });

document.querySelector("#logout-identity").onclick = () =>
  run(async () => {
    identityPassword = null;
    forgetSavedPasscode();
    identity = savedIdentity();
    creatingIdentity = !identity;
    document.querySelector("#identity-passcode").value = "";
    updateSession();
    showSavedBrowserProfile();
    clearElement(document.querySelector("#public-profile-summary"));
    setPage("identity");
    message("Profile locked on this browser. Enter the selected profile's passcode to unlock it again.");
  });

document.querySelector("#sign-content").onclick = () =>
  run(async () => {
    const fileInput = document.querySelector("#content-file");
    const file = fileInput.files[0];
    const stem = selectedFileStem(fileInput);
    const mimeType = inferMimeType(file);
    validateSignForm(file, mimeType);
    const registry = await registryJson("/api/v1/registry");
    const policy = collectPolicy("#sign-policy");
    let content = await readBase64(fileInput);
    const actions = [
      {
        action: document.querySelector("#c2pa-action").value,
        ...(document.querySelector("#c2pa-action-description").value.trim()
          ? {
              description: document
                .querySelector("#c2pa-action-description")
                .value.trim()
            }
          : {})
      }
    ];
    if (document.querySelector("#protect-text-before-signing").checked) {
      if (!mimeType.startsWith("text/")) {
        throw new Error("Text watermarking only works on text files.");
      }
      const secret = document.querySelector("#watermark-secret").value;
      if (!secret) {
        throw new Error("Enter a watermark secret or turn off text protection.");
      }
      const methods = selectedWatermarkMethods();
      if (!methods.length) {
        throw new Error("Choose at least one text watermark mode.");
      }
      const protectedText = JSON.parse(
        await callPython("watermark_text", [
          await file.text(),
          secret,
          JSON.stringify(methods),
          document.querySelector("#canary-phrase").value || null
        ])
      );
      renderWatermarkPreview(protectedText);
      download(`${stem}.protected.txt`, protectedText.transformed_content, "text/plain");
      content = textToBase64(protectedText.transformed_content);
      actions.push({
        action: "c2pa.edited",
        description: `Added text watermark protection (${methods.join(", ")})`
      });
    }
    const result = JSON.parse(
      await callPython("sign_content", [
        registryUrl(),
        requireIdentity().encrypted_pkcs8_b64,
        password(),
        content,
        registry.root_fingerprint,
        mimeType,
        document.querySelector("#canonicalization").value,
        "custom",
        "visible",
        null,
        JSON.stringify(actions),
        "[]",
        JSON.stringify(policy),
        !document.querySelector("#keep-nonce-private").checked
      ])
    );
    signedManifest = result.manifest_json;
    nonceBase64 = result.nonce_b64;
    const keepNoncePrivate = document.querySelector("#keep-nonce-private").checked;
    download(`${stem}.proof.json`, signedManifest);
    if (keepNoncePrivate) {
      downloadBase64(`${stem}.nonce`, nonceBase64);
    }
    let claim = null;
    if (document.querySelector("#publish-after-signing").checked) {
      claim = await publishSignedManifest(signedManifest);
      document.querySelector("#revoke-claim-id").value = claim.claim_id;
      document.querySelector("#dispute-claim-id").value = claim.claim_id;
    }
    let embeddedFilename = null;
    if (document.querySelector("#download-embedded-proof").checked) {
      embeddedFilename = await downloadEmbeddedProofCopy(
        fileInput,
        mimeType,
        signedManifest,
        keepNoncePrivate ? null : nonceBase64
      );
    }
    let imageWatermarkDownloaded = null;
    if (
      claim &&
      document.querySelector("#protect-image-after-publish").checked &&
      mimeType.startsWith("image/")
    ) {
      const imageWatermark = JSON.parse(
        await callPython(
          "watermark_image",
          [
            await readBase64(fileInput),
            mimeType,
            claim.claim_id,
            registry.root_fingerprint
          ],
          "image-watermarks"
        )
      );
      imageWatermarkDownloaded = selectedFileName(fileInput, ".pact-watermarked");
      downloadBase64(imageWatermarkDownloaded, imageWatermark.image_b64, mimeType);
    }
    renderObject("#sign-result", "Signed file", [
      ["Claim ID", result.claim_id],
      ["Requested protection", policySummary(policy)],
      ["Claimed actions", actions.map(actionSummary).join("; ")],
      [
        "Content verification",
        result.public_content_verifiable
          ? "Public: proof JSON contains the content check key"
          : "Private: nonce file required"
      ],
      ["Downloaded", keepNoncePrivate ? `${stem}.proof.json and ${stem}.nonce` : `${stem}.proof.json`],
      ["Embedded copy", embeddedFilename || "Not downloaded for this file type"],
      ["Watermarked image", imageWatermarkDownloaded || "Not downloaded"],
      ["Published", claim ? "Yes" : "No"],
      ["Registry claim", claim ? claim.claim_id : "Not published"]
    ]);
    message(
      claim
        ? "File signed and proof published."
        : "File signed. Proof files were downloaded but not published."
    );
  });

document.querySelector("#register-mutation").onclick = () =>
  run(async () => {
    const fileInput = document.querySelector("#mutation-edited-file");
    const file = fileInput.files[0];
    if (!file) {
      validationError(fileInput, "Choose the edited file.");
    }
    const registry = await registryJson("/api/v1/registry");
    const mimeType = inferMimeTypeFrom(file, "#mutation-mime-type");
    const policy = collectPolicy("#mutation-policy");
    const previous = await previousProofForMutation(file, mimeType);
    const previousManifest = previous.manifest || null;
    if (!previous.recognized || !previousManifest || !previousManifest.claim_id) {
      throw new Error(
        "PACT could not find a previous manifest. Provide the previous proof JSON or original media."
      );
    }
    const action = {
      action: document.querySelector("#mutation-action").value,
      ...(document.querySelector("#mutation-action-description").value.trim()
        ? {
            description: document
              .querySelector("#mutation-action-description")
              .value.trim()
          }
        : {})
    };
    const ingredient = {
      claim_id: previousManifest.claim_id,
      registry_url: previousManifest.registry_url,
      title: document.querySelector("#mutation-original-file").files[0]
        ? document.querySelector("#mutation-original-file").files[0].name
        : file.name,
      format: previousManifest.mime_type,
      relationship: "parentOf"
    };
    const result = JSON.parse(
      await callPython("sign_content", [
        registryUrl(),
        requireIdentity().encrypted_pkcs8_b64,
        password(),
        await readFileBase64(file),
        registry.root_fingerprint,
        mimeType,
        document.querySelector("#mutation-canonicalization").value,
        "custom",
        "visible",
        null,
        JSON.stringify([action]),
        JSON.stringify([ingredient]),
        JSON.stringify(policy),
        true
      ])
    );
    signedManifest = result.manifest_json;
    nonceBase64 = result.nonce_b64;
    const stem = selectedFileStem(fileInput);
    download(`${stem}.proof.json`, signedManifest);
    const claim = await publishSignedManifest(signedManifest);
    document.querySelector("#revoke-claim-id").value = claim.claim_id;
    document.querySelector("#dispute-claim-id").value = claim.claim_id;
    let embeddedFilename = null;
    if (document.querySelector("#mutation-download-embedded-proof").checked) {
      embeddedFilename = await downloadEmbeddedProofCopy(
        fileInput,
        mimeType,
        signedManifest,
        nonceBase64
      );
    }
    renderObject("#mutation-result", "Registered edit", [
      ["New claim ID", claim.claim_id],
      ["Previous claim ID", previousManifest.claim_id],
      ["Requested protection", policySummary(policy)],
      ["Edit action", actionSummary(action)],
      ["Source ingredient", ingredientSummary(ingredient)],
      ["Content verification", "Public: proof JSON contains the content check key"],
      ["Downloaded", `${stem}.proof.json`],
      ["Embedded copy", embeddedFilename || "Not downloaded for this file type"]
    ]);
    message("Edited file signed and published as a new claim.");
  });

document.querySelector("#inspect-content").onclick = () =>
  run(async () => {
    const fileInput = document.querySelector("#inspect-file");
    const file = fileInput.files[0];
    if (!file) {
      throw new Error("Choose a file to inspect.");
    }
    const mimeType = document.querySelector("#inspect-mime-type").value || file.type;
    const result = await inspectFile(file, mimeType);
    renderInspection(result, await inspectionContext(result));
    message(result.recognized ? "Inspection complete." : "No proof found in that file.");
  });

document.querySelector("#verify-manifest").onclick = () =>
  run(async () => {
    const manifest =
      signedManifest || (await readText(document.querySelector("#manifest-file")));
    const parsed = JSON.parse(manifest);
    const profile = await registryJson(
      `/api/v1/profiles/${parsed.manifest.claimant_key_id}`
    );
    const result = JSON.parse(await callPython("verify_manifest_json", [
      manifest,
      JSON.stringify(profile.public_jwk),
      document.querySelector("#verify-content-file").files[0]
        ? await readBase64(document.querySelector("#verify-content-file"))
        : null,
      document.querySelector("#nonce-file").files[0]
        ? await readBase64(document.querySelector("#nonce-file"))
        : nonceBase64
    ]));
    renderObject("#inspect-result", "Proof check", [
      ["Signature valid", result.signature_valid],
      ["Content binding valid", result.content_binding_valid],
      ["Errors", (result.errors || []).join(", ") || "None"]
    ]);
    message("Proof check complete.");
  });

document.querySelector("#audit-manifest").onclick = () =>
  run(async () => {
    const manifest =
      signedManifest || (await readText(document.querySelector("#manifest-file")));
    const result = JSON.parse(await callPython("privacy_audit", [
      manifest,
      document.querySelector("#verify-content-file").files[0]
        ? await readBase64(document.querySelector("#verify-content-file"))
        : null,
      document.querySelector("#nonce-file").files[0]
        ? await readBase64(document.querySelector("#nonce-file"))
        : nonceBase64
    ]));
    renderObject("#inspect-result", "Public proof preview", [
      ["Passed", result.passed ? "Yes" : "No"],
      ["Findings", (result.findings || []).length]
    ]);
    console.log(result);
    message("Preview complete.");
  });

document.querySelector("#lookup-profile").onclick = () =>
  run(async () => {
    const keyId = document.querySelector("#lookup-profile-key").value.trim();
    if (!keyId) {
      throw new Error("Enter a profile ID.");
    }
    const profile = await registryJson(`/api/v1/profiles/${keyId}`);
    const evidence = await registryJson(`/api/v1/profiles/${keyId}/evidence`);
    renderProfile("#lookup-result", profile, evidence);
    message("Profile loaded.");
  });

document.querySelector("#lookup-claim").onclick = () =>
  run(async () => {
    const claimId = document.querySelector("#lookup-claim-id").value.trim();
    if (!claimId) {
      throw new Error("Enter a claim ID.");
    }
    const claim = await registryJson(`/api/v1/claims/${claimId}`);
    const disputes = await registryJson(`/api/v1/claims/${claimId}/disputes`);
    renderClaim("#lookup-result", claim, disputes.disputes || []);
    message("Claim loaded.");
  });

document.querySelector("#lookup-dispute").onclick = () =>
  run(async () => {
    const disputeId = document.querySelector("#lookup-dispute-id").value.trim();
    if (!disputeId) {
      throw new Error("Enter a dispute ID.");
    }
    const dispute = await registryJson(`/api/v1/disputes/${disputeId}`);
    renderDisputes("#lookup-result", [dispute]);
    message("Dispute loaded.");
  });

document.querySelector("#refresh-claims").onclick = () =>
  run(async () => {
    const currentIdentity = requireIdentity();
    const response = await registryJson(
      `/api/v1/profiles/${currentIdentity.key_id}/claims`
    );
    renderClaims(response.claims || []);
    message("Claims loaded.");
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
          "Revoked by claimant."
      },
      requireIdentity().key_id
    );
    await registryJson(`/api/v1/claims/${claimId}/revoke`, {
      method: "POST",
      body: JSON.stringify(request)
    });
    document.querySelector("#refresh-claims").click();
    message("Claim revoked.");
  });

document.querySelector("#open-dispute").onclick = () =>
  run(async () => {
    const claimId = document.querySelector("#dispute-claim-id").value.trim();
    const reason = document.querySelector("#dispute-reason").value.trim();
    const misuseUrl = document
      .querySelector("#dispute-misuse-url")
      .value.trim();
    if (!claimId || !reason) {
      throw new Error("Enter a claim ID and explain the dispute.");
    }
    const request = await signedMutation("dispute_open", {
      claim_id: claimId,
      reason,
      ...(misuseUrl ? { misuse_url: misuseUrl } : {})
    });
    const dispute = await registryJson("/api/v1/disputes", {
      method: "POST",
      body: JSON.stringify(request)
    });
    renderDisputes("#dispute-result", [dispute]);
    message("Dispute opened.");
  });

document.querySelector("#view-claim-disputes").onclick = () =>
  run(async () => {
    const claimId = document.querySelector("#dispute-claim-id").value.trim();
    if (!claimId) {
      throw new Error("Enter a claim ID.");
    }
    const response = await registryJson(`/api/v1/claims/${claimId}/disputes`);
    renderDisputes("#dispute-result", response.disputes || []);
    message("Disputes loaded.");
  });

document.querySelector("#view-my-disputes").onclick = () =>
  run(async () => {
    const currentIdentity = requireIdentity();
    const response = await registryJson(
      `/api/v1/profiles/${currentIdentity.key_id}/disputes`
    );
    renderDisputes("#dispute-result", response.disputes || []);
    message("Disputes loaded.");
  });

document.querySelector("#view-dispute").onclick = () =>
  run(async () => {
    const disputeId = document.querySelector("#view-dispute-id").value.trim();
    if (!disputeId) {
      throw new Error("Enter a dispute ID.");
    }
    const dispute = await registryJson(`/api/v1/disputes/${disputeId}`);
    renderDisputes("#dispute-result", [dispute]);
    message("Dispute loaded.");
  });

document.querySelector("#content-file").onchange = updateSigningOptions;
document.querySelector("#mime-type").oninput = updateSigningOptions;
document.querySelector("#mutation-edited-file").onchange = updateMutationOptions;
document.querySelector("#mutation-mime-type").oninput = updateMutationOptions;

updateSession();
showSavedBrowserProfile();
updateSigningOptions();
updateMutationOptions();
setPage("identity");
forgetSavedPasscode();
message(
  identity
    ? "Saved profile found. Enter the selected profile's passcode to unlock private profile information."
    : "Create your profile to begin."
);
