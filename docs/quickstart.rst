Quickstart
==========

Before diving into code, it helps to know what each PACT operation actually
does — and in particular which steps touch the network, which are local-only,
and what the distinction is between operations that share a name with similar
concepts.

Operations overview
-------------------

**sign**
  *Local only — no network.* Reads content, generates a 32-byte random nonce,
  computes the salted commitment ``SHA-256(nonce ‖ SHA-256(content))``, and
  produces a signed manifest. The content never leaves your machine.
  Nothing is published. This step produces the artifact that all later steps use.

**register-claim** (``pact registry register-claim`` / ``service.register_claim``)
  *Network — writes to the registry.* Sends the already-signed manifest JSON to
  the registry's ``/pact/api/v1/claims`` endpoint. The registry appends an event to
  its append-only log. After this step the claim is publicly discoverable.
  Raw file content is never sent — only the manifest. Requires a profile to
  already be registered.

**verify** (``pact verify`` / ``verify_manifest``)
  *Local or light network.* Checks that the ES256 signature is valid and,
  when content and a nonce are supplied, that the commitment matches. Can run
  entirely offline given a ``--public-jwk`` file. Without a JWK file, the CLI
  fetches the claimant's public key from the registry profile endpoint — but
  it does not check revocation state, disputes, or trust tier. Those checks
  are performed by ``verify_claim``, not ``verify_manifest``.

**inspect** (``pact inspect`` / ``inspect_content``)
  *Local carrier extraction.* Takes any file — text, HTML, PDF, image, or a
  raw ``.manifest.json`` — and tries every known carrier format to extract an
  embedded manifest, locator, or watermark. Returns what was found. Does not
  verify signatures or contact the registry. Use ``inspect`` to answer "is
  there a PACT manifest in this file?", then ``verify`` on what it returns.

**recover** (``pact recover`` / ``/pact/api/v1/recover``)
  *Network — server-side extraction.* Uploads a file to the registry's recover
  endpoint, which runs carrier extraction server-side and resolves any found
  claims against the registry in one step. Use ``recover`` when you want
  extraction, signature checking, and registry resolution without running PACT
  locally.

register-profile vs. public-jwk
---------------------------------

These two commands both involve your identity's public key, but they do
completely different things.

**register-profile** (``pact registry register-profile``)
  *Network — writes to the registry.* Derives a device-binding token via the
  registry's OPRF endpoint, then signs and submits a profile mutation to
  ``/pact/api/v1/profiles``. After this step the registry has a record of your
  public key and the registry can verify your signatures. Your private key
  stays local. This must be done before ``register-claim`` will be accepted.

**public-jwk** (``pact identity public-jwk``)
  *Local only — no network.* Reads your identity file and writes only the
  public key as a JWK JSON file. Does not register anything, create a profile,
  or contact any server. Two common uses:

  - Pass the output to ``pact registry serve --admin-jwk-file`` to designate
    your identity as a registry administrator.
  - Pass the output to ``pact verify --public-jwk`` so a verifier can check
    signatures offline without the registry being reachable.

The short version: ``register-profile`` is a registry write that makes you
discoverable. ``public-jwk`` is a local file export.

---

This guide covers the core workflow through the Python API. CLI and browser
workspace workflows are covered in :doc:`server deployments <server>`.

Sign and verify a manifest
--------------------------

An identity is a registry-scoped P-256 key pair. Each registry gets a separate
key so activity on one registry cannot be linked to another.

.. code-block:: python

   import secrets

   from pact import (
       CanonicalizationProfile,
       ClaimantIdentity,
       Manifest,
       Permission,
       PermissionValue,
       Policy,
       PolicyEntry,
       base64url_encode,
       sign_manifest,
       verify_manifest,
   )

   content = "An original work.\n".encode()
   nonce = secrets.token_bytes(32)
   identity = ClaimantIdentity.generate("https://registry.example")

   policy = Policy(
       (
           PolicyEntry(Permission.GENERATIVE_TRAINING, PermissionValue.NOT_ALLOWED),
           PolicyEntry(Permission.NO_COMMERCIAL_TRAINING, PermissionValue.NOT_ALLOWED),
       )
   )

   manifest = Manifest.create(
       identity=identity,
       registry_root_fingerprint=base64url_encode(bytes(32)),
       content=content,
       mime_type="text/plain",
       canonicalization=CanonicalizationProfile.TEXT_V1,
       policy=policy,
       nonce=nonce,
   )
   signed = sign_manifest(manifest, identity)
   serialized = signed.to_json()

   parsed = type(signed).from_json(serialized)
   report = verify_manifest(parsed, identity.public_jwk, content, nonce)
   assert report.valid

The nonce is 32 random bytes held by the caller. It belongs in a content
carrier or a private evidence package — not in the registry manifest. The
registry stores only the commitment `SHA-256(nonce ‖ SHA-256(content))`.

Persist an identity
-------------------

Use the operating-system credential store when it is available:

.. code-block:: python

   from pact import KeyringIdentityStore

   store = KeyringIdentityStore()
   store.save(identity)
   restored = store.load(identity.registry_url)

The password-encrypted PKCS#8 file is the explicit fallback. PACT never falls
back silently from an unavailable keyring to an unencrypted file.

.. code-block:: python

   from pathlib import Path
   from pact import EncryptedFileIdentityStore

   fallback = EncryptedFileIdentityStore(Path("~/.config/pact/identities").expanduser())
   fallback.save(identity, "use-a-password-manager-generated-secret")
   restored = fallback.load(identity.registry_url, "use-a-password-manager-generated-secret")

The password is never stored by PACT.

Embed a carrier
---------------

Text carriers attach the signed manifest to the content itself so the claim
travels with the file. There are three modes: a visible proof block at the top
(`visible`), a zero-width invisible locator appended to the end (`invisible`),
or both (`both`). The zero-width locator carries the claim UUID, registry
fingerprint, nonce, and manifest digest as a compact cross-check. It is a
redundancy aid, not a second signature.

.. code-block:: python

   from pact import CarrierMode, embed_text_carrier, extract_text_carrier

   protected = embed_text_carrier(content, signed, nonce=nonce, mode=CarrierMode.BOTH)
   extracted = extract_text_carrier(protected)
   assert extracted.signed_manifest == signed

HTML and XML have dedicated helpers that insert the manifest into the document
structure without touching visible content:

.. code-block:: python

   from pact import embed_html_carrier, embed_xml_carrier

   protected_html = embed_html_carrier(html_document, signed, nonce=nonce, include_locator=True)
   protected_xml  = embed_xml_carrier(xml_document,  signed, nonce=nonce, include_locator=True)

Experimental text watermarks
-----------------------------

The text watermark layer modifies prose content to embed a recoverable signal.
It is conservative by design: it requires explicit confirmation, rejects content
that looks like code or structured data, and is limited to context-safe
transforms. All methods are experimental.

.. code-block:: python

   from pact import (
       LexicalSubstitutionPlugin,
       TextWatermarkParameters,
       apply_text_watermark_plugins,
   )

   result = apply_text_watermark_plugins(
       "We help new users start quickly because clear setup guidance matters.",
       "secret",
       (LexicalSubstitutionPlugin(),),
       TextWatermarkParameters(user_confirmation=True),
   )
   assert result.transformed_content != ""

The CLI equivalent:

.. code-block:: bash

   pact watermark text work.txt \
     --methods lexical,syntactic \
     --secret 'store-this-safely' \
     --output work-watermarked.txt \
     --confirm

C2PA image credentials
-----------------------

For image formats supported by the official C2PA SDK, PACT delegates embedding
and validation to that SDK:

.. code-block:: python

   from pact import C2paSignerMaterial, embed_c2pa_image, read_c2pa_asset

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   embedded = embed_c2pa_image(
       image_bytes, "image/png",
       signed=signed,
       signer_material=signer,
       title="Protected image",
   )
   inspected = read_c2pa_asset(embedded.asset_bytes, mime_type="image/png")
   assert inspected.active_manifest is not None

For PDF and DOCX, PACT provides container writers for placing an already-signed
C2PA manifest store into the spec-defined location:

.. code-block:: python

   from pact import embed_c2pa_manifest_in_pdf, embed_c2pa_manifest_in_zip_document, sign_c2pa_document

   protected_pdf  = embed_c2pa_manifest_in_pdf(pdf_bytes, manifest_store_bytes)
   protected_docx = embed_c2pa_manifest_in_zip_document(docx_bytes, "docx", manifest_store_bytes)

   # Or drive the full hybrid sign-and-embed path:
   signed_pdf = sign_c2pa_document(
       pdf_bytes, "application/pdf",
       signed=signed,
       signer_material=C2paSignerMaterial(certificate_chain_pem, private_key_pem),
       title="Protected PDF",
   )

See :doc:`carriers <carriers>` for a full description of C2PA carrier modes,
text containers, and the hybrid signer path.

Use the registry core directly
------------------------------

The registry is available as a library. It handles replay challenges,
proof-of-work verification, append-only event storage, and claimant certificate
issuance.

.. code-block:: python

   from pathlib import Path
   from pact import (
       ChallengePurpose,
       FileRegistryStore,
       MutationRequest,
       RegistryCertificateAuthority,
       RegistryService,
   )

   authority = RegistryCertificateAuthority.initialize("https://registry.example")
   store    = FileRegistryStore(Path("./registry-data"))
   service  = RegistryService("https://registry.example", store=store, certificate_authority=authority)

   challenge = service.issue_challenge(ChallengePurpose.PROFILE_REGISTRATION, difficulty=4)
   request = MutationRequest.create(
       identity,
       challenge,
       payload={
           "display_name": "Alice",
           "device_fingerprint": "pact-device-binding-v2.<base64url-32-byte-token>",
       },
       proof_of_work_solution=0,   # supply a solved value in real use
   )
   profile = service.register_profile(request)
   assert profile.key_id == identity.key_id

In normal CLI and browser flows, PACT derives the `pact-device-binding-v2`
token through the blinded OPRF endpoint. Direct API callers must supply a valid
token. The registry rejects profiles without it.

TrustMark image soft binding
-----------------------------

PACT can embed a compact 96-bit claim locator as a TrustMark soft binding
alongside perceptual fingerprints for JPEG, PNG, TIFF, and WebP:

.. code-block:: python

   from pact import (
       compare_image_perceptual_fingerprints,
       create_image_perceptual_fingerprint,
       embed_image_soft_binding,
       decode_image_soft_binding,
   )

   watermarked = embed_image_soft_binding(
       image_bytes, "image/png",
       claim_id=claim.claim_id,
       registry_root_fingerprint=claim.signed_manifest.manifest.registry_root_fingerprint,
   )
   decoded = decode_image_soft_binding(watermarked.image_bytes, "image/png")
   assert decoded.locator is not None

   original    = create_image_perceptual_fingerprint(image_bytes, "image/png")
   transformed = create_image_perceptual_fingerprint(transformed_bytes, "image/png")
   match = compare_image_perceptual_fingerprints(original, transformed)

The soft binding carries a locator, not the signature itself. Recovering a
locator from a transformed image gives a starting point to look up the registry
claim and then verify the signature, registry record, and content binding
separately.

Training-use probes
--------------------

PACT can produce canary-style probes that create cryptographic commitments to
content before you collect provider responses. The registry never receives the
protected text, prompts, responses, or evidence package unless the user
explicitly publishes them.

.. code-block:: bash

   pact probe create \
     --protected protected.txt \
     --control control.txt \
     --target-model provider/model \
     --output probes.json

   pact probe analyze probes.json \
     --responses responses.jsonl \
     --output evidence.json

   pact probe export evidence.json --output evidence-export.json

`responses.jsonl` contains one JSON object per provider response:
`{"probe_id": "...", "response": "..."}`. Analysis includes confidence
intervals and corrected p-values. The score is an explanation aid, not a legal
assertion that a provider trained on specific material.

CLI reference
-------------

The `pact` CLI exposes all of the above workflows without writing Python:

- ``pact identity init|show|export|import|rotate``
- ``pact sign``
- ``pact verify``
- ``pact inspect``
- ``pact privacy audit``
- ``pact watermark image``
- ``pact watermark text``
- ``pact probe create|analyze|export``
- ``pact registry init|serve|register-profile|register-claim``
- ``pact web``

Run ``pact <command> --help`` for per-command options. ``pact inspect`` accepts
signed manifest JSON or raw carrier files; it tries all supported carriers in
order, then resolves the registered claim when a live registry is configured.
