Quickstart
==========

PACT currently provides library APIs for registry-scoped claimant identities,
policies, signed manifests, local verification, text/HTML/XML carrier
embedding, an initial C2PA integration layer for supported image and
document containers, and a registry-core library layer with replay
challenges, append-only event storage, certificates, rotations, revocations,
and disputes. It also now ships a CLI entrypoint plus FastAPI-based public
API and proof-page surfaces for hosted and loopback-local deployment.

Create and sign a manifest
--------------------------

The nonce is deliberately retained by the caller. It belongs in an eventual
content carrier or private evidence package, not in the registry manifest.

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
           PolicyEntry(
               Permission.GENERATIVE_TRAINING,
               PermissionValue.NOT_ALLOWED,
           ),
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

Persist an identity
-------------------

Use the operating-system credential store when it is available:

.. code-block:: python

   from pact import KeyringIdentityStore

   store = KeyringIdentityStore()
   store.save(identity)
   restored = store.load(identity.registry_url)

The explicit fallback is a password-encrypted PKCS#8 file:

.. code-block:: python

   from pathlib import Path

   from pact import EncryptedFileIdentityStore

   fallback = EncryptedFileIdentityStore(Path("~/.config/pact/identities").expanduser())
   fallback.save(identity, "use-a-password-manager-generated-secret")
   restored = fallback.load(identity.registry_url, "use-a-password-manager-generated-secret")

The fallback password is never stored by PACT.

Embed a carrier
---------------

Text carriers can attach the signed manifest visibly, invisibly, or both:

.. code-block:: python

   from pact import CarrierMode, embed_text_carrier, extract_text_carrier

   protected = embed_text_carrier(
       content,
       signed,
       nonce=nonce,
       mode=CarrierMode.BOTH,
   )
   extracted = extract_text_carrier(protected)
   assert extracted.signed_manifest == signed

Structured HTML and XML files have dedicated helpers:

.. code-block:: python

   from pact import embed_html_carrier, embed_xml_carrier

   protected_html = embed_html_carrier(html_document, signed, nonce=nonce, include_locator=True)
   protected_xml = embed_xml_carrier(xml_document, signed, nonce=nonce, include_locator=True)

Apply experimental text watermark plugins
-----------------------------------------

The text watermark layer is deliberately conservative. It only runs when you
explicitly confirm the change and it rejects content that looks unsafe to
rewrite.

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

Use the CLI for text watermarking
---------------------------------

.. code-block:: bash

   pact watermark text work.txt \
     --methods lexical,syntactic \
     --secret 'store-this-safely' \
     --output work-watermarked.txt \
     --confirm

Embed a C2PA image credential
-----------------------------

For supported image formats, PACT can delegate embedding and validation to the
official C2PA SDK:

.. code-block:: python

   from pact import C2paSignerMaterial, embed_c2pa_image, read_c2pa_asset

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   embedded = embed_c2pa_image(
       image_bytes,
       "image/png",
       signed=signed,
       signer_material=signer,
       title="Protected image",
   )
   inspected = read_c2pa_asset(embedded.asset_bytes, mime_type="image/png")
   assert inspected.active_manifest is not None

Embed a prebuilt C2PA manifest into PDF or DOCX
-----------------------------------------------

For PDF and ZIP-based document formats, PACT can place an already-signed
manifest store into the spec-defined container location:

.. code-block:: python

   from pact import (
       embed_c2pa_manifest_in_pdf,
       embed_c2pa_manifest_in_zip_document,
   )

   protected_pdf = embed_c2pa_manifest_in_pdf(pdf_bytes, manifest_store_bytes)
   protected_docx = embed_c2pa_manifest_in_zip_document(
       docx_bytes,
       "docx",
       manifest_store_bytes,
   )

Use this when your signing pipeline can already produce valid C2PA manifest
store bytes but the Python SDK cannot embed them into the target file format.

Sign and embed a PDF or DOCX through the hybrid CAI path
--------------------------------------------------------

PACT can also drive the official CAI signer path for document formats that the
Python wrapper does not expose directly:

.. code-block:: python

   from pact import C2paSignerMaterial, sign_c2pa_document

   signer = C2paSignerMaterial(certificate_chain_pem, private_key_pem)
   signed_pdf = sign_c2pa_document(
       pdf_bytes,
       "application/pdf",
       signed=signed,
       signer_material=signer,
       title="Protected PDF",
   )
   signed_docx = sign_c2pa_document(
       docx_bytes,
       "docx",
       signed=signed,
       signer_material=signer,
       title="Protected document",
   )

For legacy binary formats such as ``.doc``, the helper returns a detached
manifest store and leaves the original bytes unchanged.

Use the registry core
---------------------

The registry layer is available as a pure library API. It issues replay and
proof-of-work challenges, stores append-only events, and derives public
profile evidence:

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
   store = FileRegistryStore(Path("./registry-data"))
   service = RegistryService(
       "https://registry.example",
       store=store,
       certificate_authority=authority,
   )

   challenge = service.issue_challenge(ChallengePurpose.PROFILE_REGISTRATION, difficulty=4)
   request = MutationRequest.create(
       identity,
       challenge,
       payload={
           "display_name": "Alice",
           "device_fingerprint": "pact-device-binding-v2.base64url-sha256-token",
       },
       proof_of_work_solution=0,  # supply a solved proof-of-work value
   )
   profile = service.register_profile(request)

   assert profile.key_id == identity.key_id

In normal CLI and browser workflows, PACT derives the device-binding token for
you. Direct API callers must provide a ``pact-device-binding-v2`` token signed
inside the profile-registration mutation. The registry rejects profiles without
that minimum unauthenticated-device proof.

Run the hosted registry/API service
-----------------------------------

Use the CLI entrypoint to serve the JSON API plus public claim and profile
pages:

.. code-block:: bash

   pact registry init \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --root-key-password 'store-this-offline'

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3 \
     --enable-workspace

Once the server is running, the CLI can publish identities and claims without
custom request scripts:

.. code-block:: bash

   pact registry register-profile \
     --registry https://registry.example

   pact sign ./work.txt \
     --registry https://registry.example

   pact registry register-claim ./work.manifest.json \
     --registry https://registry.example

This serves:

- ``/api/v1/registry``
- ``/api/v1/server/info``
- ``/api/v1/inspect``
- ``/api/v1/challenges``
- ``/api/v1/device-bindings/oprf``
- ``/api/v1/profiles/{key_id}``
- ``/api/v1/profiles/{key_id}/evidence``
- ``/api/v1/claims/{claim_id}``
- ``/api/v1/disputes/{dispute_id}``
- public HTML proof pages at ``/profiles/{key_id}``, ``/claims/{claim_id}``,
  and ``/verify/claim/{claim_id}``

Run the loopback-local web UI
-----------------------------

For a local-only browser workflow, bind to loopback. This starts the registry
API, proof pages, and the Pyodide browser workspace:

.. code-block:: bash

   pact web \
     --data-dir ./local-registry \
     --port 8000 \
     --database ./local-registry/registry.sqlite3

That starts the same API and proof-page app on ``127.0.0.1`` with a local
base URL. Open ``/pact`` to use the browser workflow instead of the CLI.

Run only the browser workspace
------------------------------

You can also self-host only the browser interface and point it at a remote
registry:

.. code-block:: bash

   pact web \
     --remote-registry https://registry.example \
     --port 8000

In that mode, the local process serves static workspace assets and Pyodide
feature packs. The browser sends signed mutations directly to the remote
registry. The remote registry must allow the workspace origin with CORS, for
example:

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3 \
     --cors-allowed-origin http://127.0.0.1:8000

Embed a TrustMark soft binding
------------------------------

For supported raster formats, PACT can embed a compact claim locator as a
TrustMark soft binding:

.. code-block:: python

   from pact import embed_image_soft_binding, verify_image_soft_binding

   watermarked = embed_image_soft_binding(
       image_bytes,
       "image/png",
       claim_id=claim.claim_id,
       registry_root_fingerprint=claim.signed_manifest.manifest.registry_root_fingerprint,
   )
   verification = verify_image_soft_binding(
       watermarked.image_bytes,
       "image/png",
       registry_service=service,
   )
   assert verification.registry_match

Create local training-use probes
--------------------------------

PACT can create committed treatment/control probes before you collect provider
responses. The registry does not receive the protected text, prompts,
responses, or analysis package unless the user explicitly publishes them.

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

The ``responses.jsonl`` file contains one JSON object per provider response,
for example ``{"probe_id": "...", "response": "..."}``.

Probe analysis includes confidence intervals and corrected p-values. Library
callers can pass the probe report, watermark or canary detections, image
matches, and registry verification into ``create_training_use_risk_report`` to
produce a combined evidence summary.

Use the CLI for manifest workflows
----------------------------------

``pact inspect`` accepts signed manifest JSON or raw carrier files. For raw
media, it tries supported text, HTML, XML, image watermark, C2PA image/PDF, and
ZIP-based document carriers, then resolves registered claims when the active
registry has the referenced claim.

The CLI currently exposes:

- ``pact identity init|show|export|import|rotate``
- ``pact sign``
- ``pact privacy audit``
- ``pact watermark image``
- ``pact watermark text``
- ``pact verify``
- ``pact inspect``
- ``pact probe create|analyze|export``
- ``pact registry init``
- ``pact registry serve``
- ``pact registry register-profile``
- ``pact registry register-claim``
- ``pact web``
