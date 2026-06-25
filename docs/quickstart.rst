Quickstart
==========

PACT currently provides library APIs for registry-scoped claimant identities,
policies, signed manifests, local verification, text/HTML/XML carrier
embedding, and an initial C2PA integration layer for supported image formats.
The registry, CLI, web UI, and full PDF C2PA embedding remain later work.

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
