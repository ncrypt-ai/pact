API Reference
=============

HTTP API examples
-----------------

Registry metadata is public:

.. code-block:: bash

   curl https://registry.example/api/v1/registry

Inspect a signed manifest or carrier file:

.. code-block:: bash

   curl -F file=@work.txt -F mime_type=text/plain \
     https://registry.example/api/v1/inspect

Fetch public profile and claim state:

.. code-block:: bash

   curl https://registry.example/api/v1/profiles/CLAIMANT_KEY_ID
   curl https://registry.example/api/v1/claims/CLAIM_ID

State-changing endpoints use signed mutation envelopes. The CLI and browser
workspace are the safest way to produce those envelopes. Direct integrations
must first request a challenge, solve proof-of-work, sign the exact challenge
and payload, and submit the resulting mutation request.

Profile registration also needs a private ``pact-device-binding-v2`` token. The
browser and CLI derive it automatically. Direct browser integrations use the
public OPRF endpoint as part of that derivation:

.. code-block:: bash

   curl -X POST https://registry.example/api/v1/device-bindings/oprf \
     -H 'content-type: application/json' \
     -d '{"x":"BASE64URL_P256_X","y":"BASE64URL_P256_Y"}'

The OPRF endpoint receives a blinded P-256 point. It should not receive raw
browser traits, raw hardware values, profile passcodes, or local secret
material.

Public package
--------------

.. automodule:: pact
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Canonicalization
----------------

.. automodule:: pact.canonical
   :members:

Cryptography
------------

.. automodule:: pact.crypto
   :members:

OPRF helpers
------------

.. automodule:: pact.oprf
   :members:

Identity
--------

.. automodule:: pact.identity
   :members:

Policy
------

.. automodule:: pact.policy
   :members:

Manifest
--------

.. automodule:: pact.manifest
   :members:

Privacy
-------

.. automodule:: pact.privacy
   :members:

Detection
---------

.. automodule:: pact.detection.probes
   :members:

.. automodule:: pact.detection.statistics
   :members:

.. automodule:: pact.detection.evidence
   :members:

.. automodule:: pact.detection.risk
   :members:

Carriers
--------

.. automodule:: pact.carriers.text
   :members:

.. automodule:: pact.carriers.structured
   :members:

.. automodule:: pact.carriers.c2pa
   :members:

.. automodule:: pact.carriers.c2pa_text
   :members:

Watermarks
----------

.. automodule:: pact.watermarks.base
   :members:
   :no-index:

.. automodule:: pact.watermarks.image
   :members:
   :no-index:

.. automodule:: pact.watermarks.invisible
   :members:
   :no-index:

.. automodule:: pact.watermarks.lexical
   :members:
   :no-index:

.. automodule:: pact.watermarks.syntactic
   :members:
   :no-index:

.. automodule:: pact.watermarks.semantic
   :members:
   :no-index:

.. automodule:: pact.watermarks.canary
   :members:
   :no-index:

.. automodule:: pact.watermarks.statistical
   :members:
   :no-index:

.. automodule:: pact.watermarks.textual
   :members:
   :no-index:

Registry
--------

.. automodule:: pact.registry.app
   :members:

.. automodule:: pact.registry.store
   :members:

Server
------

.. automodule:: pact.server.config
   :members:

.. automodule:: pact.server.aws
   :members:

.. automodule:: pact.server.runtime
   :members:

.. automodule:: pact.server.lambda_app
   :members:
