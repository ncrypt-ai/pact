Identity commands
=================

PACT identities are registry-scoped signing keys. The same key signs manifests,
profile-registration requests, claim-registration requests, and registry
admin actions when that identity's public JWK is configured as an admin key.

By default, identity commands use the operating-system keyring. For repeatable
development, automation, or examples, pass ``--identity-file`` and
``--identity-password`` to use a password-encrypted local file instead.

Common options
--------------

Every ``pact identity`` subcommand accepts:

- ``--registry``: the registry URL the identity belongs to. When omitted, PACT
  uses ``PACT_REGISTRY_URL`` or prompts.
- ``--identity-file``: encrypted local identity store. Omit this to use the OS
  keyring.
- ``--identity-password``: password for ``--identity-file``. When omitted, PACT
  uses ``PACT_IDENTITY_PASSWORD`` or prompts securely.

Create an identity
------------------

Use ``init`` once per registry identity:

.. code-block:: bash

   pact identity init \
     --registry https://registry.example \
     --identity-file ./secrets/alice.identity.pem \
     --identity-password 'store-this-in-your-password-manager'

The output includes the registry URL, claimant key ID, and the local
device-binding token associated with this identity.

Show the public profile material
--------------------------------

Use ``show`` to print the public JWK and key ID for the local identity:

.. code-block:: bash

   pact identity show \
     --registry https://registry.example \
     --identity-file ./secrets/alice.identity.pem \
     --identity-password 'store-this-in-your-password-manager'

This does not print the private key.

Write a public JWK file
-----------------------

Use ``public-jwk`` when another process needs the public key object by itself.
The main use today is registry admin setup:

.. code-block:: bash

   pact identity public-jwk \
     --registry https://registry.example \
     --identity-file ./secrets/admin.identity.pem \
     --identity-password 'store-this-in-your-password-manager' \
     --out ./secrets/admin.public.jwk.json

Start a local registry with that admin key:

.. code-block:: bash

   pact registry serve \
     --registry https://registry.example \
     --data-dir ./registry-data \
     --public-base-url https://registry.example \
     --database ./registry-data/registry.sqlite3 \
     --admin-jwk-file ./secrets/admin.public.jwk.json

The server stores only the public JWK. Keep the admin identity file private;
it is the key that signs admin requests such as hosted-account authorization.

Export a private identity backup
--------------------------------

Use ``export`` to write an encrypted PKCS#8 private-key backup:

.. code-block:: bash

   pact identity export \
     --registry https://registry.example \
     --identity-file ./secrets/alice.identity.pem \
     --identity-password 'current-file-password' \
     --export-password 'backup-password' \
     --out ./backups/alice.identity.pkcs8.pem

The export password protects the backup file. It can be different from the
local identity-file password.

Import a private identity backup
--------------------------------

Use ``import`` to restore an encrypted PKCS#8 backup into the local identity
store:

.. code-block:: bash

   pact identity import \
     --registry https://registry.example \
     --identity-file ./secrets/alice-restored.identity.pem \
     --identity-password 'new-local-file-password' \
     --source ./backups/alice.identity.pkcs8.pem \
     --import-password 'backup-password'

PACT refuses to import an identity when the current device is already bound to
a different identity for the same registry. Rotate the existing identity
instead when you are replacing a local key. For deliberate local registry
decommissioning or development resets, ``pact registry teardown`` can remove
the registry's local device-binding record after multiple confirmations.

Rotate an identity
------------------

Use ``rotate`` when the current identity should be replaced while preserving
device continuity:

.. code-block:: bash

   pact identity rotate \
     --registry https://registry.example \
     --identity-file ./secrets/alice.identity.pem \
     --identity-password 'store-this-in-your-password-manager'

The command writes the replacement identity back to the selected identity
store and prints the previous and replacement key IDs. Publish the rotation to
the registry before relying on the new key for public verification workflows.
