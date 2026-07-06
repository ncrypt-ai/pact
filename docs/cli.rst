CLI commands
============

The ``pact`` command is the main local entrypoint for identity management,
manifest signing, verification, privacy checks, watermarking, probe evidence,
and local registry operation.

Use ``pact --help`` or any subcommand's ``--help`` flag for the complete
argparse-generated option list.

Identity
--------

Identity commands are documented in detail in :doc:`identity`.

.. code-block:: bash

   pact identity init
   pact identity show
   pact identity public-jwk
   pact identity export
   pact identity import
   pact identity rotate

Registry lifecycle
------------------

Create local registry certificate-authority and OPRF material:

.. code-block:: bash

   pact registry init \
     --registry http://127.0.0.1:8000 \
     --data-dir ./.pact-dev \
     --root-key-password 'store-this-offline'

Serve the local monolith registry with SQLite persistence:

.. code-block:: bash

   pact registry serve \
     --registry http://127.0.0.1:8000 \
     --data-dir ./.pact-dev \
     --public-base-url http://127.0.0.1:8000 \
     --database ./.pact-dev/registry.sqlite3 \
     --enable-workspace

Tear down local persistent state for one registry:

.. code-block:: bash

   pact registry teardown \
     --registry http://127.0.0.1:8000 \
     --data-dir ./.pact-dev \
     --database ./.pact-dev/registry.sqlite3

``teardown`` deletes local registry CA/OPRF files, the selected SQLite
database files, and this machine's local device-binding record for the
specified registry. It prints the planned deletions and requires two
confirmations: the normalized registry URL, then the exact phrase
``delete registry <registry-url>``.

For noninteractive automation, pass both confirmation values explicitly:

.. code-block:: bash

   pact registry teardown \
     --registry http://127.0.0.1:8000 \
     --data-dir ./.pact-dev \
     --database ./.pact-dev/registry.sqlite3 \
     --confirm-registry http://127.0.0.1:8000 \
     --confirm-delete 'delete registry http://127.0.0.1:8000'

Use this command only for local development resets or intentional registry
decommissioning. It is destructive and does not contact a running remote
registry.

Registry publication and admin actions
--------------------------------------

.. code-block:: bash

   pact registry register-profile
   pact registry register-claim ./work.manifest.json
   pact registry verify-domain example.com
   pact registry authorize-hosted-account CLAIMANT_KEY_ID
   pact registry complete-hosted-login CLAIMANT_KEY_ID
   pact registry attest-third-party CLAIMANT_KEY_ID

These commands create signed mutation requests. Profile registration derives
the registry-scoped device-binding token locally through the blinded OPRF
flow; raw device fingerprint material is not sent to the registry.

Manifest workflows
------------------

.. code-block:: bash

   pact sign ./work.txt
   pact verify ./work.manifest.json --content ./work.txt
   pact inspect ./work.txt
   pact privacy audit ./work.manifest.json --content ./work.txt

Watermarks and probes
---------------------

.. code-block:: bash

   pact watermark image input.png --claim-id CLAIM_ID --output output.png
   pact watermark text work.txt --methods lexical,syntactic --confirm
   pact probe create --protected protected.txt --control control.txt
   pact probe analyze probes.json --responses responses.jsonl
   pact probe export evidence.json --output evidence-export.json

Browser workspace
-----------------

Run the loopback-local browser workspace and local registry:

.. code-block:: bash

   pact web \
     --data-dir ./local-registry \
     --port 8000 \
     --database ./local-registry/registry.sqlite3

Serve only the browser workspace and point it at a remote registry:

.. code-block:: bash

   pact web \
     --remote-registry https://registry.example \
     --port 8000
