PACT Documentation
==================

PACT is a Python toolkit for signing content claims, binding them to files,
and verifying them against a trust registry. It is designed around the premise
that content provenance is a multi-signal problem: rather than collapsing
verification into a single badge, PACT reports what was actually checked —
the claimant signature, registry record, content binding, revocation state, and
dispute history — as independent outputs that applications can reason about
separately.

.. toctree::
   :maxdepth: 2
   :caption: Contents
   :hidden:

   quickstart
   cli
   identity
   manifest
   carriers
   security
   server
   tpm
   legal
   api

Where to start
--------------

New to PACT? Start with the :doc:`quickstart <quickstart>`, which walks through
creating an identity, signing a file, and verifying it against a local registry.

Deploying a registry? See :doc:`server deployments <server>` for the monolith
and AWS Lambda setup guides, environment variable reference, and deployment
checklist.

Evaluating the security model? :doc:`Security model <security>` covers what
the cryptographic guarantees are, the privacy boundary, how device binding
works, and the CA setup. :doc:`Legal and policy notes <legal>` covers what
policy entries do and do not mean.

Building integrations? The :doc:`manifest format <manifest>` and
:doc:`carriers <carriers>` references document the wire format, content binding
algorithm, and carrier helpers for text, HTML, XML, C2PA, PDF, DOCX, and image
formats.

Build docs locally
------------------

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html
