PACT Documentation
==================

Open-source identity, policy, signing, and verification primitives for
portable content provenance.

.. raw:: html

   <div class="hero-banner">
     <p class="hero-kicker">Python 3.11</p>
     <h2>PACT</h2>
     <p>Project documentation and API reference.</p>
   </div>

Start Here
----------

- :doc:`Quickstart <quickstart>`
- :doc:`Carrier formats <carriers>`
- :doc:`Manifest format <manifest>`
- :doc:`Security model <security>`
- :doc:`Technological protection measure specification <tpm>`
- :doc:`Server deployments <server>`
- :doc:`Legal and policy notes <legal>`
- :doc:`API reference <api>`

Build Documentation Locally
---------------------------

.. code-block:: bash

   uv run sphinx-build -b html docs docs/_build/html

.. toctree::
   :maxdepth: 2
   :caption: Reference
   :hidden:

   quickstart
   carriers
   manifest
   security
   tpm
   server
   legal
   api
