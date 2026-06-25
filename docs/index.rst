pact Documentation
==================

Open-source identity, policy, signing, and verification primitives for
portable content provenance.

.. raw:: html

   <div class="hero-banner">
     <p class="hero-kicker">Python 3.11</p>
     <h2>pact</h2>
     <p>Project documentation and API reference.</p>
   </div>

Start Here
----------

- :doc:`Quickstart <quickstart>`
- :doc:`Carrier formats <carriers>`
- :doc:`Manifest format <manifest>`
- :doc:`Security model <security>`
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
   api
