Legal and Policy Notes
======================

PACT records signed claims and policy metadata. It does not decide who owns a
work, whether a license is valid, whether training occurred, or whether a use is
legal. Treat PACT output as provenance and evidence metadata that can support a
review, not as legal advice.

PACT has not yet received formal legal review, a court endorsement, or
regulatory approval. Operators and users should have counsel review the exact
workflow, policy language, and jurisdiction before relying on PACT in a legal
process.

Plain-language notice
---------------------

Plain-text carrier embeddings include this notice:

.. code-block:: text

   PACT NOTICE: This embedded proof is provenance and usage-rights metadata. It is not legal advice, does not transfer copyright or license rights, and should be reviewed with the surrounding content and applicable law.

The notice is visible when PACT embeds a plain-text proof. Extraction removes
the notice before returning the content body, so verification still checks the
user-selected content.

What a policy means
-------------------

A PACT policy is the claimant's machine-readable instruction or assertion. For
example, a policy can say that generative training is not allowed. That is useful
for routing, review, logging, and enforcement systems, but it is not the same as
a court finding, platform decision, or contract.

Applications should display policy results with context:

- who signed the claim
- what content was checked, if any
- whether the nonce was public or private
- what registry evidence exists
- whether the claim is disputed, revoked, or only partially verified

Manifest removal and rights metadata
------------------------------------

Removing a PACT manifest is not just a technical event. In the United States,
the Digital Millennium Copyright Act includes rules for copyright management
information. 17 U.S.C. Section 1202 prohibits, among other things, knowingly
removing or altering copyright management information without authority when the
person knows, or has reasonable grounds to know, that doing so will induce,
enable, facilitate, or conceal infringement. Civil remedies are described in
17 U.S.C. Section 1203.

References:

- 17 U.S.C. Section 1202: https://www.law.cornell.edu/uscode/text/17/1202
- 17 U.S.C. Section 1203: https://www.law.cornell.edu/uscode/text/17/1203

PACT manifests are designed to carry information that can identify a work,
identify a claimant, point to a registry claim, and express terms or conditions
for use. That kind of metadata may be relevant to copyright management
information analysis. If someone strips the manifest or locator and then uses
the work in a way that violates the manifest's rights-related requests, the
removal may be evidence that they tried to get around rights and provenance
information.

This does not mean every policy violation is automatically copyright
infringement, or that every removed manifest automatically creates liability.
The legal question depends on the work, the rights involved, the user's
authority, the policy language, the later use, and the knowledge or reasonable
grounds required by the statute. The practical point is still important:
applications and operators should treat manifest removal as a serious
rights-management and provenance signal, especially when followed by conduct the
manifest prohibited.

C2PA context
------------

PACT supports C2PA because many real files and tools use it for content
credentials. The official C2PA project is at https://c2pa.org/.

PACT does not treat C2PA as magic trust. A C2PA credential can help carry
metadata through an image, PDF, document, or text workflow, but it does not by
itself prove authorship, ownership, originality, or legal permission. Those
questions need registry evidence, claimant context, and sometimes human review.

For broader context, these critiques are worth reading:

- https://lowentropy.net/posts/c2pa/
- https://www.hackerfactor.com/blog/index.php?/archives/1028-VIDA-The-Simple-Life.html

Those links are not endorsements of every conclusion. They are useful reminders
that provenance systems need careful user experience, threat modeling, and
honest language about what was verified.

Private claims
--------------

Private claims should not send plaintext, private nonces, prompts, probe text,
provider responses, or private evidence packages to a registry. The registry
should receive the signed manifest envelope and public evidence only.

If exact content verification should be restricted, sign with a private nonce
and share that nonce only with the intended verifier.

Deployment policy
-----------------

Operators are responsible for local law, retention policy, abuse handling, and
user-facing terms. At minimum, a production registry should document:

- who operates the registry
- what public profile and claim data is retained
- how disputes and revocations are handled
- how security issues are reported
- whether uploads to inspection endpoints are logged
- what rate limits and abuse controls are active
- how registry CA keys and database backups are protected
