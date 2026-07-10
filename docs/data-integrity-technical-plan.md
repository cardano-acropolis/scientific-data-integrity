# Data Integrity — Technical Plan

Scope: the **Data Integrity** workstream (see `../README.md`). This document
(1) assesses whether secure hardware is necessary, (2) plans a software
proof-of-concept that installs alongside the analysis software on any
computer, and (3) surveys industry grants and partnerships.

Guiding principle from the README's threat model: hashing proves *when* and
*by whom* a dataset was committed — not *that the underlying science is real*.
We build for **provenance**, and we are precise about not overclaiming
**proof of truth**.

---

## 1. Is secure hardware necessary?

Short answer: **No — not for the proof-of-concept, and it should not gate v1.**
A software-only approach delivers guarantees that are strictly better than the
status quo, and it is honest about its limits. Secure hardware belongs in a
later, optional tier, and its real value (device attestation *at the
instrument*) requires a manufacturer partnership — a strategic goal, not a v1
dependency. Mandating secure hardware would also directly contradict the
requirement that the software install on *any* computer.

### What each layer actually proves

An on-chain hash commitment gives us three things:

| Property | Guaranteed by | Meaning |
|---|---|---|
| **Integrity** | hash | the file has not changed since it was committed |
| **Existence / time** | block timestamp | the data existed at or before block time (proof of priority) |
| **Attribution** | signing key | committed by a specific (pseudonymous) identity |

It does **not** guarantee **authenticity of origin**: that the bytes came from a
genuine measurement rather than a generator. The chain will faithfully record a
hash of fabricated data. Closing that gap is what secure hardware is *for*.

### What secure hardware buys — and what it doesn't

Secure hardware (workstation **TPM**, a **TEE**/enclave such as Intel SGX,
AMD SEV, ARM TrustZone, or Apple Secure Enclave; an **HSM**; or an
instrument-embedded **secure element** with remote attestation) can:

- attest that the hashing/capture code ran unmodified in a known-good
  environment;
- sign measurements with a device key provisioned by the instrument
  manufacturer, so the signature proves "this came from BD instrument serial
  #X on firmware Y";
- make the capture path tamper-evident.

Its limits are fundamental:

1. **The analog hole.** Even a perfectly attested instrument only proves the
   bytes came from *that device's digitizer* — not that the physical sample was
   real. A spoofed or synthetic sample fed into a genuine instrument produces
   genuinely-attested fake data. Hardware raises the bar; it never reaches "the
   science is real."
2. **Deployment friction.** Instrument-level attestation needs manufacturer
   buy-in (firmware signing, key provisioning). Fielded instruments cannot be
   retrofitted. This is a multi-year partnership, not a POC input.
3. **Trust is relocated, not removed.** Attestation shifts the trust root to the
   hardware vendor and their CA — a different, non-zero assumption.
4. **It contradicts "install on any computer."** Mandatory TEEs/TPMs exclude
   the machines many labs actually run.

### Recommended stance: a tiered trust model

Design v1 as software-only, but make the signer and attestation swappable so
higher tiers slot in without redesign.

- **Tier 0 — status quo.** Trust the publisher entirely. (What we're replacing.)
- **Tier 1 — software (this project's v1).** Hash at the earliest software
  capture point on the acquisition workstation; anchor on-chain; sign with a
  researcher/lab key. Proves integrity + time + attribution. Defeats
  edit-after-the-fact, silent re-analysis of "raw" files, and backdating. Does
  **not** stop a determined fabricator. Requires nothing but the software.
- **Tier 2 — software + platform hardening.** Run the capture agent inside a TEE
  with remote attestation and/or bind the signing key to the workstation TPM.
  Proves "an unmodified capture agent ran on this machine." Workstation-level,
  broadly retrofittable, no manufacturer needed.
- **Tier 3 — instrument attestation.** Manufacturer-provisioned device keys sign
  measurements at the source. Proves origin device + firmware — closest to
  genuine, modulo the analog hole. Requires BD/vendor partnership.

**Build Tier 1 now. Architect for Tier 2/3. Pursue Tier 3 as a partnership
track in parallel.** Crucially, message the guarantee honestly: we provide
verifiable *provenance*, not *proof that the data is true*.

---

## 2. Software development plan

**Constraint:** installs on the analysis software of *any* computer, with
minimal friction and no mandatory hardware. That constraint drives the whole
design toward a lightweight, cross-platform agent that meets existing
workflows where they already are.

### Architecture (layered, each layer pluggable)

1. **Capture layer — how data enters (ordered by universality):**
   - **Watched-folder daemon (primary).** Monitors the acquisition output
     directory; when a file is closed/finalized (e.g. a new `.fcs`), it is
     hashed. Zero integration with proprietary software — this is what makes it
     work on *any* computer.
   - **Plugin/export hooks (better UX, vendor-specific).** FlowJo exposes a
     plugin API; instrument acquisition software (e.g. BD DIVA) has export
     hooks. Higher friction, higher assurance of catching data at the source.
   - **CLI + library.** For scripted pipelines and LIMS integration.
2. **Hashing layer.** FCS files carry a TEXT segment (keyword metadata) and a
   DATA segment (the event matrix). We compute:
   - a hash over the **raw file bytes** (anyone holding the file can verify), and
   - optionally a **canonical hash over the DATA segment alone**, so metadata
     edits are distinguishable from data edits.
   - Use a **Merkle tree over event blocks** for streaming large files and
     partial verification. Algorithm: **Blake2b-256** for the on-chain
     identifier (Cardano-native, cheap), with SHA-256 available for external
     interoperability. Every choice documented.
3. **Manifest layer.** Emit a provenance manifest (JSON; align with **W3C PROV**
   and consider **C2PA**-style content credentials) capturing file hash(es),
   size, MIFlowCyt-relevant instrument metadata harvested from FCS keywords
   (`$CYT`, `$DATE`, `$OP`, …), pseudonymous operator/lab ID, software version,
   and timestamp. The manifest is itself hashed.
4. **Signing layer.** Sign the manifest with an **Ed25519** researcher/lab key.
   Expose a **pluggable signer interface** so a TPM, TEE, HSM, or
   instrument-provisioned key (Tier 2/3) drops in unchanged.
5. **Anchoring layer (Cardano).**
   - **POC:** write the hash into **transaction metadata** on a testnet
     (preprod/preview) via **Blockfrost**, using a serialization library
     (**PyCardano**, or **Lucid**/**MeshJS** in TypeScript).
   - **Vision (per README):** mint an **NFT** representing the dataset
     commitment using **CIP-25** (or **CIP-68**) metadata — ownable,
     transferable proof.
   - **Cost control at scale:** batch many hashes into a **Merkle root** and
     anchor the root periodically (the OpenTimestamps pattern); each dataset
     gets an inclusion proof, keeping per-dataset on-chain cost near zero.
6. **Verification layer.** A verifier (CLI + static web page): given a file +
   manifest, recompute the hash, check the signature, resolve the Cardano tx
   (Blockfrost/explorer), and confirm the hash is anchored and the block time.
   Fully public and trustless.
7. **Identity layer.** Pseudonymous keys satisfy the README's
   anonymous/pseudonymous-publishing goal. Optionally issue **DIDs** —
   **Atala PRISM / Identus** is Cardano-native and already named for the reagent
   track — to bind a durable identity without doxxing.

### Stack recommendation (a decision to confirm)

Per `CLAUDE.md`, the stack is not yet established, so this is a recommendation,
not a commitment:

- **Proof-of-concept: Python.** Fastest path to the end-to-end loop; `watchdog`
  for file events, `PyCardano` + Blockfrost for anchoring, native fit with the
  Jupyter/FlowJo/scientific ecosystem.
- **Production agent: Rust (or Go).** A single static, cross-compiled binary
  with a strong file-watching (`notify`) and crypto story for a
  distribute-to-any-lab daemon.

I'll want to confirm this choice with you before scaffolding code.

### Phased roadmap

- **Phase 0 — Spike (the README's requested deliverable). ✅ Implemented in
  [`../poc/`](../poc/).** Python CLI (`keygen` / `make-sample` / `commit` /
  `verify`): hash a local `.fcs` (FCS-aware, separable TEXT/DATA hashes, Merkle
  tree over event rows), build + sign an Ed25519 provenance manifest, and anchor
  it. Runs end-to-end today against a **local** anchor backend; the **Cardano
  preprod** backend (Blockfrost transaction metadata) is wired behind the same
  interface and activates when `pycardano` + a funded preprod wallet + a
  Blockfrost key are supplied.
- **Phase 1 — Daemon.** Watched-folder agent + Merkle batching/anchoring service
  + verifier web page.
- **Phase 2 — Integration.** FlowJo plugin / instrument export hook; full
  MIFlowCyt manifest; NFT (CIP-25/68) option; pseudonymous DID identity.
- **Phase 3 — Attestation.** TPM/TEE Tier 2; BD-partnership instrument-key pilot
  (Tier 3).
- **Cross-cutting.** Reproducible + signed builds, OSI-approved license, docs,
  and a living threat-model document that states the guarantee precisely.

---

## 3. Grants and partnerships

**Framing matters.** This project has two fundable faces, and they appeal to
different money. As *open-source software for data provenance and
reproducibility* it reaches the largest, best-aligned pools (NSF, CZI, Sloan).
As a *Cardano application* it reaches Catalyst/Intersect. With mainstream
science funders the blockchain angle is often a liability — **lead with
"cryptographic, tamper-evident provenance" and treat Cardano as an
implementation detail** everywhere except category 1 below.

Amounts and deadlines below come from the cited pages; several government and
funder sites block automated fetching, so **verify figures on the primary page
before applying** — treat them as indicative.

### Cardano ecosystem

- **Project Catalyst** — community-treasury (ADA) grants in ~12-week Funds,
  community-voted; $150M+ distributed historically. Propose the PoC into
  *Cardano Use Cases: Concepts* (early prototypes/MVPs) or *Cardano Open:
  Developers*. Most accessible, fastest money; awards are small.
  <https://projectcatalyst.io/> ·
  <https://docs.projectcatalyst.io/current-fund/fund-basics/fund-rules>
  *(A standing "research-integrity" category is unconfirmed — challenges are
  set per-Fund; frame the science angle yourself.)*
- **Intersect MBO** — member-governed ecosystem-budget grants and open tenders;
  more infrastructure/tooling-oriented. Watch for relevant tenders.
  <https://www.intersectmbo.org/grants>
- **Cardano Foundation** — relationship/endorsement-driven, not an open portal;
  aligns with their "real-world utility" messaging.
- **IOG** — no standing public grant program; route through Catalyst/Intersect.
  <https://developers.cardano.org/docs/community/funding/>

### US federal

- **NSF CICI — IPAAI program area (NSF 25-531)** — the strongest federal fit:
  explicitly funds *integrity, provenance, and authenticity of scientific data*
  for reproducibility. Needs a US institutional (university) PI.
  <https://www.nsf.gov/funding/opportunities/cici-cybersecurity-innovation-cyberinfrastructure/nsf25-531/solicitation>
- **NSF POSE / PESOSE** — funds building a sustainable community around an
  *existing* open-source tool (Phase I ≈ $300K, Phase II ≈ $1.5M). Does **not**
  fund initial creation — strong *once a PoC + users exist*, premature at day
  zero. <https://www.nsf.gov/funding/opportunities/pose-pathways-enable-open-source-ecosystems>
- **NIH Rigor & Reproducibility** — a policy/review framework, not a grant.
  Use it as *justification language* ("operationalizes NIH authentication
  requirements for flow cytometry"). <https://grants.nih.gov/policy-and-compliance/policy-topics/reproducibility>
- **HHS Office of Research Integrity (ORI)** — small grants for *research on*
  integrity/transparency (Phase I ≈ $75K). A rare federal home for the
  anti-fraud framing if cast as a research question.
  <https://ori.hhs.gov/funding-opportunity-research-grants-research-integrity>
- **NIST** — a standards ally (hashing, provenance frameworks) to cite for
  credibility, **not** a realistic grant source here.

### Open-science / metascience philanthropy

- **CZI EOSS** (co-sponsored with **Kavli** and **Wellcome**) — best-fit
  biomedical open-source funding (≈ $400K/2 yrs, LOI → full app). Reaches three
  named funders at once — but EOSS funds *already-adopted* tools, so **sequence
  it after a PoC + real users**.
  <https://chanzuckerberg.com/rfa/essential-open-source-software-for-science/>
- **Alfred P. Sloan — Open Source in Science** — rolling LOIs, no deadline;
  funds the *ecosystem/norms/incentives* around research software. Receptive to
  unconventional infrastructure ideas. <https://sloan.org/programs/digital-technology/open-source-in-science>
- **Astera Institute** — metascience-native open-science program + public-goods
  residency; comfortable with novel (incl. blockchain) mechanisms. Relationship,
  not open RFP. <https://astera.org/open-science/>
- **Open Philanthropy / Templeton** — no specific matching program verified;
  low priority absent an open RFP.

### Industry & standards partnerships (adoption/credibility, not cash)

- **BD (Becton Dickinson) / FlowJo** — the dominant cytometer + analysis-software
  vendor; the critical partner for embedding hashing at the point of
  acquisition, and the path to the Tier 3 instrument-key pilot. Already named in
  the project charter.
- **ISAC** — owns the **FCS** file standard and **MIFlowCyt**; the standards
  home for proposing acquisition-time hashes as an FCS/MIFlowCyt extension.
  <https://isac-net.org/page/Data-Standards> · <https://isac-net.org/miflowcyt-2/>
- **FlowRepository** — ISAC-affiliated public repository; the natural place to
  anchor and verify published-data hashes. <http://flowrepository.org/>
- **ARTiFACTS / Bloxberg** — the closest existing analogs (blockchain research
  provenance, Ethereum-based); study as competitor/interoperability reference.
- **DeSci — Molecule / DeSci DAOs** — ideologically aligned, crypto-native seed
  funding and community; higher-variance. <https://ethereum.org/desci/>

### Recommended targets, in order

1. **NSF CICI / IPAAI** — most on-target federal money (needs a university PI).
2. **Project Catalyst (Concepts / Developers)** — fastest, most accessible; good
   for the first deliverable. Smaller dollars.
3. **Sloan — Open Source in Science** — rolling, unconventional-friendly.
4. **CZI EOSS** — best philanthropy fit, but *after* adoption exists.
5. **ISAC + BD/FlowJo + FlowRepository partnerships** — not cash, but what makes
   the rest fundable; pursue from day one.

Sequencing: Catalyst + partnerships now → NSF CICI with an academic PI → POSE
and EOSS once a tool and community exist.
