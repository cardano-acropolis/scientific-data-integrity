# Scientific Data Integrity

A repository for the data-integrity project, which emcompasses both
hashing data at the point of integrity and establishing a chain of
custody and quality for reagents.

For reagent integrity, it would be wise to first start with the domain
with the highest stakes: namely medical testing.

## Reagent Integrity

 1. Structure
    1. Aggregate QC documents
    2. Set up a common structure
 2. Common QC platforms
    1. Research common QC platforms
    2. Consider implementing an automated solution that integrates
       with the internal manufacturing step-verification involved
       medical testing reagents.
 3. PRISM
    1. Set up PRISM identities and tracking for reagents.
 4. Contact NIH, AMA, CDC, WHO, etc.
    1. Find existing database standards.
    2. Adapt to blockchain migration.

## Data Integrity

### Outline

 1. Plan for data hashing and submission at the point of acquisition.
    1. Research software and connectivity mechanisms.
    2. Identify how to source funding on the blockchain.
    3. Develop proof of concept.
 2. Proposal to BD
    1. Research current initiatives
    2. Plan point of contact (audience)
    3. Prepare presentation
    4. Contact
    5. Present
 3. Proposal to NIH
    1. Research current initiatives
    2. Contact Flow Repository to see if they would be willing to
       partner.
	   
### Tasks

 * [ ]  Task force to identify current projects and implement
        proof-of-concept for data hashing
 * [ ]  Task force to imagine how an academic system of anonymous or
        pseudonymous publishing would work (apropos of Charles
        Hoskinson)
 * [ ]  We should speak with FlowJo at BD
 * [ ]  Connect with the API developers for Flow Repository

### Risks of AI

Generative AI sharpens exactly the threat this project exists to
counter. It lowers the cost of fabrication while raising the cost of
detection, so a strategy built on *catching* fakes after publication is
losing ground every year. This is the core argument for anchoring
provenance at the point of acquisition rather than policing outputs
downstream.

 1. Fabrication at scale
    1. Generative models can synthesize plausible raw data —
       microscopy images, western blots, flow cytometry `.fcs` files,
       spectra — that pass visual inspection and summary-statistic
       checks.
    2. Paper mills, already an industrial problem, gain throughput and
       polish. What took a skilled forger now takes a prompt.
    3. Synthetic data can be tuned to defeat the very anomaly detectors
       (e.g. duplicate-image screens like those used by Elisabeth Bik)
       that currently find fraud.
 2. The detection arms race is unwinnable head-on
    1. Every detector becomes training signal for the next generator.
    2. "AI-detector" tools are unreliable and produce false positives
       that harm honest researchers, so they cannot be the sole gate.
    3. Absence of a detectable artifact is not evidence of authenticity.
 3. Erosion of trust
    1. Once reviewers assume any dataset *could* be synthetic, the
       burden of proof inverts and legitimate work is harder to
       publish.
    2. Retractions and reproducibility failures compound the credibility
       problem the field already faces.
 4. Why provenance beats detection
    1. A cryptographic hash committed on-chain **at the moment of
       acquisition**, from the instrument or capture software, binds the
       data to a time and (pseudonymous) identity before any opportunity
       to fabricate or edit.
    2. Verification then asks "does this match what was recorded at
       acquisition?" — a question AI cannot forge — instead of "does
       this look fake?", which AI is built to defeat.
    3. This shifts the trust anchor from the appearance of the data to
       an immutable, timestamped commitment, and it is robust regardless
       of how good generators become.
 5. Implications for this project
    1. Hashing should live as close to the instrument/acquisition step
       as possible; anything captured after the fact inherits the same
       forgeability we are trying to eliminate.
    2. The reagent workstream faces the mirror risk: AI-generated QC
       documents and certificates of analysis. On-chain chain-of-custody
       for reagents answers this the same way.
    3. Threat model to keep in view: an adversary with the acquisition
       device can still hash fabricated data, so device attestation and
       trusted-capture paths are the harder, higher-value problem —
       hashing alone proves *when*, not *that it is real*.

### Revolution in Scientific Transparency

These are the notes from the twitter space.

 1. Pasteur put in his will not to let anyone see his lab notebook.
 2. Fraud and abuse in science as shown by [Elisabeth
    Bik](https://www.nature.com/articles/d41586-020-01363-z) in [her
    twitter](https://twitter.com/MicrobiomDigest) along with
    @mortenoxe, @TigerBB8 and @SmutClyde
 3. The field is pushing for more transparency, rigor, and
    reproducibility.
	   1. [NIH policies and
          guidelines](https://www.niaid.nih.gov/grants-contracts/rigor-and-reproducibility-forms-f)
	   2. [FlowRepository](https://flowrepository.org/) and the [role
          of Flow
          Cytometry](https://onlinelibrary.wiley.com/doi/10.1002/cyto.a.23940)
	   3. [Journals](https://www.nature.com/articles/533452a)
	   4. [Ngram](https://books.google.com/ngrams/graph?content=rigor+and+reproducibility&year_start=1800&year_end=2019&corpus=26&smoothing=3&direct_url=t1%3B%2Crigor%20and%20reproducibility%3B%2Cc0)
	   5. [How-to
          guide](https://journals.asm.org/doi/10.1128/mBio.01902-16)
 4. Potential strategies to get started
	   1. Hash data automatically and store hashes in NFTs on the
          blockchain.
	   2. [Publishing](https://www.nature.com/articles/533452a)
	   3. Publishing anonymously and verifying data authenticity
	   4. VABrandon's note that QC and reagents could be stored
          on-chain. I should say that probably hashes will be
          sufficient, but we can do side-chains.
 5. Action items
	   1. Task force to identify current projects and implement
          proof-of-concept for data hashing
	   2. Task force to imagine how an academic system of anonymous or
          pseudonymous publishing would work (apropos of Charles
          Hoskinson)
       3. We should speak with FlowJo at BD.
       4. Connect with the API developers for Flow Repository
