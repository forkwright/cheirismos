# Generic recovery runbook

This runbook governs a physical recovery case after a target is available. It
is deliberately target-neutral; its steps do not identify a chip, voltage,
pinout, or firmware layout by inference.

1. **Open and preserve the case.** Record the objective, deadline, target
   identity, current configuration, historical attempts, and source evidence.
   Separate observations, claims, hypotheses, and proposed effects.
2. **Perform intake.** Obtain the physical markings, topology, power model,
   instrument identity, and fixture mapping needed by the next operation.
   Missing facts remain unknown and block only dependent work.
3. **Qualify independently.** Test an instrument and its adapter on a
   sacrificial or otherwise safe target. Then qualify the actual fixture and
   electrical limits for the DUT. Do not extrapolate between either step.
4. **Commission and delegate.** Bind the target, controller, instruments,
   fixture revision, permitted effect classes, limits, evidence store, expiry,
   and revocation policy. Grant only the scope required for the case.
5. **Acquire before mutation.** Make repeatable, complete, read-only captures
   when the target permits them. Preserve immutable originals in independent
   storage and record both electrical and content plausibility evidence.
6. **Plan the least destructive experiment.** State the question, required
   preconditions, expected observations, stop condition, and recovery path.
   Review it independently when the grant or effect class requires review.
7. **Admit and execute.** The supervisor durably records intent, acquires the
   target lease, verifies interlocks, and performs the bounded effect. It
   records observations and a receipt throughout the operation.
8. **Reconcile ambiguity.** On interruption, loss of contact, or uncertain
   outcome, stop automatic progression. Collect fresh device evidence and
   resolve the attempt as verified, failed, or still unknown.
9. **Validate the recovery.** Define target-specific functional and reliability
   checks before declaring success. A completed write or initial boot is not a
   recovery conclusion.
10. **Close or escalate.** Preserve the evidence bundle and recommendation.
    Escalate when the next necessary observation or effect exceeds the
    qualified fixture or authority; retain the platform work and case ledger.
