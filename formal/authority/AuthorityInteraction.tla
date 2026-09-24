------------------------------ MODULE AuthorityInteraction ------------------------------
\* AR-0099: bounded TLA+ model of the mandatory AWC/AWR/AWQ/AWG/UI gates.
\*
\* This is intentionally an abstraction.  The Python AR-0098 model and the
\* runtime are refinement targets; neither one is substituted for this model.

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Jobs, MaxRepairs

Phases == {"new", "admitted", "leased", "dispatched", "executing",
           "quality_pending", "quality_accepted", "oracle_pending",
           "repair_pending", "ui_pending", "completion_pending",
           "recovering", "completed", "blocked"}
Authorities == {"awc", "awr", "awq", "awg", "ui", ""}
QualityStates == {"not_decided", "accepted", "rejected", "unknown"}
GuidanceStates == {"not_required", "pending", "requires_ui", "approved", "rejected"}
UIStates == {"not_required", "pending", "approved", "rejected", "ambiguous", "expired"}
ChangeKinds == {"none", "ordinary_alternative", "refinement", "test_change",
                "specification_change", "repair_escalation"}

VARIABLES phase, revision, lease, quality, guidance, ui, changeKind,
          repairAttempts, repairRequired, checkpoint, terminalCommit,
          lastOperation, lastAuthority, lastJob, lastRevision, lastLease

vars == <<phase, revision, lease, quality, guidance, ui, changeKind,
          repairAttempts, repairRequired, checkpoint, terminalCommit,
          lastOperation, lastAuthority, lastJob, lastRevision, lastLease>>

\* Concurrent safety runs do not need the transient audit projection to
\* distinguish lifecycle states.  The audit fields remain in the full model
\* and are checked by AuthorityOwnership/LeaseAndRevisionFence.
StateView == <<phase, revision, lease, quality, guidance, ui, changeKind,
               repairAttempts, repairRequired, checkpoint, terminalCommit>>


Stable == UNCHANGED <<phase, revision, lease, quality, guidance, ui, changeKind,
          repairAttempts, repairRequired, checkpoint, terminalCommit>>

StableNoPhase == UNCHANGED <<revision, lease, quality, guidance, ui, changeKind,
          repairAttempts, repairRequired, checkpoint, terminalCommit>>

Record(op, authority, job) ==
  /\ lastOperation' = op
  /\ lastAuthority' = authority
  /\ lastJob' = job
  /\ lastRevision' = revision[job]
  /\ lastLease' = lease[job]

AuthorityOf(op) ==
  IF op \in {"admit", "lease", "recover", "commit"} THEN "awc"
  ELSE IF op \in {"dispatch", "start", "evidence", "checkpoint", "crash",
                   "continue", "failure", "retry", "alternative", "repair",
                   "repair_escalate", "block", "request_completion",
                   "stale_rejected", "replay_rejected", "ambiguous_rejected"} THEN "awr"
  ELSE IF op = "quality_accept" THEN "awq"
  ELSE IF op = "guidance" THEN "awg"
  ELSE IF op = "ui_decide" THEN "ui"
  ELSE ""

Init ==
  /\ phase = [j \in Jobs |-> "new"]
  /\ revision = [j \in Jobs |-> 1]
  /\ lease = [j \in Jobs |-> ""]
  /\ quality = [j \in Jobs |-> "not_decided"]
  /\ guidance = [j \in Jobs |-> "not_required"]
  /\ ui = [j \in Jobs |-> "not_required"]
  /\ changeKind = [j \in Jobs |-> "none"]
  /\ repairAttempts = [j \in Jobs |-> 0]
  /\ repairRequired = [j \in Jobs |-> FALSE]
  /\ checkpoint = [j \in Jobs |-> FALSE]
  /\ terminalCommit = [j \in Jobs |-> FALSE]
  /\ lastOperation = ""
  /\ lastAuthority = ""
  /\ lastJob = ""
  /\ lastRevision = 0
  /\ lastLease = ""

Admit(j) ==
  /\ phase[j] = "new"
  /\ phase' = [phase EXCEPT ![j] = "admitted"]
  /\ StableNoPhase
  /\ Record("admit", "awc", j)

Lease(j) ==
  /\ phase[j] = "admitted"
  /\ lease[j] = ""
  /\ phase' = [phase EXCEPT ![j] = "leased"]
  /\ lease' = [lease EXCEPT ![j] = "LSE"]
  /\ UNCHANGED <<revision, quality, guidance, ui, changeKind,
                 repairAttempts, repairRequired, checkpoint, terminalCommit>>
  /\ Record("lease", "awc", j)

Dispatch(j) ==
  /\ phase[j] = "leased" /\ lease[j] # ""
  /\ phase' = [phase EXCEPT ![j] = "dispatched"]
  /\ StableNoPhase
  /\ Record("dispatch", "awr", j)

Start(j) ==
  /\ phase[j] = "dispatched" /\ lease[j] # ""
  /\ phase' = [phase EXCEPT ![j] = "executing"]
  /\ StableNoPhase
  /\ Record("start", "awr", j)

Evidence(j) ==
  /\ phase[j] = "executing" /\ lease[j] # ""
  /\ phase' = [phase EXCEPT ![j] = "quality_pending"]
  /\ StableNoPhase
  /\ Record("evidence", "awr", j)

QualityAccept(j) ==
  /\ phase[j] = "quality_pending"
  /\ quality' = [quality EXCEPT ![j] = "accepted"]
  /\ phase' = [phase EXCEPT ![j] = "quality_accepted"]
  /\ UNCHANGED <<revision, lease, guidance, ui, changeKind,
                 repairAttempts, repairRequired, checkpoint, terminalCommit>>
  /\ Record("quality_accept", "awq", j)

Alternative(j, kind) ==
  /\ phase[j] = "quality_accepted"
  /\ changeKind[j] = "none"
  /\ kind \in ChangeKinds \ {"none"}
  /\ changeKind' = [changeKind EXCEPT ![j] = kind]
  /\ guidance' = [guidance EXCEPT ![j] = "pending"]
  /\ phase' = [phase EXCEPT ![j] = "oracle_pending"]
  /\ UNCHANGED <<revision, lease, quality, ui, repairAttempts,
                 repairRequired, checkpoint, terminalCommit>>
  /\ Record("alternative", "awr", j)

RepairEscalate(j) ==
  /\ phase[j] = "executing"
  /\ changeKind[j] = "none"
  /\ repairAttempts[j] = MaxRepairs
  /\ MaxRepairs > 0
  /\ repairRequired' = [repairRequired EXCEPT ![j] = TRUE]
  /\ changeKind' = [changeKind EXCEPT ![j] = "repair_escalation"]
  /\ guidance' = [guidance EXCEPT ![j] = "pending"]
  /\ phase' = [phase EXCEPT ![j] = "repair_pending"]
  /\ UNCHANGED <<revision, lease, quality, ui, repairAttempts,
                 checkpoint, terminalCommit>>
  /\ Record("repair_escalate", "awr", j)

RepairAttempt(j) ==
  /\ phase[j] = "executing"
  /\ repairAttempts[j] < MaxRepairs
  /\ repairAttempts' = [repairAttempts EXCEPT ![j] = @ + 1]
  /\ UNCHANGED <<phase, revision, lease, quality, guidance, ui, changeKind,
                 repairRequired, checkpoint, terminalCommit>>
  /\ Record("repair", "awr", j)

Guidance(j) ==
  /\ phase[j] \in {"oracle_pending", "repair_pending"}
  /\ IF changeKind[j] \in {"refinement", "test_change", "specification_change", "repair_escalation"}
        THEN /\ guidance' = [guidance EXCEPT ![j] = "requires_ui"]
             /\ phase' = [phase EXCEPT ![j] = "ui_pending"]
        ELSE /\ guidance' = [guidance EXCEPT ![j] = "approved"]
             /\ phase' = [phase EXCEPT ![j] = "quality_accepted"]
  /\ UNCHANGED <<revision, lease, quality, ui, changeKind,
                 repairAttempts, repairRequired, checkpoint, terminalCommit>>
  /\ Record("guidance", "awg", j)

UIDecide(j, outcome) ==
  /\ phase[j] = "ui_pending"
  /\ outcome \in {"approved", "rejected", "ambiguous", "expired"}
  /\ ui' = [ui EXCEPT ![j] = outcome]
  /\ IF outcome = "approved"
        THEN /\ phase' = [phase EXCEPT ![j] = IF repairRequired[j] THEN "executing" ELSE "quality_accepted"]
             /\ guidance' = [guidance EXCEPT ![j] = "approved"]
             /\ repairRequired' = [repairRequired EXCEPT ![j] = FALSE]
        ELSE /\ phase' = [phase EXCEPT ![j] = "blocked"]
             /\ guidance' = [guidance EXCEPT ![j] = "rejected"]
             /\ UNCHANGED <<repairRequired, changeKind>>
  /\ UNCHANGED <<revision, lease, quality, changeKind, repairAttempts,
                 checkpoint, terminalCommit>>
  /\ Record("ui_decide", "ui", j)

Continue(j) ==
  /\ phase[j] = "quality_accepted"
  /\ quality[j] = "accepted"
  /\ guidance[j] \in {"not_required", "approved"}
  /\ ui[j] # "pending"
  /\ ~checkpoint[j]
  /\ phase' = [phase EXCEPT ![j] = "executing"]
  /\ checkpoint' = [checkpoint EXCEPT ![j] = TRUE]
  /\ UNCHANGED <<revision, lease, quality, guidance, ui, changeKind,
                 repairAttempts, repairRequired, terminalCommit>>
  /\ Record("continue", "awr", j)

RequestCompletion(j) ==
  /\ phase[j] \in {"executing", "quality_accepted"}
  /\ quality[j] = "accepted"
  /\ guidance[j] \in {"not_required", "approved"}
  /\ ui[j] # "pending"
  /\ phase' = [phase EXCEPT ![j] = "completion_pending"]
  /\ StableNoPhase
  /\ Record("request_completion", "awr", j)

Commit(j) ==
  /\ phase[j] = "completion_pending"
  /\ quality[j] = "accepted"
  /\ guidance[j] \in {"not_required", "approved"}
  /\ ui[j] # "pending"
  /\ terminalCommit' = [terminalCommit EXCEPT ![j] = TRUE]
  /\ phase' = [phase EXCEPT ![j] = "completed"]
  /\ UNCHANGED <<revision, lease, quality, guidance, ui, changeKind,
                 repairAttempts, repairRequired, checkpoint>>
  /\ Record("commit", "awc", j)

Checkpoint(j) ==
  /\ phase[j] = "executing"
  /\ ~checkpoint[j]
  /\ checkpoint' = [checkpoint EXCEPT ![j] = TRUE]
  /\ UNCHANGED <<phase, revision, lease, quality, guidance, ui, changeKind,
                 repairAttempts, repairRequired, terminalCommit>>
  /\ Record("checkpoint", "awr", j)

Crash(j) ==
  /\ phase[j] = "executing" /\ checkpoint[j]
  /\ phase' = [phase EXCEPT ![j] = "recovering"]
  /\ StableNoPhase
  /\ Record("crash", "awr", j)

Recover(j) ==
  /\ phase[j] = "recovering" /\ checkpoint[j]
  /\ revision' = [revision EXCEPT ![j] = @ + 1]
  /\ lease' = [lease EXCEPT ![j] = "REC"]
  /\ phase' = [phase EXCEPT ![j] = "leased"]
  /\ UNCHANGED <<quality, guidance, ui, changeKind, repairAttempts,
                 repairRequired, checkpoint, terminalCommit>>
  /\ Record("recover", "awc", j)

Blocked(j) ==
  /\ phase[j] \in {"quality_pending", "oracle_pending", "repair_pending", "ui_pending"}
  /\ phase' = [phase EXCEPT ![j] = "blocked"]
  /\ StableNoPhase
  /\ Record("block", "awr", j)

\* Hostile observations are explicit transitions, but they leave all
\* lifecycle state unchanged and therefore cannot become approval.
RejectStale(j) ==
  /\ phase[j] \notin {"completed", "blocked"}
  /\ Stable
  /\ Record("stale_rejected", "awr", j)

RejectReplay(j) ==
  /\ phase[j] \notin {"completed", "blocked"}
  /\ Stable
  /\ Record("replay_rejected", "awr", j)

RejectAmbiguous(j) ==
  /\ phase[j] \notin {"completed", "blocked"}
  /\ Stable
  /\ Record("ambiguous_rejected", "awr", j)

NextFor(j) ==
  \/ Admit(j) \/ Lease(j) \/ Dispatch(j) \/ Start(j) \/ Evidence(j)
  \/ QualityAccept(j) \/ Alternative(j, "ordinary_alternative")
  \/ Alternative(j, "refinement") \/ Alternative(j, "test_change")
  \/ Alternative(j, "specification_change") \/ RepairAttempt(j)
  \/ RepairEscalate(j) \/ Guidance(j)
  \/ UIDecide(j, "approved") \/ UIDecide(j, "rejected")
  \/ UIDecide(j, "ambiguous") \/ UIDecide(j, "expired")
  \/ Continue(j) \/ RequestCompletion(j) \/ Commit(j)
  \/ Checkpoint(j) \/ Crash(j) \/ Recover(j) \/ Blocked(j)
  \/ RejectStale(j) \/ RejectReplay(j) \/ RejectAmbiguous(j)

ProgressFor(j) ==
  /\ NextFor(j)
  /\ lastOperation' \notin {"stale_rejected", "replay_rejected", "ambiguous_rejected"}

Next == (\E j \in Jobs : NextFor(j)) \/ UNCHANGED vars

Spec == Init /\ [][Next]_vars

FairSpec == Init /\ [][Next]_vars /\ \A j \in Jobs : WF_vars(ProgressFor(j))

TypeOK ==
  /\ phase \in [Jobs -> Phases]
  /\ revision \in [Jobs -> Nat]
  /\ lease \in [Jobs -> STRING]
  /\ quality \in [Jobs -> QualityStates]
  /\ guidance \in [Jobs -> GuidanceStates]
  /\ ui \in [Jobs -> UIStates]
  /\ changeKind \in [Jobs -> ChangeKinds]
  /\ repairAttempts \in [Jobs -> Nat]
  /\ repairRequired \in [Jobs -> BOOLEAN]
  /\ checkpoint \in [Jobs -> BOOLEAN]
  /\ terminalCommit \in [Jobs -> BOOLEAN]
  /\ lastOperation \in STRING
  /\ lastAuthority \in Authorities
  /\ lastJob \in (Jobs \cup {""})
  /\ lastRevision \in Nat
  /\ lastLease \in STRING

AuthorityOwnership ==
  /\ lastAuthority = AuthorityOf(lastOperation)
  /\ (lastOperation = "guidance" => lastAuthority = "awg")
  /\ (lastOperation = "ui_decide" => lastAuthority = "ui")
  /\ (lastOperation \in {"admit", "lease", "recover", "commit"} => lastAuthority = "awc")
  /\ (lastOperation \in {"dispatch", "start", "evidence", "continue", "alternative",
                            "repair_escalate", "request_completion", "checkpoint", "crash"}
      => lastAuthority = "awr")

LeaseAndRevisionFence ==
  /\ \A j \in Jobs : revision[j] >= 1
  /\ \A j \in Jobs : phase[j] \in {"leased", "dispatched", "executing",
      "quality_pending", "quality_accepted", "oracle_pending", "repair_pending",
      "ui_pending", "completion_pending", "recovering", "completed"} => lease[j] # ""
  /\ lastOperation \in {"dispatch", "start", "evidence", "continue", "alternative",
      "repair_escalate", "request_completion", "checkpoint", "crash"} => lastLease # ""

QualityGate ==
  /\ \A j \in Jobs : phase[j] \in {"quality_accepted", "oracle_pending",
      "completion_pending", "completed"} => quality[j] = "accepted"
  /\ \A j \in Jobs : phase[j] = "ui_pending" /\ ~repairRequired[j]
      => quality[j] = "accepted"
  /\ \A j \in Jobs : phase[j] \in {"completion_pending", "completed"}
      => guidance[j] \in {"not_required", "approved"} /\ ui[j] # "pending"

MandatoryChangeControl ==
  /\ \A j \in Jobs : changeKind[j] \in {"refinement", "test_change", "specification_change"}
      => phase[j] \in {"oracle_pending", "ui_pending", "quality_pending", "quality_accepted",
                         "leased", "dispatched", "executing", "recovering",
                         "completion_pending", "completed", "blocked"}
  /\ \A j \in Jobs : changeKind[j] \in {"refinement", "test_change", "specification_change"}
      /\ phase[j] \in {"quality_accepted", "completion_pending", "completed"}
      => guidance[j] = "approved" /\ ui[j] = "approved"

RepairEscalationSafety ==
  /\ \A j \in Jobs : repairRequired[j] =>
      phase[j] \in {"repair_pending", "ui_pending", "blocked", "executing"}
  /\ \A j \in Jobs : repairRequired[j] /\ phase[j] = "executing" => ui[j] = "approved"
  /\ \A j \in Jobs : repairAttempts[j] <= MaxRepairs

TerminalCommitSafety ==
  /\ \A j \in Jobs : phase[j] = "completed" => terminalCommit[j]
  /\ \A j \in Jobs : terminalCommit[j] => phase[j] = "completed"

NoAmbiguousApproval ==
  /\ \A j \in Jobs : ui[j] \in {"ambiguous", "expired", "rejected"}
      => phase[j] = "blocked"

Safety == TypeOK /\ AuthorityOwnership /\ LeaseAndRevisionFence
         /\ QualityGate /\ MandatoryChangeControl /\ RepairEscalationSafety
         /\ TerminalCommitSafety /\ NoAmbiguousApproval

TerminalOrBlocked == \A j \in Jobs : phase[j] \in {"completed", "blocked"}

\* The two-job safety configuration deliberately bounds the cross-product to
\* the shared admission/lease/dispatch/evidence path.  The one-job fairness
\* configuration checks every later authority branch without this reduction.
ConcurrentSafetyBound ==
  \A j \in Jobs :
    /\ phase[j] \in {"new", "admitted", "leased", "dispatched", "executing",
                     "quality_pending", "quality_accepted"}
    /\ changeKind[j] = "none"
    /\ repairAttempts[j] = 0
    /\ ~checkpoint[j]
    /\ ~repairRequired[j]

NormalProgressBound ==
  \A j \in Jobs :
    /\ phase[j] \in {"new", "admitted", "leased", "dispatched", "executing",
                     "quality_pending", "quality_accepted", "completion_pending",
                     "completed", "blocked"}
    /\ changeKind[j] = "none"
    /\ repairAttempts[j] = 0
    /\ ~checkpoint[j]
    /\ ~repairRequired[j]

ChangeControlBound ==
  \A j \in Jobs :
    /\ phase[j] \in {"new", "admitted", "leased", "dispatched", "executing",
                     "quality_pending", "quality_accepted", "oracle_pending",
                     "ui_pending", "completion_pending", "completed", "blocked"}
    /\ changeKind[j] \in {"none", "refinement", "test_change", "specification_change"}
    /\ repairAttempts[j] = 0
    /\ ~repairRequired[j]

RepairEscalationBound ==
  \A j \in Jobs :
    /\ phase[j] \in {"new", "admitted", "leased", "dispatched", "executing",
                     "quality_pending", "quality_accepted", "repair_pending",
                     "ui_pending", "completion_pending", "completed", "blocked"}
    /\ changeKind[j] \in {"none", "repair_escalation"}
    /\ repairAttempts[j] <= MaxRepairs

BoundedTerminality == []<>(TerminalOrBlocked)

THEOREM Spec => []Safety
THEOREM FairSpec => []Safety

=============================================================================================
