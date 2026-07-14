# Conformance capability loop — playbook

GOAL: live-verify (CONF_LIVE+) **every** in-scope function in
conformance/profiler/triage_backlog.json (2423 fns) — NOT just the easy
classes. Hard functions are never filtered out; they are BUCKETED by blocked
reason, and the loop's improvement step exists to UNLOCK those buckets.
Failures are the work queue. Coverage of the whole pool is the metric.

State: `loop_state.json` (same dir). One iteration per wakeup.

## Iteration procedure

1. **Batch health** (state.phase == "proving"):
   - Oracle dead (`:8790` refused)? Kill hung `loop_batch` procs; relaunch game
     (elevated launcher per CONFORMANCE_WORKFLOW.md — UAC prompt; if the bridge
     isn't up in ~2 min, PushNotification the user and just re-arm the wakeup).
     Then d2dbg_reload_provider + d2dbg_set_all_modes shadow.
     **BOOT READINESS (revised 2026-07-13 after live diagnosis): the status
     flags `charSelectReady`/`charListLoaded` are UNRELIABLE -- they stayed
     False even with the char-select screen fully up and 64 chars loadable.
     The RELIABLE readiness signal is `d2dbg_list_characters` returning
     count>0. So: after bridge+provider up, POLL d2dbg_list_characters every
     ~6s (ignore the status flags); once it returns count>0, call
     d2dbg_load_character. Do NOT gate on charSelectReady. main_menu_
     singleplayer SEH-faults through the boot window AND from char-select
     (already past title) -- rely on the auto-advance to char-select and just
     poll list_characters. Relaunch can hit a transient 'Diablo II Error'
     startup dialog (lingering lock from the crashed instance): dismiss via
     Win32 EnumWindows+WM_CLOSE, then relaunch once more (it comes up clean).**
   - Batch running + oracle alive? Re-arm fallback wakeup, end turn.
   - Batch finished? → 2.
2. **Analyze** (ground truth = fun-doc/logs/runs.jsonl + proven_functions.jsonl
   matched by ADDRESS — name-audit renames fns):
   - Tally terminal outcomes; update state.buckets — every non-proven fn goes
     into a bucket keyed by blocked reason (stateful_reason code, abort-defer,
     marshal_fault, weak_proof, malformed, library-leak, ...).
   - Append iteration summary to state.journal.
3. **Improve — ONE capability increment per iteration**, targeting the LARGEST
   cumulative bucket (or the highest-leverage known TODO). Validate offline
   (py_compile + targeted unit check) before the next batch. Never loosen proof
   standards. Capability backlog (grows from bucket data):
   - stateful sub-classes (biggest): unit-gated global-table getters need a
     shadow-first prove leg; delegates need the call-through lane to actually
     fire; multi-pointer params need handle+scalar mixed marshalling
   - abort-class handle-getters: clamped case-value scalar sweep on the handle
     path (case extractor exists in abi_static — thread it through)
   - marshal_fault unbounded getters: retry once with vectors clamped 0..16
   - void/out-param writers: Class B out-param modeling (spec translator + shadow gen)
   - register-explicit beyond Class D v1
   - malformed_response: provider parse robustness / corrective retry
   - library leakage in in_scope: report to triage (user owns scope step)
4. **Retry queue**: after a capability lands, move that bucket's fns into the
   NEXT batch (they take priority over fresh cursor fns).
5. **Build next batch**: batch_builder.py --count 15 — retry-queue fns first,
   then next fns from the cursor, NO class filtering. Only hard skips: already
   CONF_LIVE+, and _looks_like_library_or_runtime names (recorded to the
   'library' bucket as triage feedback, not attempted).
6. **Launch** loop_batch.py in background (FUNDOC_ADVERSARIAL_VET=0 until the
   marshal_fault clamp-retry capability lands), state.phase="proving".
7. **Re-arm**: ScheduleWakeup fallback 1800s, same /loop prompt verbatim. The
   batch's background-task notification is the primary wake signal.

## Reporting & hygiene
- Every ~3 iterations: coverage % (CONF_LIVE+ / 2423), bucket burn-down, lessons
  → distill to memory (batch-pipeline-improvements-jul12.md successor) and give
  the user a compact summary.
- Code fixes stay uncommitted unless the user says commit.
- Stop conditions: user says stop; or pool exhausted AND all buckets empty or
  explicitly parked (then ScheduleWakeup stop:true + final report).
