# Measurement methodology

*Transferable lessons from Mirage's measurement work. Written because the same
failure shapes recurred across unrelated subsystems, and naming them is cheaper
than rediscovering them.*

Every entry here is a defect that actually shipped or actually produced a wrong
number in this repository. None is hypothetical.

---

## 1. A self-consistent test cannot detect that the reasoning is wrong

**The general statement.** If a test's expected value is derived from the same
reasoning that produced the code, the test can only detect drift *from* that
reasoning — never that the reasoning was wrong to begin with. It will pass
forever while the code is wrong in exactly the way both were wrong.

This applies to every "golden output" test in every codebase: pinned hashes,
recorded fixtures, snapshot tests, expected-value constants. The question to ask
of each is **"where did the expected value come from, and could it be wrong in the
same direction as the code?"**

Three instances here:

- **Mirage against Mirage.** Traffic-analysis experiments compared a Mirage flow
  to another Mirage flow. Any defect shared by both arms was structurally
  invisible — the comparison could not see it, by construction.
- **The negative test of the negative test.** A parser guard was tested with
  input that did not exercise the guard's failure mode, so it passed against the
  defect it was written to catch.
- **The pinned JA3 string.** `FIREFOX_DESKTOP`'s expected fingerprint was
  transcribed from the same understanding that built the template. Both were a
  strict subset of real Firefox — 12 of 17 extensions, one cipher short, three
  groups short — and the test passed. Only a packet capture of the real browser
  could reveal it, and when one was taken the generator was corrected to match
  field for field.

**The fix is not more care.** It is to source the expected value from somewhere
the implementation cannot reach: a capture, a reference implementation, a
different tool, a real peer. If that is impossible, say so at the test rather than
letting a green check imply a validation that did not happen.

---

## 2. Knowing the rule does not prevent the reach

A warning in a document is not a control.

A video capture that seeked every 8 s produced 8 long gaps in 75 s, one per seek.
It was caught by a control, documented in `cover-scheduling.md`, and a warning was
written: *"any capture that drives a player needs the equivalent."*

Months later a browse capture navigated every ~18 s and produced a 12974 ms worst
gap — the same defect, in the same file, by the same author who wrote the warning.

**The fix is an affordance, not a reminder.** `tools/cover-sources/hls/check_driver_artifact.py`
now refuses a trace whose driver acts periodically, and refuses a trace that spans
less than half its capture window. The operator no longer has to remember.

### Prohibit rather than detect

The first version of that guard tried to *detect* contamination: flag any gap
within 20% of the driver's declared interval. **It passed both known-bad
captures.** The driver acted every 18 s but its idle was 12.97 s — interval minus
page-load time — so nothing matched.

Recognising the artifact required modelling exactly the thing that had not been
modelled. And it is not separable in general: segmented video shows regularly
spaced ~10 s gaps that are the genuine class structure, while a timed browse shows
regularly spaced gaps that are the instrument. **Spacing alone cannot tell them
apart** — only the driver knows, so the driver must declare and the harness must
refuse.

---

## 3. The instrument is part of the measurement

`browser_capture.py` wrote a connection's trace only when that connection
*closed*. Every long-lived connection was therefore silently absent. A 45 s video
session produced 47 connection files across 22 hosts and **not one was the video
stream**: short-lived background connections closed and were recorded; the single
long-lived connection carrying the payload vanished.

The output looked like success — a healthy directory full of traces, none of them
the traffic under study. It invalidated the entire four-class cover table, which
had been measured through it.

**Corollary: verify the instrument saw what the subject did.** A guard was already
in place asserting that the *page played video*. It passed. It said nothing about
whether the *tap recorded it*, and those are two separate claims. A verification
that checks the subject but not the instrument checks half the system.

---

## 3b. A value computed and not consumed

Four instances, four different mechanisms, one failure:

- `finalise_run()` was defined and never called, so a clock guard never ran once
- a ninth guard existed in a chain that could not reach it
- a resolved-config dump was written to disk and never read back
- the capture guard printed corrected burst figures and the table read the
  uncorrected summary line printed above them

In each the **correct value existed and did not reach the decision**. That is worse
than a missing value, because the output looks computed and is confidently wrong:
browse entered the cover table at 4967 ms when the guard, two lines lower in its
own output, said 95.6 ms.

**Why it is endemic here.** The Rust side is clean - `cargo build --workspace`
reports zero never-used/never-read warnings, because the compiler enforces it. All
four instances are in the Python and shell harnesses, where nothing does. The
measurement code has no compiler and is exactly where a wrong number does the most
damage, since it becomes a finding rather than a crash.

**Checks.** A scan for module-level Python functions defined and never referenced
across `tools/` and `scripts/` currently comes back clean (15 files). That catches
the `finalise_run` shape and not the others - a value that is printed but parsed
wrongly downstream is invisible to any such scan. The durable habit is narrower:
**when a computation produces a correction, check what consumes it**, not just that
it ran.

---

## 3c. Confirm the precondition held before reading the result

A green result from a test whose condition never existed is not evidence. Four
instances, four domains, same shape:

| domain | the result | the condition that never held |
|---|---|---|
| harness | a clean capture | a stale process still held the port; nothing was recorded |
| bridge config | a warning disappeared | the field was recognised but not applied |
| cover capture | `VERDICT:OK`, trace files present | the page played; the **tap** never recorded the stream |
| mutation testing | 212 tests green | the mutation **failed to compile**, and the restore had already run |

The last one is the sharpest because it inverts: the green reading was about to be
recorded as *"the test cannot detect this defect"*, which would have removed a
working assertion. A test that appears not to fire is as much a claim about the
condition as one that appears to pass.

**The rule:** before reading a result, confirm the thing being tested was actually
present — port free, config applied, capture recording, mutation compiled. In
every case above the check was one command and the wrong conclusion would have
survived for sessions.

### Mutation testing inverts the failure direction, so it needs a standing step

Everywhere else in this project a false green *shipped a bad result*. In mutation
testing a false green *deletes a working assertion* — the conclusion "the test
cannot catch X" removes a test that could. That asymmetry makes the fixture check
a required step rather than good practice:

> **Before trusting a mutation's verdict, confirm the mutated line executed.**

The fixture that exposed this had due order `[0,1,0,1,2,0,2]` — never two
consecutive records from one carrier — so a mutation coalescing consecutive
same-carrier records could not run. Not a bad fixture; an *incomplete* one. The fix
is both halves: a second fixture that can reach the path, and an assertion in the
test that it does. `has_adjacent_same_carrier()` in `pacer.rs` is that assertion —
it fails loudly if the fixture ever stops covering the mutated branch, so the
coverage claim cannot rot into a comment.

---

## 4. Decompose totals that agree suspiciously well

A bridge and the host it fronts both answered probes in 32.0 ms, and that was
recorded as "the splice pays the same round trip, so it is timing-indistinguishable."

Decomposed:

    cover host : connect 17.84 + post-connect 14.11 = 31.95 ms
    bridge     : connect  0.09 + post-connect 31.89 = 31.98 ms

The bridge's post-connect cost equalled the cover's *entire* cost to within
0.06 ms. The totals matched because the bridge's own connect was free on loopback
while it paid the cover's in full — **two errors of equal size cancelling.**

This is the third clean-looking null in this project that proved to be an
artifact, and the first found by decomposition rather than by a control arm. When
two totals agree better than the mechanism explains, split them into phases and
check that the phases agree too.

---

## 5. A correction can be invalid even when it removes something

Distance looked like an additive per-arm constant, so subtracting each arm's own
connect time should not have been able to *manufacture* a difference. Applied to
real data it flagged 14 of 17 probe classes at AUC = 1.000, every one an artifact.

A splice does not shift cost by a constant; it **relocates** cost from the connect
phase into the response phase. Subtracting per-arm connect removed 17.8 ms the
cover legitimately paid and 0.09 ms from a bridge that pays the same 17.8 ms later.

Related: the intuitive way to remove a distance confound is to substitute a local
stand-in server. That matches distance and **destroys server identity in the same
step** — separable classes went 8 → 13, with `fin` vs `rst` on four of them,
because the stand-in was a different program. At loopback resolution any two
distinct programs separate.

---

## 6. A fixed quantile assumes a unimodal distribution

`GAP_QUANTILE = 0.99` was derived to replace a fixed 0.5 s constant, and was right
to. It still cannot express segmented video, whose gap distribution is *bimodal* —
intra-burst near zero, inter-segment near 10 s — with the long gaps only 0.08% of
the sample. p99 lands inside the fast mode and reports 1.3 ms against a real 10 s
stall: a 7507x underestimate.

It survived because every class measured until then happened to be unimodal. **A
summary statistic encodes an assumption about distribution shape; when the
population widens, re-check the shape before re-using the summary.**

---

## 7. Pre-register, including the failure mode

Write the numeric criteria for each outcome *before* the run, and include what
result would mean the run itself was invalid.

This is what let a distance-matched capture be called invalid rather than reported
as a regression: the criterion "more separable classes than the baseline means the
stand-in is not a valid substitute" was on the record before the number was seen.
Without it, 13-versus-8 reads as a finding.

See `scripts/probe-suite/PREREGISTERED.md` for the format in use.

---

## 8. Warnings fire on absence, not on wrongness

`http_shadow_target` unset produced a warning naming a prober-exploitable
inconsistency. Set to a *plausible but wrong* value it produced a different
prober-exploitable inconsistency and **no warning at all**.

The same shape appeared in fingerprint provenance, where `checked_days` measured
the *age* of a template when what mattered was its *correctness*.

**A check that only fires on a missing value implies the present values are fine.**
If the field has a right answer, default to it; if it has wrong answers that look
right, check for those too.
