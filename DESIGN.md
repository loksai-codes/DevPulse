# DevPulse Visual System & Design Architecture: "The Triage Ward"

Clinical triage system for autonomous incident response and human-in-the-loop governance. Every incident is treated as an admitted patient; the engineer is the attending physician.

---

## 1. Design Plan & Architectural Wireframes

### Ward Board (Overview Screen)
```
+---------------------------------------------------------------------------------------------------------------------------------------------+
|  [+] DEVPULSE :: TRIAGE WARD                          [+ Ingest Alert]   [Mode: Mock | Live]   [Night Shift]   [Ward | Records | Strip]    |
|  Attending: Dr. Sarah Lin (Maintainer #04)  |  Origin: Switch Console (#incident-response)  |  Beds: 4 Active  |  Integrity: SHA-256 Chain |
+---------------------------------------------------------------------------------------------------------------------------------------------+
|  Filter: [ All (4) ]  [ Needs Approval (2) ]  [ Running Sandbox (1) ]  [ Resolved (1) ]        | Culprit search: [________________]        |
+---------------------------------------------------------------------------------------------------------------------------------------------+
|                                                                                                                                             |
|  BED 01 - CRITICAL                      BED 02 - NEEDS SIGN-OFF               BED 03 - ISOLATION CHAMBER            BED 04 - DISCHARGED     |
|  +-----------------------------------+  +-----------------------------------+  +----------------------------------+  +--------------------+ |
|  | WRISTBAND: INC-8402               |  | WRISTBAND: INC-8409               |  | WRISTBAND: INC-8395              |  | WRISTBAND: INC-8380| |
|  | auth/session-verifier.ts:142      |  | queue/worker-dispatcher.ts:88     |  | config/env-loader.ts:31          |  | db/pool-alloc.ts:74| |
|  | specHash: 7f8c12...3a19           |  | specHash: e2b144...9044           |  | specHash: 41de99...8c02          |  | specHash: 9a20...  | |
|  +-----------------------------------+  +-----------------------------------+  +----------------------------------+  +--------------------+ |
|  | +-------------------------------+ |  | +-------------------------------+ |  | +------------------------------+ |  | +----------------+ | |
|  | | /\   /\        /\   ERRATIC   | |  | |       /\        /\   AMBER     | |  | | RUNNING: pytest -q ...       | |  | |                | | |
|  | |/  \_/  \__/\__/  \  WAVEFORM  | |  | | _/\__/  \__/\__/  \  PULSE     | |  | | [PASS] test_missing_env_key | |  | | —————— STEADY — | | |
|  | | (Live Canvas ECG)             | |  | | (Challenge TTL: 04:12)         | |  | | Exit: 0 | 1280ms            | |  | | (Archived)     | | |
|  | +-------------------------------+ |  | +-------------------------------+ |  | +------------------------------+ |  | +----------------+ | |
|  | Diagnosis: Auth null deref        |  | Diagnosis: Spin loop on empty q   |  | Diagnosis: Missing required key  |  | Discharged: 13:40  | |
|  | Challenge: appr_098f (03:28)      |  | Challenge: appr_44a1 (04:12)      |  | Stage: 8. Execute                |  | Stamp: VERIFIED    | |
|  | [Open patient chart ->]           |  | [Open patient chart ->]           |  | [Open patient chart ->]          |  | [Review case ->]   | |
|  +-----------------------------------+  +-----------------------------------+  +----------------------------------+  +--------------------+ |
+---------------------------------------------------------------------------------------------------------------------------------------------+
```

### Patient Chart (Detail Screen)
```
+---------------------------------------------------------------------------------------------------------------------------------------------+
|  <- Back to Ward Board              PATIENT CHART: INC-8402 / Auth Session Null Dereference              Severity: Critical                 |
|  9-STAGE VITALS: 1.Detect -> 2.Investigate -> 3.Recall -> 4.Synthesize -> [5.CHALLENGE (ACTIVE)] -> 6.Authorize -> 7.Consume -> 8.Execute -> 9.Remember
+---------------------------------------------------------------------------------------------------------------------------------------------+
|  CHART NOTES (Physical Clipboard)       | PRESCRIPTION (Proposed Diff Reader)        | ISOLATION CHAMBER (Sandbox & Key-Turn)               |
|  +------------------------------------+ | +----------------------------------------+ | +--------------------------------------------------+ |
|  | [STEEL CLIP]                       | | | PRESCRIPTION ORDER                     | | | HARDWARE LAMPS:                                  | |
|  | Admitted: 2026-11-05T14:18:22Z     | | | Target: auth/session-verifier.ts       | | | [x] --network none  [x] read-only  [x] non-root | |
|  | Error: TypeError: Cannot read      | | | specHash: 7f8c12e5...3a19              | | +--------------------------------------------------+ |
|  | property 'sub' of null             | | +----------------------------------------+ | | RECESSED MONITOR (Phosphor #2BE59A)              | |
|  |                                    | | | @@ -140,6 +140,9 @@                    | | | > sandbox-runner --isolate                       | |
|  | ATTENDING DIAGNOSIS:               | | |    const decoded = parseJwt(token);    | | | > apply patch 7f8c12e5                           | |
|  | Expired JWT causes null session    | | | -  return decoded.sub;                 | | | > run test-suite tests/auth.test.ts              | |
|  | payload without explicit guard.    | | | +  if (!decoded || !decoded.sub) {     | | | [PASS] handles_null_session_payload              | |
|  |                                    | | | +    throw new AuthError('EXPIRED');   | | | Status: Ready for execution                      | |
|  | STAPLED PRIOR CASE (Violet stamp): | | | +  }                                   | | +--------------------------------------------------+ |
|  | +--------------------------------+ | | | +  return decoded.sub;                 | |                                                      |
|  | | CASE #INC-7210 (94% MATCH)     | | |                                          | | TWO-KEY APPROVAL CONTROLLER:                         |
|  | | Stapled note: Session guard    | | | [ READ TRACKING: 100% SCROLLED ]         | | +--------------------------------------------------+ |
|  | | check validated by @alin       | | | (Key unlocks only after full diff read)  | | | Challenge: appr_8402 | 5:00 Physical Gauge       | |
|  | | [VERIFIED CASE FILE STAMP]     | | +----------------------------------------+ | | Bound specHash: 7f8c12e5                           | |
|  | +--------------------------------+ |                                              | | Maintainer: Dr. Sarah Lin (Allowlisted)            | |
|  | Prescribing Agent: Sentinel        |                                              | | Channel: Switch Room (Verified Origin)             | |
|  +------------------------------------+                                              | |                                                    |
|                                                                                      | |      (( HOLD TO TURN KEY: 1.2s ))                  |
|                                                                                      | |      [Circular mechanical lock + gauge]            |
|                                                                                      | |      Keyboard: Hold Space/Enter | Touch: Hold       |
|                                                                                      | +--------------------------------------------------+ |
|                                                                                      | SECURITY REJECTION TESTS (Interactive):             |
|                                                                                      | [Test Non-Allowlist]   [Test Bridged-Slack Origin]   |
|                                                                                      | [Test Replay Attack]   [Test Diff Hash Mismatch]    |
+---------------------------------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Design Tokens

### Color Palette

| Token | Daylight (Paper) | Night Shift | Purpose |
|---|---|---|---|
| `--surface-paper` | `#E8ECE2` (warm pale-sage) | `#15201A` (dim olive paper) | Main triage board & clipboard surface |
| `--surface-paper-card` | `#F2F5ED` | `#1B2922` | Patient charts, prescription sheets |
| `--surface-monitor-bezel`| `#0B120E` | `#070C09` | Heavy hardware bezel around screens |
| `--surface-monitor-screen`| `#040806` | `#020504` | Recessed CRT monitor interior |
| `--ink-primary` | `#14201A` | `#D8E2DA` | Crisp clinical black typography |
| `--ink-secondary` | `#4E5F55` | `#8CA093` | Meta info, labels, secondary diagnosis |
| `--ink-tertiary` | `#7D8F83` | `#586B60` | Line numbers, hash delimiters |
| `--grid-line-fine` | `rgba(20, 32, 26, 0.06)` | `rgba(216, 226, 218, 0.05)` | 8px millimeter ECG grid lines |
| `--grid-line-bold` | `rgba(20, 32, 26, 0.15)` | `rgba(216, 226, 218, 0.12)` | 40px major millimeter ECG grid lines |
| `--phosphor` | `#2BE59A` | `#2BE59A` | Sandbox terminal phosphor (strictly contained within bezel) |
| `--phosphor-dim` | `rgba(43, 229, 154, 0.2)` | `rgba(43, 229, 154, 0.2)` | Phosphor glow interior / inactive lamps |
| `--alarm-red` | `#E5352B` | `#F0453B` | Expired challenge, tamper alert, intruder bridge |
| `--alarm-red-soft` | `rgba(229, 53, 43, 0.12)`| `rgba(240, 69, 59, 0.2)` | Red alert banner strip |
| `--amber-pending` | `#F2A100` | `#F5AC18` | Challenge countdown, awaiting signature |
| `--memory-violet` | `#6B4EE6` | `#866DF0` | Precedent memory cards, verified stamps |
| `--brass-metal` | `#B8860B` | `#996F08` | Physical two-key lock barrel and mechanical ring |

### Typography Scale

- **Display & Headings**: `Instrument Serif`, `Georgia`, serif.
  - Ward Title: `28px`, `line-height: 1.1`, `letter-spacing: -0.02em`
  - Bed & Patient Names: `20px`, `line-height: 1.2`, `letter-spacing: -0.01em`
  - Clipboard Header: `18px`, `font-style: italic`
- **Body & Clinical Notes**: `Inter Tight`, system-ui, sans-serif.
  - Body Normal: `13px / 1.4`
  - Notes & Clinical Summaries: `12px / 1.45`
  - Microcopy / Labels: `11px / 1.3`, sentence case only.
- **Data, Hashes & Code**: `IBM Plex Mono`, monospace.
  - specHash & Hashes: `11px`, `letter-spacing: -0.03em`
  - Code & Diffs: `12px`, `line-height: 1.5`
  - Timers & Sequences: `13px`, tabular figures (`font-variant-numeric: tabular-nums`)

### Border Radii & Depth
- **Paper Cards**: `2px` (nearly crisp paper corner, never pill-shaped).
- **Recessed Monitors**: `14px` (industrial curved monitor bezel).
- **Keys & Dials**: `50%` (fully circular mechanical turning keys).
- **Paper Shadow**: `0 1px 1px rgba(0,0,0,0.06), 0 3px 8px -2px rgba(20,32,26,0.12)`
- **Recessed Bezel Shadow**: `inset 0 3px 6px rgba(0,0,0,0.8), inset 0 0 1px rgba(255,255,255,0.08)`

---

## 3. Component Hierarchy

1. **`App`**: Layout shell, navigation tabs (Ward Board, Records Room, Audit Strip), Theme toggle (Daylight/Night Shift), Mode toggle (Mock/Live), Ingest Alert drawer trigger.
2. **`WardBoard`**: The main triage ward containing horizontal rows of beds with live ECG canvases, status filter bar, and search.
3. **`Bed`**: Single patient bed with patient wristband, live Canvas ECG waveform, diagnosis, specHash, countdown timer, and quick admission status.
4. **`PatientChart`**: 3-column physical clipboard layout:
   - Left: Chart notes with stapled prior case card (`INC-7210`, 94% similarity).
   - Center: `PatchSheet` (prescribed diff reader with unified syntax tint and 100% scroll read gate).
   - Right: `IsolationChamber` (recessed CRT monitor with `--network none`, `read-only`, `non-root` lamps) + `TwoKeyApproval` physical turn control.
5. **`TwoKeyApproval`**: Physical mechanical key slot with 1.2s press-and-hold radial fill, haptic scale animation, 5:00 countdown drain, security rejection triggers, and intruder warning alarm.
6. **`IsolationChamber`**: Glass sandbox unit streaming real-time stdout/stderr lines, exit code, and test evidence summary.
7. **`MemoryRoom`**: Physical filing drawer with manila folder index tabs, search engine with keyword highlighting, similarity scoring, and automatic filing animation.
8. **`AuditStrip`**: Continuous scrolling ECG paper strip chart displaying sequence ticks, cryptographic hash links, interactive Web Crypto SHA-256 chain sweep verification, and paper-tear tamper demonstration.
9. **`IngestDrawer`**: Slide-out clinical admission form to paste stack traces, view Sentinel parser diagnostics, and admit new patient beds.

---

## 4. Motion & State Communication Rules

- **Waveform Canvas**: 60fps canvas draw of authentic ECG complexes (P wave, QRS complex, T wave). Erratic tachycardia for critical incidents, calm sinus rhythm for resolved, and flatline `#E5352B` on challenge expiry.
- **Two-Key Turn**: Smooth 1.2-second SVG radial fill gauge. Spring release on mouse-up/key-up before 1.2s cancels with tactile feedback. Success transitions smoothly into runner execution.
- **Diff Read Gating**: Scroll observer tracks percentage read; unlocks the key slot only when 100% of the diff lines have been visible.
- **Tamper Paper Tear**: Jagged SVG clip-path visually separates the audit strip at the tampered sequence; subsequent ticks turn alarm red.
- **Chain Verification Sweep**: Phosphor green laser line sweeps from sequence 0 to end, computing client-side SHA-256 over `prevHash + seq + event + detail`.
- **Prefers-Reduced-Motion**: Animations smoothly downgrade to instantaneous state transitions while preserving all functional indicators.

