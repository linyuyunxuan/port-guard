=====================================================================
PortGuard v1.9.6 - Windows Server 2008 R2 QA HANDOFF
Read this file FIRST. All text here is plain ASCII.
=====================================================================

WHAT THIS PACKAGE IS
  A read-only evidence collector plus a 30-item human checklist.
  The scripts DO NOT create/delete firewall rules, DO NOT edit the
  database, DO NOT repack anything. They only write txt reports.

WHAT IS DELIBERATELY NOT IN THIS PACKAGE
  The three anchor values (EXPECTED_ZIP_SHA / EXPECTED_VERSION /
  EXPECTED_SUMS_ENTRIES) are NOT here. The publisher sends them to
  the verifier through an INDEPENDENT channel (the signed release
  announcement body / signature page). You type them BY HAND into
  verify_expect.txt from that channel.
  If these values ever arrive inside a package that also carries the
  release zip or its sidecar, A2 is false-green and the gate is void.

FOLDER LAYOUT ON THE 2008R2 CLEAN MACHINE
  C:\PG\
    PortGuard-v1.9.6.zip
    PortGuard-v1.9.6.zip.sha256
    PortGuard\                     <- extracted from the zip
    verify_2008r2.bat              <- from this package
    verify_2008r2.ps1              <- from this package
    verify_expect.txt              <- YOU create by hand, step 2
    00_READ_ME_FIRST.txt           <- from this package
    01_CHECKLIST_30.txt            <- from this package
    02_EVIDENCE_INDEX.TEMPLATE.txt <- from this package
  Only ONE PortGuard-v*.zip may exist in C:\PG\. More than one makes
  the collector hard-fail as ambiguous; use bat argument 4 to pass an
  explicit zip path if you must keep several.

STEP 0 - BEFORE ANY VERIFICATION
  Take a VM snapshot; record its name in the evidence index.
  Confirm the machine is clean: no Python, no venv, no source tree,
  no old PortGuard, no PortGuard_Block_* / PortGuard_Allow_* rules.

STEP 1 - WHERE THE ANCHOR COMES FROM
  The publisher must send the three values to the verifier BEFORE
  verification starts, through a channel independent of GitHub
  Release. Record on the signature page: sender, receiver, channel,
  timestamp, and where the delivery evidence is stored.
  The release announcement body is only an AFTER-THE-FACT copy.
  If the verifier can only get the values after the Release is
  public, that is the chicken-and-egg failure. STOP and escalate.

STEP 2 - CREATE verify_expect.txt BY HAND
  Copy verify_expect.TEMPLATE.txt to verify_expect.txt.
  Replace all three <FILL_...> placeholders with the values from
  STEP 1. Do NOT copy them from any package.
  Save as ANSI or UTF-8 WITHOUT BOM, CRLF line endings.
  NEVER use Notepad "Unicode" (UTF-16): keys get NUL bytes and A2
  hard-fails. A hard fail on a bad expect file is CORRECT behaviour
  (fail-closed). Fix the file encoding; do not blame the zip.

STEP 3 - RUN THE COLLECTOR
  Double-click verify_2008r2.bat (mode FULL, no other arguments).
  It writes verify_2008r2_report.txt next to itself.
  Verdicts: PASS / FAIL / NEEDS-VISUAL.
  NEEDS-VISUAL means a human must judge on the desktop. The script
  never signs the release and never replaces visual review.
  Other modes:
    verify_2008r2.bat SAVEBASE
      Run BEFORE E2 injection; writes pg_rules_baseline.txt.
    verify_2008r2.bat DIFF
      Run AFTER E2; compares rules with the saved baseline.
    verify_2008r2.bat FULL "D:\fwlogs\pfirewall.log" "1.2.3.4"
      Also checks F2 custom log path and D3 test-IP rule name.

STEP 4 - HUMAN ITEMS (the collector cannot do these)
  - Every [HUMAN] row in 01_CHECKLIST_30.txt.
  - A5 / C4 font fallback: visually compare the worst-case text
    columns at all three window+DPI combinations against the Win10
    baseline screenshots. A font file existing is NOT proof that
    the font family is usable by Qt.
  - B1 startup line: a line from a PREVIOUS run is NOT proof. Its
    timestamp must fall inside THIS operation window.
  - C1/C2/C3: write down HOW the sample rows were injected.
  - D4: wait at least one full expiry sweep; record actual wait.
  - E2: audit CSV exported from GUI (clean machine has no Python).
  - F2: three log-path lines copied verbatim from netsh output.
  - G3: copy ALL evidence out of the VM, then roll back LAST.

STEP 5 - HAND BACK
  Give the publisher: verify_2008r2_report.txt, pg_rules_baseline.txt,
  filled PG196_EVIDENCE_INDEX.txt, all PG196_*.png screenshots, E2
  audit CSV, F3 log sample, diag-*.txt, portguard.log*, and the
  signed signature page (section 5 of the verification document).
  Do NOT roll back the VM until every one of these is OUT.

ASCII-ONLY RULE
  Keep .bat / .ps1 / .txt as CRLF and pure ASCII. A non-ASCII byte or
  a UTF-8 BOM can break the 2008R2 scripts or the anchor parser.
