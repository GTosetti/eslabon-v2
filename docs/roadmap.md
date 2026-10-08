# Roadmap

Everything here is **out of v0.1** (`docs/design.md` §3, "Out"). The six items keep the
order of priority set there. Gaps that the reviews of v0.1 routed to the roadmap are
added under the item they belong to, each with its origin. Nothing on this page is built.

## 1. Measuring detection against real samples

v0.1 measures false positives on 200 legitimate packages (`docs/measurements.md`) and
fires every rule on synthetic fixtures built at test time. It has not measured how many
real malicious packages it catches. The source for that is DataDog's malicious-packages
dataset, and it is handled only inside Kali (design §8: suspicious packages are analysed
only in Kali; the host runs the test suite and the legitimate corpus only).

Procedure:

1. **Snapshot Kali, cold.** Shut the VM down first: on the lab host a live snapshot never
   converged under Hyper-V (`docs/evidence/e7/README.md`, "Incidents").
2. **Clone the dataset inside Kali**, never on the host.
3. **Decrypt inside Kali**, into a directory that is not shared with the host, and run
   `eslabon scan` over each archive there. Nothing is installed or executed: Eslabon
   reads the archives in memory.
4. **Export only results**: the JSON Lines events and the per-rule counts. No sample,
   archive or decrypted file leaves the VM.
5. **Restore** Kali to the snapshot, and confirm the restore as in E7
   (`currentStateModified="false"` in the `.vbox` file).

What to publish: the detection rate per rule and per ecosystem, next to the
false-positive table, with the same "measured, not proven" caveat.

## 2. `.pth` files that `import` at interpreter startup

From design §3. A `.pth` file is scanned like any other member (ESL-003 and ESL-004 run
on every file), but no rule judges a `.pth` line that imports code at interpreter
startup.

## 3. Archive anomalies beyond v0.1

From design §3 and §8:
- case-only name collisions;
- comparing a zip entry's local-header name with its central-directory name, beyond the
  `BadZipFile` case v0.1 already records;
- tar trailing data.

Routed here by the Task 4 review (tar reading):
- data hidden in tar member padding, or skipped through a pax `size` override;
- GNU sparse extension blocks (a sparse member is recorded and the scan is
  `incomplete`, but its content is not reconstructed);
- the tar reader relies on `tarfile` internals, which are only partly guarded by tests.

Routed here by the false-positive measurement (`docs/measurements.md`, ruling R50):
- when a PyPI sdist hits a cap, fall back to the wheel;
- skip an oversize member, record an anomaly and continue, instead of aborting the rest
  of the archive. Today a cap stops the scan and the summary is `limits_exceeded`, which
  must be triaged as an unscanned remainder, never as clean.

## 4. Dependency files

`requirements.txt` and `package-lock.json` are not read. Eslabon scans one package
archive at a time.

## 5. Entropy, metadata signals, steganography, bundled binaries

From design §3: entropy; metadata signals such as package age, a missing repository or
odd version jumps; steganography; bundled binaries.

Rule extensions the reviews routed here (residual gaps of v0.1, see the README's
"What this does not detect"):
- **ESL-003** (Task 9 review): JavaScript evaluators other than a direct `eval` or
  `Function` call (the `vm` module's run functions, a timer given a decoded string, an
  indirect or bracket-notation `eval`); Python evaluators reached through aliases,
  `getattr` or the `builtins` module; a gap of more than 50 characters between evaluator
  and decoder.
- **ESL-001** (Task 10 review): a download command assembled indirectly, for example
  through string formatting or a `shutil.which` lookup, rather than written next to the
  `subprocess`/`os.system` call.
- **ESL-004** (ruling R40): environment exfiltration that iterates over the variables
  instead of serialising the whole environment.
- **ESL-005** (ruling R44): typosquats of npm packages ranked below 1,000. Raising the
  cutoff to 2,000 for npm was measured at +6 false positives per 1,000 names for +2
  historical hits, and was not taken.

## 6. Syslog/CEF output; publishing to PyPI

Output today is JSON Lines only. The name `eslabon` was free on PyPI and npm on
2026-10-05 (design §3); v0.1 is not published to either.
