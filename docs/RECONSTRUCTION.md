# Binary → REA → SPEC.md → rebuild → oracle → retry

The original application is the analysis input. The destination project is a separate folder. Treat rebuilding a whole application as a sequence of testable features, not one unbounded request.

## 1. Analyse and specify

Select the artifact, choose a feature or whole-application scope, and add known behaviour in Reverse engineering. **Prepare analysis** creates an Ask task with REA enabled. It can read the matching packaged REA workflows through `rea_workflow`, inspect the live schemas and availability, and gather actual static evidence.

The resulting brief should contain stable requirement IDs (`REQ-001`, etc.), UI flows, inputs/outputs, state transitions, file formats, error cases, dependencies, coverage, evidence references and unresolved questions. Separate static facts, user observations, inference and unknowns. Write behavioural contracts rather than pasting decompiled implementation bodies into the specification.

Use runtime tools only for a defined observation on a selected target. Toolchain installation does not authorise arbitrary process attachment, target execution, network interception or modification. The manual REA catalog shows its actual runtime capabilities; the coding agent's REA subset remains static. External debuggers can be opened explicitly from Toolchain. No proxy certificate or system proxy is installed automatically.

## 2. Save SPEC and build

Choose the completed brief and click **Save SPEC & prepare build**. A new `quixi-reconstruction-<UUID>` folder contains:

- `SPEC.md`: the draft contract to review and refine.
- `oracle-cases.json`: initially empty, so coverage starts unverified.
- `manifest.json`: target, scope, observations, brief identity and evidence hashes.
- `evidence/<record-ID>.json`: the original saved results for this artifact, including failures.
- `README.md`: a coverage checklist.

If a saved specification is selected, the build task reuses it so your edits remain intact. The prepared implementation task runs in Code mode with REA disabled. The agent's file reader blocks raw dossier evidence and manifests in implementation/retry runs, omits them from its initial file list, and rejects analysis task-record reads. Its instructions use SPEC and project code, and send unanswered analysis questions back to a separate analysis pass. In implementation and retry runs the agent's write, edit and append actions refuse anything under `quixi-reconstruction-*` (SPEC, oracle cases, evidence) and `quixi-oracle-runs/`: you own the specification and expected results. Its shell `command` action is not restricted this way, and MCP clients' file tools are outside this rule; a changed oracle file needs a new approval. The agent proposes missing oracle cases in its summary for you to add and approve. The editor remains available for your own evidence review. This is an information-separation workflow; Code mode still has the Windows user's permissions, including shell access, and is not a separate OS security boundary. A strict isolated implementation process requires a separate environment containing only the reviewed specification and implementation files.

## 3. Declare oracles

An oracle is a supported expected result for a defined input. Record where that expectation came from. Do not change expected outputs merely to make the reconstruction pass. Keep independent reference observations outside implementation-generated results.

Example schema, to adapt to a real rebuilt program and a real reference observation:

```json
{
  "version": 1,
  "cases": [
    {
      "id": "sum-positive",
      "requirement": "REQ-001",
      "argv": ["build/rebuild.exe", "--sum", "19", "23"],
      "expectationSource": "Reviewed reference observation: inputs 19 and 23 produce 42 and exit 0",
      "expected": {
        "exitCode": 0,
        "stdout": "42\r\n",
        "stderr": ""
      }
    }
  ]
}
```

Each case uses exactly one of two forms:

- `argv` (preferred): the program (relative to the destination project or absolute) and its arguments, with optional `stdin` text. It runs directly, without PowerShell, so stdout/stderr are compared byte for byte and the real exit code is reported.
- `command`: a PowerShell command line, kept for compatibility. PowerShell re-encodes native output line by line, so exact line endings and exit codes other than 0/1 may not survive.

Cases run in the destination project's root. Each needs a unique ID, requirement, `argv` or `command`, expectationSource, expected exitCode, and at least one expected output stream. Comparisons are exact, including whitespace and line endings. Omit a stream only if it is intentionally outside that case's comparison. A program that does not exist fails the case (PowerShell `CommandNotFoundException` / "is not recognized" counts as a failure unless the expected stderr declares it). At most 12 cases run per batch; output is bounded and truncation fails the case. Each case uses the 180-second timeout, and its whole process tree is ended afterwards.

### Approval

Oracle commands are programs that run with your Windows permissions, so a suite runs only after you approve its exact bytes. **Run oracle checks** first shows every case's command or argv, its expectations and the file's SHA-256. **Approve & run** records that hash in REA Studio's data directory (never in the project). Any later change to the file, including by an agent, requires a new review. The agent's `oracle` action and the MCP `studio_oracle_run` tool run only an approved, unchanged suite; neither can approve one, and the agent's file actions and the MCP file tools cannot reach the approval record, because REA Studio refuses to open its data directory as, inside or around a project.

Approval is a consent step, not a security boundary. Shell commands run with your Windows permissions (the Code-mode `command` action and the MCP `studio_command` tool) can modify any file you can, including the approval record. Review commands an agent or MCP client runs, and use a separate environment when you need isolation.

For binary files, structured data, screenshots, numerical tolerances or UI flows, write a project test/harness that compares the reconstructed output with independently supplied fixtures, then declare its command and supported expected output. The built-in runner compares stdout/stderr and exit status; it does not invent image similarity or silently normalise JSON. Store fixtures and harness code with the project. Do not distribute someone else's artifacts with this application.

## 4. Run, inspect and retry

Select the saved specification, choose Code mode, click **Run oracle checks**, review the listed commands and approve them. The runner saves an immutable report under `quixi-oracle-runs/<UUID>.json`, including commands, expectation sources, observed output, exit codes and differences.

- `unverified`: no cases were declared. This is not a pass.
- `failed`: at least one case did not match or could not run completely.
- `passed`: every declared case matched. Uncovered requirements remain unverified.

**Prepare retry** creates a Code task referring to the actual failure report. It repairs the implementation and reruns the oracle suite, with at most three repair attempts requested per task. If a requirement or expected output is missing, record the blocker and return to REA/observation. Do not manufacture a success claim at the iteration limit.

The agent can invoke the same runner with `{"action":"oracle","config":"quixi-reconstruction-<UUID>/oracle-cases.json"}` once you have approved that file. Reports survive restarts and are ordinary project files. This loop does not guarantee a model will follow every instruction or reconstruct an entire application; inspect the actual changes, evidence and comparisons.

## Coverage limits

Static decompilation can reveal interfaces and algorithms but cannot prove all runtime behaviour. Packed resources, dynamically generated code/data, remote services, user accounts and hardware-dependent behaviour may need additional observations. Failed parsers remain failed in the dossier. For PE resources that are not file-backed, continue supported native/import analysis and retain resource recovery as an unresolved requirement.
