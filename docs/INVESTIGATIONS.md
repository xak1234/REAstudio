# Multi-artifact investigations

An investigation groups the exact file builds being examined: for example, an EXE and several DLLs. It records a name, canonical file paths and SHA-256 identities in the app's data directory. It does not copy, execute or modify those original files.

Open a destination project outside every original artifact's folder. Select the relevant artifact paths in Reverse engineering, name the investigation and capture it. Snapshots are immutable: capture another investigation when a module is rebuilt. The previous snapshot and saved evidence remain available. Two different paths with identical bytes remain distinct modules; duplicate spellings of one path are refused.

Investigations belong to the selected project folder. Moving a project does not silently retarget its snapshots. Names may repeat; each snapshot has its own ID and creation time.

## Inspect a saved investigation

Inspection reads the current file identities and classifies each artifact:

| Status | Meaning |
| --- | --- |
| Current | The current bytes match the pinned SHA-256 and size. |
| Changed | The file's size or content differs. If its size already differs, hashing is skipped. |
| Missing | The pinned file or an ancestor no longer exists. |
| Unavailable | Identity could not be established, including a read error, symbolic link/reparse point, or exhausted byte budget. |

The result separately counts matching saved observations, excluded records, failed observations and unverified model suggestions. A module can be current while having **no analysis evidence**. Neither a current hash nor a successful export establishes analysis coverage or correct reconstruction.

The file snapshot is immutable; its matching evidence can grow as you perform additional analysis on the same builds. Inspection and export discover the saved observations available at that time. They do not change REA's selected target or run analysis automatically. Continue to select and analyse each module explicitly through the existing REA/IDA tools.

## Export an evidence bundle

Export requires every pinned file to be current and at least one matching saved observation. The destination must be outside every original artifact folder and must not contain any of the original files.

A new `rea-investigation-<UUID>` directory contains:

- `manifest.json`: the named snapshot, each module's pinned identity and evidence counts, original record metadata, record-file hashes, exclusions with reasons, limits and remaining uncertainties.
- `evidence/<record-ID>.json`: the original saved response bytes for observations matching both a module's path and pinned SHA-256.
- `README.md`: the bundle's purpose and limits.

Failed observations remain failures. Model suggestions remain explicitly unverified even when the identity of their source artifact is known. A module without matching observations is marked `no-matching-saved-evidence`; it is not silently counted as analysed. Records for an earlier build, records whose artifact changed during analysis and records without a verified identity are excluded with reasons. Their originals are preserved.

Discovery reads bounded record headers directly, ignoring the response structure while selecting records. It does not trust the summary index to supply record identity, target or provenance. Legacy IDA records with a provider input SHA-256 retain that identity; other legacy records without verified identities remain excluded.

Export writes into a newly created staging directory, then rechecks all pinned files before promoting the complete bundle. A failed ordinary export cleans only its own staging directory. A process or machine interruption can leave a `.partial` directory; it is not a completed export and is never reused as one. Earlier bundles are not overwritten or removed.

Removing an investigation deletes only that project's snapshot metadata. It does not delete original artifacts, saved observations or exported bundles.

## Bounds and interpretation

| Resource | Limit |
| --- | --- |
| Saved investigations | 32 per project |
| Artifacts | 32 files per investigation |
| Artifact size | 4 GiB per file, 8 GiB total |
| Hashing | Streaming with a shared 8 GiB budget per identity-check pass; capture/export use separate initial and final passes |
| Matching exported evidence | 4,096 records, 128 MiB total |
| Individual saved record | 16 MiB |
| Exclusion details | 4,096 records, 16 MiB of metadata |
| Saved-history discovery | 10,000 records, 512 MiB of input |
| Saved snapshot metadata | 2 MiB |

Directories, network/device paths and symbolic links or Windows reparse points are not accepted as pinned files. File snapshots do not claim that all dynamically loaded modules, resources, servers or runtime state have been discovered.

Limits fail explicitly rather than returning a silently truncated bundle. Discovery examines the app's saved evidence history, including records for other artifacts. A malformed or oversized record blocks discovery and identifies the problematic record; its original is preserved. Review that record or use individual evidence export instead of treating a partial scan as complete coverage.

Independent file hashes are observations at separate times. They do not create an atomic whole-application snapshot, authenticate a provider's conclusions or prove runtime equivalence. For a reconstruction, derive a separately reviewed specification and supported behavioural cases. Investigation export deliberately does not create a SPEC, an approved oracle suite or an automatic implementation handoff.
