# Development Guidelines

These rules apply to this repository, every nested directory, and nested submodules. Inside a LevitateOS checkout, the workspace root `AGENTS.md` also applies across Git boundaries. Local guides may add domain details but must preserve these rules.

- Unit testing is prohibited. Do not add, retain, run, or require unit tests, including assertion-based unit doctests and renamed or mock-only equivalents. Remove them instead of ignoring them.
- Keep development direct. Do authorized work without mandatory paperwork, decision matrices, repeated approvals, coverage targets, or process-only blockers.
- Choose compilation, typechecking, or focused integration/CLI/boot/runtime checks when useful. No mandatory build, lint, test, or policy-audit pipeline on local commits.
- Development submodules may follow working branches; exact superproject pins are required only for release reproduction or preparation.
- Fix behavior in its existing owner, preserve unrelated edits, and report failures honestly.
- Keep runtime checks that prevent invalid artifacts or destructive operations. Do not suppress failures or fabricate success.
