# Release Notes: 0.3.4 (preparation)

Status: preparation only. No Git tag has been created and no release has been
published for this candidate.

## Version identifiers

- SDK package version: `0.3.4`.
- Default TLS service API header version: `0.3.0` (`VE_TLS_C_SDK_API_VERSION`
  remains `"0.3.0"`).

The package version identifies this distribution. The service API value is sent
in `x-tls-apiversion`; it does not identify the C ABI. C compatibility is verified
through exported symbols and exact configuration version/size contracts.

## Included changes

- API-key authentication is available through the public producer constructors,
  including exact-size versioned configuration validation and key capture per
  request attempt. API-key requests disable HTTP debug logging to avoid exposing
  the key.
- Versioned configuration initialization and creation enforce the legacy-prefix
  and exact-size/version boundaries. Version 3 covers memory-retry,
  timeout-binding, delivery-diagnostic, and transient-HTTP policy fields while
  legacy creation leaves that tail disabled.
- Public delivery diagnostics and send-done callbacks expose delivery state,
  retry and retention outcomes, and borrowed callback metadata with documented
  lifetime and threading rules.
- Review fixes preserve the legacy initialization prefix, reject mismatched
  versioned layouts without reading beyond the supplied size, and keep delivery
  diagnostics consistent across retained-close and retry paths.
- Persistent lease validation and file mutations now share a local POSIX
  `lease.lock` guard. Each persistent Producer also receives a fresh 128-bit
  owner identity to prevent stale writers from matching a recreated lease after
  clock rollback. Lock or entropy failure rejects persistent initialization.
  Each instance reuses its own guard descriptor under an instance mutex, while
  keeping per-operation file locks and fresh lease reads. Private persistence
  operations reject cross-process use of inherited descriptors; Producer is
  not fork-safe and must be stopped before `fork()` and recreated in the child.
  Stop older instances before upgrading a shared directory;
  per-operation locks and lease reads still add I/O cost (see `docs/persistent.md`).
- The iOS Bridge can use a private lifetime-exclusive persistence constructor:
  it retains the existing guard until close/destroy and uses the instance mutex
  for normal WAL operations, avoiding repeated flock/lease reads. Heartbeat,
  close validation, recovery and fork rejection remain protected. Public C
  constructors, configuration layout, exported symbols and stale takeover
  semantics are unchanged; this private mode must not share a directory with
  an instance using a different ownership model.

## Release gate

The static/shared build, test, export, sanitizer, installed-consumer, and
platform checks remain release-gate work for the eventual 0.3.4 tag. Tagging and
publishing are intentionally outside this preparation change.
