# Release Notes 0.3.5

## Build

- The PutLogs protocol demos support shared-library builds with curl enabled.
- The PutLogsV2 demo encodes the nanosecond remainder within the current millisecond.
- The PutLogsV2 demo returns success for HTTP 200 before clearing its response.

## Persistent delivery

- Persist acknowledged WAL ranges across gaps. After restart, recovery skips
  records covered by durable acknowledgements and replays unconfirmed records.
- Preserve the WAL record ID high-water mark across reopen so that new records
  cannot reuse IDs that a previous checkpoint already acknowledges.
- Apply the checkpoint retry delay after a write failure even when further ACKs
  arrive. Explicit flush and close still attempt to save the checkpoint.

## Compatibility

- New WAL checkpoints retain the readable V1 prefix. Stop the old
  producer before opening its WAL directory with the new version.
- Delivery remains at least once. A successful write whose response is lost or
  a process exit before a checkpoint becomes durable can still cause a replay.
- The SDK package and default User-Agent identify version `0.3.5`. The default
  service API header stays at `0.3.0`. The public C ABI and versioned configuration
  layout are unchanged.
