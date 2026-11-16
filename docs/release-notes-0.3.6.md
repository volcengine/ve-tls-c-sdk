# Release Notes 0.3.6

## WAL recovery

- Recover large backlogs within the configured send-memory budget. Mobile
  producers with exclusive WAL ownership can continue reading in the
  background when the initial recovery window fills.
- Retry temporary WAL reads during mobile background recovery. When a
  record's checksum fails, replay later complete records whose boundaries
  can be verified and preserve ambiguous data.
- Replay older raw records with their original payload and encode key-value
  records normally, including when both formats coexist in a WAL.
- Keep exclusive WAL ownership while the current process holds the lock.
  On Android, a new owner that acquires the lock can take over before the
  lease expires once the previous local process is confirmed to have exited.

## WAL writes and acknowledgements

- Reclaim fully acknowledged space so producers can accept new records under
  the configured WAL limits.
- Reuse an ID only when the write never happened or rollback is confirmed.
  A complete write followed by a temporary sync failure retains its original
  ID and becomes eligible to send after syncing succeeds.
- Resume delivery of records already in the WAL when send-batch memory becomes
  available after a temporary allocation failure.

## Compatibility

- Upgrade using the existing WAL directory after stopping the old producer.
  Recovery uses the acknowledgements saved on disk. Delivery remains at least
  once when the client lacks a durable acknowledgement.
- The SDK package and default User-Agent identify version `0.3.6`. The
  service API header stays at `0.3.0`, and the public C ABI and versioned
  configuration layouts are unchanged.
