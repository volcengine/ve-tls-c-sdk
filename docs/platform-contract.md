# Platform Vtable Contract

`ve_tls_platform` is the portability boundary for threads, time, and local
persistent storage. A custom platform must provide the complete callback set
used by the producer, or start from `ve_tls_platform_init_default()` and
replace callbacks deliberately. Opaque mutex, condition, thread, and file
handles remain owned by the platform implementation.

## Threads and waits

- `mutex_lock` and `mutex_unlock` operate on a valid mutex. Condition waits
  require that mutex to be locked by the calling thread and return with it
  locked.
- `cond_wait` may wake spuriously; core rechecks its predicate.
- `cond_timedwait_ms` receives a relative timeout in milliseconds. Return `0`
  for a notification and a non-zero value for timeout or platform error. Core
  uses its own `time_ms` deadline and does not treat a non-zero wait result as
  a durable application error.
- `thread_create` starts the supplied function with its argument. Every
  successful handle is joined exactly once by `thread_join`; the callback must
  not detach or free that handle behind the platform's back.
- `sleep_ms` is a best-effort relative sleep. Non-positive values are no-ops.

The default pthread implementation returns the underlying pthread result for
timed waits, joins before freeing thread handles, and uses condition variables
with the mutex supplied by the caller.

## Time

`time_ms` is an epoch/wall-clock millisecond value used for queue deadlines,
retry budgets, rate/breaker timing, and persistent lease timestamps. A custom
implementation must use one consistent unit and clock domain across processes;
substituting a process-local monotonic value changes stale-lease semantics.
`time_unix_ns` is Unix epoch nanoseconds for APIs that need nanosecond wall-clock
timestamps. A time callback failure is represented by its documented sentinel
value; callers must not assume a network or storage error is encoded in that
value.

## Filesystem callbacks

The core accepts short reads and writes and loops until the requested byte
range is complete. Callback results follow these rules:

- `file_open` returns an opaque handle or `NULL` on failure.
- `file_read` and `file_write` return the number of bytes transferred; zero or
  a negative value aborts a full transfer.
- `file_seek` returns the resulting offset, or a negative value on failure.
- `file_fsync` returns `0` only after the file's preceding writes are durable;
  any non-zero value is a sync failure.
- `file_truncate` returns `0` on success and non-zero on failure.
- `path_stat` returns `0` for both an existing path and a missing path. For a
  missing path it sets `exists=0`; other stat errors are non-zero.
- `path_mkdirs`, `path_remove`, and `path_rename` return `0` on success and
  non-zero on failure. The default remove implementation treats an already
  missing path as success.

The core does not depend on a platform-specific `errno` value. Preserve enough
diagnostic context in the producer error/metric layer if the platform needs to
report a native cause.

## Durability and lease errors

Manifest, checkpoint, and lease writes are written and then passed through
`file_fsync`. Sync-WAL append also requires `file_fsync` before the append is
reported as durable. A failed fsync is not equivalent to a successful write:
the operation returns a persistent error, while bytes already written may be
seen again during recovery.

Lease acquisition reads the existing lease file. A heartbeat within
`lease_timeout_ms` is an owned lease and acquisition fails. Only
`TAKEOVER_IF_STALE` may replace a stale lease, and takeover increments the
fencing token. New leases start at token 1. Heartbeat updates the timestamp and
must also be durable. Release removes the lease only after the current lease
has been validated.

The low-level lease helpers return non-zero for malformed, owned, stale-mode,
open/read/write/fsync, or remove failures. Producer-level open/recover/flush
surfaces these failures as `VE_TLS_PERSISTENT_ERROR` or its documented
operation-specific failure result; no custom platform should silently convert
a failed durability barrier into success.
