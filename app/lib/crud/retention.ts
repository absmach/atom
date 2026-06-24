/**
 * Default soft-delete retention window, in days. Mirrors the backend
 * `ATOM_PURGE_RETENTION_DAYS` default (`PurgeConfig` in `src/config.rs`).
 *
 * Disable vs delete:
 * - Disabling sets a status (`inactive`/`disabled`/`suspended`). It is
 *   reversible, keeps the row live, and only blocks the subject from acting.
 * - Deleting soft-deletes the row: it is hidden immediately and stays
 *   recoverable. Physical purge (permanent removal) only runs when purge is
 *   enabled on the server; until then tombstones are retained indefinitely.
 */
export const DEFAULT_RETENTION_DAYS = 90;

/** Shared note appended to soft-delete confirmation dialogs. */
export const SOFT_DELETE_RETENTION_NOTE =
  "It is hidden immediately and stays recoverable. When purge is enabled, it " +
  `is permanently removed after the retention period (default ${DEFAULT_RETENTION_DAYS} days).`;
