// The one error type the signer throws. `reason` is the void-which-binds-go
// refusal word (or, for a minting refusal that has no wire word, the snake_case
// name of the Go sentinel), so a caller branches on it with equality, exactly
// as a Go caller asserts errors.Is / ReasonFor.

export class VoidWhichBindsError extends Error {
  /**
   * @param {string} reason the Go refusal word, e.g. 'malformed', 'wrong_type',
   *   'incomplete', 'issuer_mismatch', 'action_mismatch', 'unknown_handle'
   * @param {string} message
   * @param {{ detail?: string }} [opts] a finer word where Go wraps two
   *   sentinels (action_mismatch wraps digest_mismatch or resource_mismatch)
   */
  constructor(reason, message, opts = {}) {
    super(`void-which-binds: ${reason}: ${message}`);
    this.name = 'VoidWhichBindsError';
    /** @type {string} */
    this.reason = reason;
    /** @type {string | undefined} */
    this.detail = opts.detail;
  }
}
