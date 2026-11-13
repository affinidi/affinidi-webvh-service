#![no_main]
//! Fuzz `did_ops::verify_log_extends`, the append-only check between the log a
//! host holds and the one it is sent.
//!
//! Input layout: the previous log, a NUL byte, then the next log; without a
//! NUL the whole input is the next log with no previous one. Must never
//! panic, and resending the identical log is always accepted.

use did_hosting_common::did_ops::verify_log_extends;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let next = match data.split_once('\0') {
        Some((previous, next)) => {
            let _ = verify_log_extends(Some(previous), next);
            let _ = verify_log_extends(Some(next), previous);
            next
        }
        None => data,
    };
    let _ = verify_log_extends(None, next);
    assert!(
        verify_log_extends(Some(next), next).is_ok(),
        "resending the identical log was refused"
    );
});
