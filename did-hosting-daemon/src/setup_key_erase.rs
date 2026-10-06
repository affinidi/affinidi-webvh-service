//! Best-effort secure erase of the ephemeral setup key (FTL-29235).
//!
//! The setup key file holds the private key of the `did:key` that was an admin
//! at the VTA during online provisioning. Once provisioning succeeds the file
//! has no further use, so it is zero-filled, synced and unlinked rather than
//! left recoverable on the volume.

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Overwrite `path` with zeros (flushed to disk), then remove it. A missing
/// file is not an error, so the call is idempotent.
pub fn erase_setup_key(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let len = f.metadata()?.len();
        f.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 4096];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..chunk])?;
            remaining -= chunk as u64;
        }
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::remove_file(path)
}

/// Erase the setup key after a successful provision and report the outcome on
/// stderr. A failed erase is a warning, not an error: provisioning already
/// succeeded and must not be reported as failed.
pub fn erase_after_provision(path: &Path) {
    match erase_setup_key(path) {
        Ok(()) => eprintln!("  setup key securely erased: {}", path.display()),
        Err(e) => eprintln!(
            "  WARNING failed to erase setup key {}: {e}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::erase_setup_key;
    use std::io::Write;

    #[test]
    fn removes_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("setup-key.json");
        std::fs::File::create(&path)
            .expect("create")
            .write_all(b"{\"private_key_multibase\":\"zSECRET\"}")
            .expect("write");

        erase_setup_key(&path).expect("erase");

        assert!(!path.exists(), "file must be removed after erase");
    }

    #[test]
    fn is_noop_when_file_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.json");

        erase_setup_key(&path).expect("idempotent");

        assert!(!path.exists());
    }

    #[test]
    fn zeroes_bytes_before_removal() {
        // Keep the inode alive through a hard link so the overwritten bytes
        // can be read back after the original path is unlinked.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("setup-key.json");
        let link = dir.path().join("peek.hardlink");
        let secret = b"zSUPERSECRETKEYMATERIAL0123456789";
        std::fs::File::create(&path)
            .expect("create")
            .write_all(secret)
            .expect("write");
        std::fs::hard_link(&path, &link).expect("hard link");

        erase_setup_key(&path).expect("erase");

        assert!(!path.exists());
        let residual = std::fs::read(&link).expect("read link");
        assert_eq!(residual.len(), secret.len());
        assert!(
            residual.iter().all(|&b| b == 0),
            "bytes must be zeroed before unlink"
        );
    }
}
