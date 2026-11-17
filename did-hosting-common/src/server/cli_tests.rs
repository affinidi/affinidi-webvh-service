//! Tests for [`super`].

use super::*;
use clap::Parser;

#[derive(Parser)]
struct Probe {
    #[command(subcommand)]
    cmd: Probed,
}

#[derive(Subcommand)]
enum Probed {
    #[command(flatten)]
    Vta(VtaCommand),
    #[command(flatten)]
    Keys(KeysCommand),
}

/// `vta-request` takes the control plane's old `--did-hosting-url`
/// spelling as well as `--public-url`, and needs no mediator.
#[test]
fn vta_request_accepts_both_url_spellings() {
    for flag in ["--public-url", "--did-hosting-url"] {
        let p = Probe::try_parse_from(["x", "vta-request", flag, "https://a.example/x"])
            .expect("parses");
        let Probed::Vta(VtaCommand::VtaRequest {
            public_url,
            mediator_did,
            label,
            ..
        }) = p.cmd
        else {
            panic!("not vta-request");
        };
        assert_eq!(public_url, "https://a.example/x");
        assert_eq!(mediator_did, None);
        assert_eq!(label, None);
    }
}

#[test]
fn import_secrets_takes_one_key_source() {
    assert!(
        Probe::try_parse_from([
            "x",
            "import-secrets",
            "--vta-bundle",
            "a",
            "--signing-key",
            "b"
        ])
        .is_err()
    );
}

#[test]
fn a_producer_pubkey_is_decoded_with_or_without_its_multicodec_prefix() {
    let raw = [9u8; 32];
    let bare = multibase::encode(multibase::Base::Base58Btc, raw);
    let mut prefixed = vec![0xed, 0x01];
    prefixed.extend_from_slice(&raw);
    let prefixed = multibase::encode(multibase::Base::Base58Btc, prefixed);
    assert_eq!(decode_ed25519_pubkey_multibase(&bare).unwrap(), raw);
    assert_eq!(decode_ed25519_pubkey_multibase(&prefixed).unwrap(), raw);
    assert!(decode_ed25519_pubkey_multibase("zshort").is_err());
}

#[test]
fn each_service_names_its_own_artifacts_and_next_step() {
    assert_eq!(Service::Daemon.artifact_prefix(), "daemon");
    assert!(matches!(
        Service::Control.open_next_step(),
        super::super::vta_setup::OfflineOpenNextStep::Setup { .. }
    ));
    assert!(matches!(
        Service::Daemon.open_next_step(),
        super::super::vta_setup::OfflineOpenNextStep::ImportSecrets { .. }
    ));
}
