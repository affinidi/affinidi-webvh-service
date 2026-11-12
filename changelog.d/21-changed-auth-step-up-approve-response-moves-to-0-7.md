### Changed — `auth/step-up/approve-response` moves to 0.7

The VTA and the VTC moved every step-up answer to
`auth/step-up/approve-response/0.7` and stopped serving 0.6
(OpenVTC/verifiable-trust-infrastructure#2346), and the browser wallet
cuts over with them (OpenVTC/vta-browser-plugin#412). Its lock holds one
version per slug, so after that change the wallet sends only 0.7, and a
control plane still on 0.6 refuses every `stepUpVta` approval. The control
plane now serves 0.7 only; 0.6 is no longer accepted. Merge together with
the wallet's change.

The payload is unchanged. 0.7 relaxes the specification's proof
requirement and spells the `assertionInvalid` `details.reason` values in
lowerCamelCase. The control plane still requires an `assertionMethod`
proof (a relying party may be stricter than the specification) and emits
no `details.reason`, so neither change alters what it does. The UI's
generated types follow the lock.
