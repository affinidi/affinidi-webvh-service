# Affinidi WebVH Service

WebVH DID requires supporting infrastructure for it to work to it's full potential.

- WebVH Server
- WebVH Witness
- WebVH Watcher
- WebVH Common

> **IMPORTANT:**
> affinidi-webvh-service crate is provided "as is" without any warranties or guarantees,
> and by using this framework, users agree to assume all risks associated with its
> deployment and use including implementing security, and privacy measures in their
> applications. Affinidi assumes no liability for any issues arising from the use
> or modification of the project.

## Requirements

- Rust (1.91.0) 2024 Edition

## Example Client

The `webvh-server` crate includes an example CLI (`webvh-server/examples/client.rs`)
that demonstrates the full flow of programmatically creating a `did:webvh` DID
and uploading it to a running webvh-server. It handles DIDComm v2
authentication, DID document construction, WebVH log entry creation, and
upload.

### Building

```sh
cargo build -p affinidi-webvh-server --example client
```

### Usage

1. Start the webvh-server with DIDComm authentication configured.

2. Run the example, pointing it at the server:

   ```sh
   cargo run -p affinidi-webvh-server --example client -- --server-url http://localhost:8085
   ```

3. The example will generate a `did:key` identity and pause, printing the DID:

   ```
   Generated DID: did:key:z6Mk...
   Ensure this DID is in the server ACL (e.g. via webvh-server invite).
   Press Enter to continue...
   ```

   Add the printed DID to the server's ACL (for example, by running the
   webvh-server `invite` command in another terminal), then press Enter.

4. The example will authenticate, create the DID, upload it, and verify
   resolution. On success it prints a summary:

   ```
   DID Created and Hosted Successfully!
     Mnemonic:   apple-banana
     SCID:       FHcGtSJ...
     DID URL:    http://localhost:8085/apple-banana/did.jsonl
     DID:        did:webvh:FHcGtSJ...:localhost%3A8085:apple-banana
     Public Key: z6Mk...
   ```

## Support & feedback

If you face any issues or have suggestions, please don't hesitate to contact us
'using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi WebVH Service codebase, you can
also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on GitHub under
   [Issues](https://github.com/affinidi/affinidi-webvh-service/issues).

2. If you're unable to find an open issue addressing the problem,
   [open a new one](https://github.com/affinidi/affinidi-webvh-service/issues/new).
   Be sure to include a **title and clear description**, as much relevant
   information as possible,
   and a **code sample** or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute?

Head over to our [CONTRIBUTING](https://github.com/affinidi/affinidi-webvh-service/blob/main/CONTRIBUTING.md)
guidelines.
