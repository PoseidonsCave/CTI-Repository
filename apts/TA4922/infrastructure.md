# Infrastructure

## Scope

This report documents only network and cryptographic artifacts statically
recovered from the local samples. No suspected host was contacted. The
configured addresses and certificate do not establish successful network
activity, server ownership, or current availability.

## Local Network Model

| Artifact | Local evidence | Defensive use |
| --- | --- | --- |
| Configured C2 | Two addresses decrypted from the HMAC-verified client configuration | Endpoint and network hunting on TCP/4449 |
| TLS identity | Embedded certificate, verified configuration-key signature, and certificate-pinning callback | Sample-linked certificate-fingerprint pivot |
| Application framing | Four-byte little-endian length prefix and MessagePack records inside `SslStream` | Endpoint plaintext or authorized TLS-decryption analysis |

## Locally Recovered RAT C2

| Indicator | Local evidence |
| --- | --- |
| `103.59.103[.]93:4449` | Decrypted and HMAC-verified client configuration |
| `103.97.128[.]141:4449` | Decrypted and HMAC-verified client configuration |

Both loader variants contain byte-for-byte identical copies of the managed
client. The two addresses therefore derive from the same recovered
configuration. Static analysis does not establish whether the client
connected to either address or whether either endpoint was operational.

## Pinned Certificate

The recovered RAT embeds a certificate and an RSA signature over its
configuration key. The signature verifies with the certificate's public key,
associating the key with the embedded certificate. The client then pins that
certificate in its `SslStream` validation callback. This relationship does
not establish ownership of, or successful authentication to, a specific
server.

| Field | Value |
| --- | --- |
| SHA-256 | `da8751a11fbd4f9638aab7fbd89ba21d8e1d9661710e7d04f35268bb4e3564ef` |
| SHA-1 | `811816215363259bb445a45422e60ff5d02c18f5` |
| SPKI SHA-256 | `8c1f16f891ec0decbebf06abc4a1d4db64fe5df19c1edaf342b4a0a79ce8922d` |
| Subject | `CN=Venom` |
| Issuer | `C=CN, L=SH, O=Venom By alexeikun, OU=alexeikun, CN=Venom Server` |
| Serial | `F8D5DCAEBB74E335D238A4A8AB87EF26AA0C7FC7` |
| Key | RSA-1024 |
| Validity | 2024-10-18 through 2035-07-28 |

## Analytic Takeaways

- Retain the two configured addresses as local sample artifacts and preserve
  their TCP/4449 context.
- Correlate the certificate fingerprint with the local payload, configured
  addresses, or endpoint artifacts; a fingerprint match alone does not
  establish actor-wide ownership.
- Treat application framing as an endpoint-plaintext or authorized
  TLS-decryption opportunity because the length prefix and MessagePack body
  are carried inside TLS.
- Do not infer successful execution, network connectivity, endpoint
  availability, or infrastructure ownership from static configuration.
