# Test material only

`cert.pem` and `key.pem` are a throwaway self-signed certificate for `localhost` and its private
key, made only for the tests in `server/tests/tls_cli.rs`. They protect nothing and must never be
used for a real server. `spki-sha256.txt` is the SHA-256 of the certificate's
SubjectPublicKeyInfo, the value the tests expect as the pin.
