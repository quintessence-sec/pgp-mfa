# pgp-mfa

a proof of concept for a multi-factor authentication system using PGP, possible alternative to TOTP (RFC 6238).

## usage

```bash
$ go build -v -o pgp-mfa
$ ./pgp-mfa import-key <key-file> # armored / binary format supported, - for stdin
$ gpg --export <key-id> | ./pgp-mfa import-key - # import from stdin
$ ./pgp-mfa challenge <length> [key-id]    # if no key-id is provided, you'll be prompted to select one
```

## what's the point?

the idea is not to replace RFC 6238, or any other MFA system, but to provide an alternative that could be used in production.

- still works offline
- not time based: it is not necessary to have a clock on the device, nor for it to be in sync with current real time.
- no shared secrets: TOTP relies on a shared secret between the server and the client, which could be compromised, by using PGP, only the public key is shared.
- emailable challenges: PGP keys contains an email address, the server could use this information to send the challenge to the user by email.
- benefits from expirability: PGP keys can expire, allowing a 0 interaction self-destruction of the mean of access to the account.

## how does it work?

1. the server generates a random string, and encrypts it with the public key of the user.
2. the encrypted message is sent to the user.
3. user has to decrypt the message using their private key (and passphrase if one is set).
4. the server checks whether the decrypted message is the same one as the one originally sent
5. (optional) the server can check whether the challenge has expired, and reject the solution if it has.

## performance

run benchmark with `go test -bench=.` and see the results. uses go's crypto/rand package to generate random bytes.

### tests

| test name | description |
| --- | --- |
| Ed25519_16 | uses a public ed25519 key to encrypt / decrypt a 16 bytes challenge |
| Ed25519_32 | 32 bytes challenge |
| Ed25519_64 | 64 bytes challenge |
| Ed25519_128 | 128 bytes challenge |
| Ed25519_256 | 256 bytes challenge |
| Ed25519_512 | 512 bytes challenge |
| rsa3072-16 | uses a public rsa3072 key to encrypt / decrypt a 16 bytes challenge |
| rsa3072-32 | 32 bytes challenge |
| rsa3072-64 | 64 bytes challenge |
| rsa3072-128 | 128 bytes challenge |
| rsa3072-256 | 256 bytes challenge |
| rsa4092-16 | uses a public rsa4092 key to encrypt / decrypt a 16 bytes challenge |
| rsa4092-32 | 32 bytes challenge |
| rsa4092-64 | 64 bytes challenge |
| rsa4092-128 | 128 bytes challenge |
| rsa4092-256 | 256 bytes challenge |
| ChallengesGeneration_16 | measures how fast can the machine can generate challenges of 16 bytes |
| ChallengesGeneration_32 | 32 bytes |
| ChallengesGeneration_64 | 64 bytes |
| ChallengesGeneration_128 | 128 bytes |
| ChallengesGeneration_256 | 256 bytes |
| ChallengesGeneration_512 | 512 bytes |
