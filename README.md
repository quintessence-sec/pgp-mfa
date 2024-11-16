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
| Rsa3072-16 | uses a public rsa3072 key to encrypt / decrypt a 16 bytes challenge |
| Rsa3072-32 | 32 bytes challenge |
| Rsa3072-64 | 64 bytes challenge |
| Rsa3072-128 | 128 bytes challenge |
| Rsa3072-256 | 256 bytes challenge |
| Rsa4092-16 | uses a public rsa4092 key to encrypt / decrypt a 16 bytes challenge |
| Rsa4092-32 | 32 bytes challenge |
| Rsa4092-64 | 64 bytes challenge |
| Rsa4092-128 | 128 bytes challenge |
| Rsa4092-256 | 256 bytes challenge |
| ChallengesGeneration_16 | measures how fast can the machine can generate challenges of 16 bytes |
| ChallengesGeneration_32 | 32 bytes |
| ChallengesGeneration_64 | 64 bytes |
| ChallengesGeneration_128 | 128 bytes |
| ChallengesGeneration_256 | 256 bytes |
| ChallengesGeneration_512 | 512 bytes |

### results

```
goos: linux
goarch: amd64
pkg: github.com/quintessence-sec/pgp-mfa
cpu: AMD Ryzen 9 7950X 16-Core Processor            
BenchmarkEd25519_16-32                             27735             42647 ns/op
BenchmarkEd25519_32-32                             27698             43268 ns/op
BenchmarkEd25519_64-32                             27820             42442 ns/op
BenchmarkEd25519_128-32                            28976             41584 ns/op
BenchmarkEd25519_256-32                            28774             42483 ns/op
BenchmarkEd25519_512-32                            27616             43069 ns/op
BenchmarkRsa4092_16-32                              6246            178434 ns/op
BenchmarkRsa4092_32-32                              6500            181093 ns/op
BenchmarkRsa4092_64-32                              6232            182861 ns/op
BenchmarkRsa4092_128-32                             6586            180314 ns/op
BenchmarkRsa4092_256-32                             6598            181688 ns/op
BenchmarkRsa4092_512-32                             6369            181804 ns/op
BenchmarkRsa3072_16-32                             10000            109607 ns/op
BenchmarkRsa3072_32-32                             10000            110057 ns/op
BenchmarkRsa3072_64-32                             10000            110457 ns/op
BenchmarkRsa3072_128-32                            10000            109201 ns/op
BenchmarkRsa3072_256-32                            10000            110007 ns/op
BenchmarkRsa3072_512-32                             9853            111029 ns/op
BenchmarkChallengesGeneration_16-32              3557168               334.9 ns/op
BenchmarkChallengesGeneration_32-32              3463393               345.9 ns/op
BenchmarkChallengesGeneration_64-32              2635272               446.3 ns/op
BenchmarkChallengesGeneration_128-32             1996668               605.8 ns/op
BenchmarkChallengesGeneration_256-32             1361889               874.7 ns/op
BenchmarkChallengesGeneration_512-32              730452              1443 ns/op
PASS
ok      github.com/quintessence-sec/pgp-mfa     36.111s
```

according to the results, we can deduce that the most optimal configuration is to use an ed25519 key, with a challenge length of 128 bytes.

### resistance to brute-force attacks

the charset of challenges is, by default: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/\\'"!@#$%^&*()[]{}<>?,.;:`, which is a total of 91 characters.

if we consider an ed25519 key we can process 128 bytes in 41.584 microseconds (≈ 3.078 MB/s ~ 24046.875 attempts/s).

| challenge length | number of possible solutions | probability of 1st try success | number of years to brute-force |
| --- | --- | --- | --- |
| 16 bytes | 2.211E+31 | 4.522E-30% | 9.196E+26
| 32 bytes | 4.890E+62 | 2.045E-61% | 2.034E+58
| 64 bytes | 2.391E+125 | 4.182E-124% | 9.945E+120
| 128 bytes | 5.719E+250 | 1.749E-249% | 2.378E+246
| 256 bytes | 3.270E+501 | 3.058E-500% | 1.360E+497
| 512 bytes | 1.070E+1003 | 9.350E-1002% | 4.448E+998

this is, of course, assuming that:

1. the randomness of the challenge is perfectly random
2. the brute-force attacker has no access to the server
3. there are no delays between retries, and there are no maximum number of attempts
