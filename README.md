# JWT Cracker

Multi-threaded JWT brute-force cracker in C. Tests all possible secret keys using HMAC verification against the token signature. For security testing only.

Uses modified [Apple Base64 implementation](https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c) with Base64URL support.

## Usage

```
./jwtcrack <token> [alphabet] [max_len] [hmac_alg]
./jwtcrack --version
```

| Argument | Default | Description |
|----------|---------|-------------|
| token | required | JWT to crack |
| alphabet | `eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789` | Characters to try |
| max_len | 6 | Max secret length (1-1000) |
| hmac_alg | sha256 | Hash function (see below) |

### HMAC Algorithms

- `sha256` - HS256 (HMAC-SHA256)
- `sha384` - HS384 (HMAC-SHA384)
- `sha512` - HS512 (HMAC-SHA512)

Any OpenSSL-supported hash name works. Unknown names fall back to sha256.

### Threading Model

Creates N threads where N = alphabet length. Each thread handles secrets starting with one character.

## Examples

Basic (HS256):
```
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE
```

Custom alphabet, max length 5, HS256:
```
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE ABCSNFabcsnf1234 5 sha256
```
Secret: `Sn1f` (< 1 second on modern CPU)

HS512 example:
```
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiYWRtaW4ifQ.RnWtv7Rjggm8LdMU3yLnz4ejgGAkIxoZwsCMuJlHMwTh7CJODDZWR8sVuNvo2ws25cbH9HWcp2n5WxpIZ9_v0g adimnps 9 sha512
```
Secret: `adminpass` (~15 seconds)

HS384 example:
```
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJyb2xlIjoiYWRtaW4ifQ.31xCH3k8VRqB8l5qBy7RyqI2htyCskBy_4cIWpk3o43UkIMW-IcjTUEL_NyFXUWJ 0123456789 6 sha384
```

## Build

### Linux

```
apt-get install libssl-dev
make
```

### macOS

```
brew install openssl
make OPENSSL=/usr/local/opt/openssl/include OPENSSL_LIB=-L/usr/local/opt/openssl/lib
```

### Clean

```
make clean    # remove objects
make fclean   # remove objects + binary
make re       # full rebuild
```

## Docker

Build:
```
docker build . -t jwtcrack
```

Run:
```
docker run -it --rm jwtcrack <token> [alphabet] [max_len] [hmac_alg]
```

Test (with Valgrind):
```
docker build -f Dockerfile.test -t jwtcrack-test .
docker run --rm jwtcrack-test
```

## Benchmarking

```
/usr/bin/time -f "CPU seconds: %U\nWall time: %E" ./jwtcrack <token> <alphabet> <max_len> <hmac_alg>
```

## Limitations

- No progress indicator
- Cannot resume interrupted runs
- Performance depends on alphabet size and max_len

## Contributing

See `FIXES-PROPOSED.md` for known issues and improvement proposals.
