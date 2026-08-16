# SRL binary

`srl` is a standalone command-line URL encoder and decoder. Its tokens are
self-contained, reversible, and compatible with the SRL web backend; no
database or network connection is required.

```sh
./srl encode 'https://example.com/a/long/path?query=value'
./srl decode 'TOKEN_FROM_ENCODE'
./srl decode 'https://your-srl.example/r/TOKEN_FROM_ENCODE'
./srl 'https://example.com/a/long/path?query=value'
./srl 'TOKEN_FROM_ENCODE'
```

The automatic form also recognizes complete SRL `/r/<token>` redirect links.
Both literal Unicode paths and their browser-percent-encoded forms are
supported. If the argument is omitted, one URL or token is read from standard
input:

```sh
printf '%s\n' 'https://example.com/path' | ./srl encode
```

Only absolute `http://` and `https://` URLs are accepted. Decoding restores the
exact original bytes, including URL case, escape spelling, query order, and
Unicode. If every self-contained token would be longer, encoding returns the
original URL unchanged; decoding accepts that pass-through form.

A raw token is not independently browser-routable. Decode it with this command
or append it to the web backend's `/r/` route to use it as a redirect link.

Build a stripped static Linux binary:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o srl .
```
