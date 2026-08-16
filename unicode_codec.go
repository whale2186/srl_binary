package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/dop251/scsu"
)

const (
	// V4 applies the Unicode Standard Compression Scheme (SCSU) to the exact
	// UTF-8 suffix after the lowercase scheme. SCSU is especially effective for
	// short Cyrillic, Arabic, Hebrew, and Indic text. These markers and the
	// pinned encoder version are part of the wire format.
	modeSCSUHTTPS byte = 's'
	modeSCSUHTTP  byte = 't'
)

func encodeUnicodeURLV4(link string) (string, bool, error) {
	var mode byte
	var suffix string
	switch {
	case strings.HasPrefix(link, "https://"):
		mode = modeSCSUHTTPS
		suffix = link[len("https://"):]
	case strings.HasPrefix(link, "http://"):
		mode = modeSCSUHTTP
		suffix = link[len("http://"):]
	default:
		return "", false, nil
	}

	// ASCII is already handled more compactly by the URL dictionaries/range
	// model. Skipping it also avoids needless allocations on the common path.
	if !utf8.ValidString(suffix) || scsu.FindFirstEncodable(suffix) < 0 {
		return "", false, nil
	}
	encoded, err := scsu.EncodeStrict(suffix, nil)
	if err != nil {
		return "", false, err
	}
	return makeToken(mode, encoded), true, nil
}

func isUnicodeModeV4(mode byte) bool {
	return mode == modeSCSUHTTPS || mode == modeSCSUHTTP
}

func decodeUnicodeURLV4(token string) ([]byte, error) {
	if len(token) < 2 || !isUnicodeModeV4(token[0]) || !isRawBase64URL(token[1:]) {
		return nil, errMalformedToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(token[1:])
	if err != nil || len(payload) == 0 {
		return nil, errMalformedToken
	}

	reader := scsu.NewReader(bytes.NewReader(payload))
	var suffix strings.Builder
	for {
		r, _, readErr := reader.ReadRune()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, errMalformedToken
		}
		size := utf8.RuneLen(r)
		if size < 0 || suffix.Len() > maxURLBytes-size {
			return nil, errDecodedTooLarge
		}
		suffix.WriteRune(r)
	}

	// SCSU permits multiple representations of some text. Re-encoding rejects
	// aliases and catches corrupt streams that happen to decode successfully.
	canonical, err := scsu.EncodeStrict(suffix.String(), nil)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, errors.New("noncanonical or corrupt SCSU compressed link")
	}

	prefix := "https://"
	if token[0] == modeSCSUHTTP {
		prefix = "http://"
	}
	if suffix.Len() > maxURLBytes-len(prefix) {
		return nil, errDecodedTooLarge
	}
	return append([]byte(prefix), suffix.String()...), nil
}

func unicodeModeNameV4(mode byte) string {
	switch mode {
	case modeSCSUHTTPS:
		return "SCSU HTTPS"
	case modeSCSUHTTP:
		return "SCSU HTTP"
	default:
		return fmt.Sprintf("unknown Unicode mode %q", mode)
	}
}
