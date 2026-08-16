package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	// Brotli modes are versioned by their marker. The algorithm has a built-in
	// web-text dictionary and is most useful for longer, unfamiliar URLs.
	modeBrotliHTTPS          byte = '.'
	modeBrotliHTTP           byte = '-'
	modeBrotliTokenizedHTTPS byte = 'b'
	modeBrotliTokenizedHTTP  byte = 'c'

	// Below this point the structural/range and DEFLATE candidates win the
	// regression corpus, while constructing eight Brotli encoders only adds
	// latency and memory.
	minimumBrotliInputV3 = 80
)

var brotliOptionsV3 = []brotli.WriterOptions{
	{Quality: 5, LGWin: 16},
	{Quality: 9, LGWin: 16},
	{Quality: 10, LGWin: 16},
	{Quality: 11, LGWin: 16},
}

var (
	mediumBrotliOptionsV3 = []brotli.WriterOptions{
		{Quality: 5, LGWin: 16},
		{Quality: 9, LGWin: 16},
		{Quality: 10, LGWin: 16},
	}
	largeBrotliOptionsV3 = []brotli.WriterOptions{
		{Quality: 5, LGWin: 20},
		{Quality: 9, LGWin: 20},
		{Quality: 10, LGWin: 20},
	}
)

func encodeBrotliURLV3(link string) (string, bool, error) {
	var rawMode, tokenizedMode byte
	var suffix string
	switch {
	case strings.HasPrefix(link, "https://"):
		rawMode = modeBrotliHTTPS
		tokenizedMode = modeBrotliTokenizedHTTPS
		suffix = link[len("https://"):]
	case strings.HasPrefix(link, "http://"):
		rawMode = modeBrotliHTTP
		tokenizedMode = modeBrotliTokenizedHTTP
		suffix = link[len("http://"):]
	default:
		return "", false, nil
	}
	if len(suffix) < minimumBrotliInputV3 {
		return "", false, nil
	}

	raw, err := bestBrotliV3([]byte(suffix))
	if err != nil {
		return "", false, err
	}
	tokenizedInput := tokenizeV1([]byte(suffix))
	tokenized, err := bestBrotliV3(tokenizedInput)
	if err != nil {
		return "", false, err
	}

	rawToken := makeToken(rawMode, raw)
	tokenizedToken := makeToken(tokenizedMode, tokenized)
	if len(tokenizedToken) < len(rawToken) {
		return tokenizedToken, true, nil
	}
	return rawToken, true, nil
}

func bestBrotliV3(input []byte) ([]byte, error) {
	var best []byte
	options := brotliOptionsV3
	if len(input) > 4<<10 {
		options = mediumBrotliOptionsV3
	}
	if len(input) > 1<<16 {
		options = largeBrotliOptionsV3
	}

	for _, option := range options {
		var buffer bytes.Buffer
		writer := brotli.NewWriterOptions(&buffer, option)
		if _, err := writer.Write(input); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		best = chooseCompressedBytes(best, buffer.Bytes())
	}
	return best, nil
}

func isBrotliModeV3(mode byte) bool {
	switch mode {
	case modeBrotliHTTPS, modeBrotliHTTP, modeBrotliTokenizedHTTPS, modeBrotliTokenizedHTTP:
		return true
	default:
		return false
	}
}

func decodeBrotliURLV3(token string) ([]byte, error) {
	if len(token) < 2 || !isBrotliModeV3(token[0]) || !isRawBase64URL(token[1:]) {
		return nil, errMalformedToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(token[1:])
	if err != nil || len(payload) == 0 {
		return nil, errMalformedToken
	}

	tokenized := token[0] == modeBrotliTokenizedHTTPS || token[0] == modeBrotliTokenizedHTTP
	limit := maxURLBytes
	if tokenized {
		limit = maxTokenizedBytes
	}
	decoded, err := inflateBrotliV3(payload, limit)
	if err != nil {
		return nil, err
	}
	if tokenized {
		decoded, err = detokenizeV1(decoded)
		if err != nil {
			return nil, err
		}
	}

	prefix := "https://"
	if token[0] == modeBrotliHTTP || token[0] == modeBrotliTokenizedHTTP {
		prefix = "http://"
	}
	if len(decoded) > maxURLBytes-len(prefix) {
		return nil, errDecodedTooLarge
	}
	return append([]byte(prefix), decoded...), nil
}

func inflateBrotliV3(input []byte, limit int) ([]byte, error) {
	source := bytes.NewReader(input)
	reader := brotli.NewReader(source)
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > limit {
		return nil, errDecodedTooLarge
	}
	if source.Len() != 0 {
		return nil, errors.New("Brotli compressed link contains trailing data")
	}
	return decoded, nil
}

func brotliModeNameV3(mode byte) string {
	switch mode {
	case modeBrotliHTTPS:
		return "Brotli HTTPS"
	case modeBrotliHTTP:
		return "Brotli HTTP"
	case modeBrotliTokenizedHTTPS:
		return "dictionary+Brotli HTTPS"
	case modeBrotliTokenizedHTTP:
		return "dictionary+Brotli HTTP"
	default:
		return fmt.Sprintf("unknown Brotli mode %q", mode)
	}
}
