package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	kflate "github.com/klauspost/compress/flate"
)

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

const (
	// A URL this large is already far beyond what browsers and most servers
	// accept. The limit also protects Decode from compressed-data bombs.
	maxURLBytes          = 1 << 20
	maxTokenizedBytes    = maxURLBytes * 2
	maxCommandInputBytes = maxURLBytes * 3

	// Each marker identifies both a representation and version 1 of its frozen
	// dictionary. New dictionary versions must use new markers so old tokens
	// remain decodable.
	// Digits are URL-safe, shell-safe, and cannot begin an absolute URL scheme,
	// so a pass-through URL can never be mistaken for a token.
	modeTokenized            byte = '0'
	modeDeflate              byte = '1'
	modeDeflateWithDict      byte = '2'
	modeTokenizedWithDeflate byte = '3'
)

var (
	errEmptyInput       = errors.New("input is empty")
	errInputTooLarge    = fmt.Errorf("input is larger than %d bytes", maxURLBytes)
	errDecodedTooLarge  = fmt.Errorf("decoded URL is larger than %d bytes", maxURLBytes)
	errTokenTooLarge    = fmt.Errorf("compressed link is larger than %d bytes", maxCommandInputBytes)
	errMalformedToken   = errors.New("malformed compressed link")
	errUnsupportedInput = errors.New("input is not an absolute http:// or https:// URL")
)

// dictionaryV1 is part of the on-disk/wire format. Do not reorder, remove, or
// change entries. Add a new version and new mode markers instead.
//
// Bytes 0x80..0xfe represent these entries. Byte 0xff escapes a literal
// non-ASCII byte. Ordinary ASCII bytes represent themselves.
var dictionaryV1 = [][]byte{
	[]byte("https://www."),
	[]byte("http://www."),
	[]byte("https://"),
	[]byte("http://"),
	[]byte(".me"),
	[]byte(".xyz"),
	[]byte("www."),
	[]byte(".com"),
	[]byte(".org"),
	[]byte(".net"),
	[]byte(".io"),
	[]byte(".co"),
	[]byte(".dev"),
	[]byte(".app"),
	[]byte(".ai"),
	[]byte(".edu"),
	[]byte(".gov"),
	[]byte(".uk"),
	[]byte(".in"),
	[]byte(".de"),
	[]byte(".jp"),
	[]byte(".fr"),
	[]byte(".ca"),
	[]byte(".au"),
	[]byte(".us"),
	[]byte("/api/"),
	[]byte("/v1/"),
	[]byte("/v2/"),
	[]byte("/v3/"),
	[]byte("/users/"),
	[]byte("/user/"),
	[]byte("/account/"),
	[]byte("/accounts/"),
	[]byte("/auth/"),
	[]byte("/oauth/"),
	[]byte("/callback"),
	[]byte("/login"),
	[]byte("/logout"),
	[]byte("/signin"),
	[]byte("/signup"),
	[]byte("/search"),
	[]byte("/watch"),
	[]byte("/view"),
	[]byte("/download"),
	[]byte("/uploads/"),
	[]byte("/images/"),
	[]byte("/static/"),
	[]byte("/assets/"),
	[]byte("/docs/"),
	[]byte("/products/"),
	[]byte("/product/"),
	[]byte("/category/"),
	[]byte("/collections/"),
	[]byte("/posts/"),
	[]byte("/blog/"),
	[]byte("/page/"),
	[]byte("/index.html"),
	[]byte(".html"),
	[]byte(".json"),
	[]byte(".php"),
	[]byte(".js"),
	[]byte(".css"),
	[]byte(".png"),
	[]byte(".jpg"),
	[]byte(".jpeg"),
	[]byte(".svg"),
	[]byte(".webp"),
	[]byte(".pdf"),
	[]byte(".zip"),
	[]byte("?utm_source="),
	[]byte("&utm_source="),
	[]byte("utm_medium="),
	[]byte("utm_campaign="),
	[]byte("utm_content="),
	[]byte("utm_term="),
	[]byte("?id="),
	[]byte("&id="),
	[]byte("?q="),
	[]byte("&q="),
	[]byte("?query="),
	[]byte("&query="),
	[]byte("?page="),
	[]byte("&page="),
	[]byte("?ref="),
	[]byte("&ref="),
	[]byte("?token="),
	[]byte("&token="),
	[]byte("?lang="),
	[]byte("&lang="),
	[]byte("?redirect="),
	[]byte("&redirect="),
	[]byte("?url="),
	[]byte("&url="),
	[]byte("%20"),
	[]byte("%2F"),
	[]byte("%2f"),
	[]byte("%3A"),
	[]byte("%3a"),
	[]byte("%3D"),
	[]byte("%3d"),
	[]byte("%26"),
	[]byte("%25"),
	[]byte("github.com"),
	[]byte("google.com"),
	[]byte("youtube.com"),
	[]byte("youtu.be"),
	[]byte("facebook.com"),
	[]byte("instagram.com"),
	[]byte("twitter.com"),
	[]byte("x.com"),
	[]byte("linkedin.com"),
	[]byte("wikipedia.org"),
	[]byte("amazon.com"),
	[]byte("microsoft.com"),
	[]byte("apple.com"),
	[]byte("cloudflare.com"),
	[]byte("openai.com"),
	[]byte("stackoverflow.com"),
	[]byte("reddit.com"),
	[]byte("medium.com"),
	[]byte("tiktok.com"),
	[]byte("discord.com"),
	[]byte("t.me"),
	[]byte("localhost"),
	[]byte("127.0.0.1"),
}

const commonURLCorpusV1 = "" +
	"https://www.google.com/search?q=example\n" +
	"https://github.com/users/example/projects\n" +
	"https://www.youtube.com/watch?v=example\n" +
	"https://en.wikipedia.org/wiki/Example\n" +
	"https://www.amazon.com/products/example?ref=example\n" +
	"https://api.example.com/v1/users/123.json\n" +
	"https://example.com/search?q=example&page=1&utm_source=example&utm_medium=web&utm_campaign=example\n" +
	"https://example.com/assets/images/example.webp\n" +
	"http://localhost:8080/api/v1/users?id=123\n" +
	"https%3A%2F%2Fwww.example.com%2Fcallback%3Ftoken%3Dexample"

type trieNode struct {
	children map[byte]int
	entry    int
}

type tokenChoice struct {
	entry  int
	length int
}

var (
	dictionaryTrieV1        = buildTrie(dictionaryV1)
	rawFlateDictionaryV1    = buildRawFlateDictionaryV1()
	tokenFlateDictionaryV1  = tokenizeV1([]byte(commonURLCorpusV1))
	compressionLevelsToTest = []int{
		flate.BestSpeed,
		4, 5, 7, 8,
	}
)

func buildTrie(entries [][]byte) []trieNode {
	if len(entries) > 127 {
		panic("URL dictionary has more than 127 entries")
	}

	nodes := []trieNode{{children: make(map[byte]int), entry: -1}}
	for entry, fragment := range entries {
		if len(fragment) < 2 {
			panic("URL dictionary entries must contain at least two bytes")
		}

		node := 0
		for _, b := range fragment {
			next, ok := nodes[node].children[b]
			if !ok {
				next = len(nodes)
				nodes[node].children[b] = next
				nodes = append(nodes, trieNode{children: make(map[byte]int), entry: -1})
			}
			node = next
		}
		if nodes[node].entry != -1 {
			panic("duplicate URL dictionary entry")
		}
		nodes[node].entry = entry
	}
	return nodes
}

func buildRawFlateDictionaryV1() []byte {
	var dictionary bytes.Buffer
	for _, fragment := range dictionaryV1 {
		dictionary.Write(fragment)
		dictionary.WriteByte(0)
	}
	dictionary.WriteString(commonURLCorpusV1)
	return dictionary.Bytes()
}

// tokenizeV1 uses dynamic programming, rather than a greedy replacement, so
// overlapping dictionary matches always produce the smallest token stream.
func tokenizeV1(input []byte) []byte {
	cost := make([]int, len(input)+1)
	choices := make([]tokenChoice, len(input))

	for i := len(input) - 1; i >= 0; i-- {
		literalCost := 1
		if input[i] >= 0x80 {
			literalCost = 2
		}
		cost[i] = literalCost + cost[i+1]
		choices[i] = tokenChoice{entry: -1, length: 1}

		node := 0
		for j := i; j < len(input); j++ {
			next, ok := dictionaryTrieV1[node].children[input[j]]
			if !ok {
				break
			}
			node = next
			entry := dictionaryTrieV1[node].entry
			if entry >= 0 && 1+cost[j+1] < cost[i] {
				cost[i] = 1 + cost[j+1]
				choices[i] = tokenChoice{entry: entry, length: j - i + 1}
			}
		}
	}

	output := make([]byte, 0, cost[0])
	for i := 0; i < len(input); {
		choice := choices[i]
		if choice.entry >= 0 {
			output = append(output, byte(0x80+choice.entry))
			i += choice.length
			continue
		}

		if input[i] >= 0x80 {
			output = append(output, 0xff)
		}
		output = append(output, input[i])
		i++
	}
	return output
}

func detokenizeV1(input []byte) ([]byte, error) {
	output := make([]byte, 0, len(input))
	for i := 0; i < len(input); i++ {
		b := input[i]
		switch {
		case b < 0x80:
			if len(output) == maxURLBytes {
				return nil, errDecodedTooLarge
			}
			output = append(output, b)
		case b == 0xff:
			i++
			if i == len(input) || input[i] < 0x80 {
				return nil, errMalformedToken
			}
			if len(output) == maxURLBytes {
				return nil, errDecodedTooLarge
			}
			output = append(output, input[i])
		default:
			entry := int(b - 0x80)
			if entry >= len(dictionaryV1) {
				return nil, errMalformedToken
			}
			fragment := dictionaryV1[entry]
			if len(output) > maxURLBytes-len(fragment) {
				return nil, errDecodedTooLarge
			}
			output = append(output, fragment...)
		}
	}
	return output, nil
}

// Encode returns the shortest self-contained representation this codec can
// produce. If the URL is already shorter than every encoded form, Encode
// returns it unchanged; Decode accepts that pass-through form too.
func Encode(link string) (string, error) {
	token, err := encodeShortestToken(link)
	if err != nil {
		return "", err
	}
	return shorter(link, token), nil
}

// encodeShortestToken returns the smallest self-contained ASCII token even
// when the source URL itself uses fewer bytes. The public Encode function
// retains its no-expansion guarantee, while the HTTP API can wrap this token
// in the Unicode display alphabet and compare visible characters separately.
func encodeShortestToken(link string) (string, error) {
	if err := validateURL(link); err != nil {
		return "", err
	}

	input := []byte(link)
	tokenized := tokenizeV1(input)
	best := makeToken(modeTokenized, tokenized)

	plainDeflate, err := bestDeflate(input, nil)
	if err != nil {
		return "", fmt.Errorf("compress URL: %w", err)
	}
	best = shorter(best, makeToken(modeDeflate, plainDeflate))

	dictionaryDeflate, err := bestDeflate(input, rawFlateDictionaryV1)
	if err != nil {
		return "", fmt.Errorf("compress URL with dictionary: %w", err)
	}
	best = shorter(best, makeToken(modeDeflateWithDict, dictionaryDeflate))

	tokenDeflate, err := bestDeflate(tokenized, tokenFlateDictionaryV1)
	if err != nil {
		return "", fmt.Errorf("compress tokenized URL: %w", err)
	}
	best = shorter(best, makeToken(modeTokenizedWithDeflate, tokenDeflate))
	if rangeToken, ok := encodeRangeURLV2(link); ok {
		best = shorter(best, rangeToken)
	}
	if brotliToken, ok, err := encodeBrotliURLV3(link); err != nil {
		return "", fmt.Errorf("compress URL with Brotli: %w", err)
	} else if ok {
		best = shorter(best, brotliToken)
	}
	if unicodeToken, ok, err := encodeUnicodeURLV4(link); err != nil {
		return "", fmt.Errorf("compress Unicode URL with SCSU: %w", err)
	} else if ok {
		best = shorter(best, unicodeToken)
	}
	if punycodeToken, ok, err := encodePunycodeURLV5(link); err != nil {
		return "", fmt.Errorf("compress Unicode URL with Punycode: %w", err)
	} else if ok {
		best = shorter(best, punycodeToken)
	}
	return best, nil
}

// Decode restores a token produced by Encode. An already-uncompressed absolute
// URL is returned unchanged, which is how Encode avoids expanding very short or
// high-entropy inputs.
func Decode(compressed string) (string, error) {
	if compressed == "" {
		return "", errEmptyInput
	}
	if isUnicodeTokenV1(compressed) {
		if len(compressed) > maxUnicodeRedirectTokenBytesV1 {
			return "", errTokenTooLarge
		}
		raw, err := DecodeUnicodeTokenV1(compressed)
		if err != nil {
			return "", fmt.Errorf("%w: Unicode token v1: %v", errMalformedToken, err)
		}
		return Decode(raw)
	}
	if len(compressed) > maxCommandInputBytes {
		return "", errTokenTooLarge
	}

	mode := compressed[0]
	if !isMode(mode) {
		if err := validateURL(compressed); err != nil {
			return "", fmt.Errorf("unknown compressed-link format: %w", err)
		}
		return compressed, nil
	}
	if markerIndex := rangeMarkerIndexV2(mode); markerIndex >= 0 {
		decoded, err := decodeRangeURLV2(compressed, markerIndex)
		if err != nil {
			return "", fmt.Errorf("%w: %v", errMalformedToken, err)
		}
		link := string(decoded)
		if err := validateURL(link); err != nil {
			return "", fmt.Errorf("%w: decoded value is not a URL", errMalformedToken)
		}
		return link, nil
	}
	if isBrotliModeV3(mode) {
		decoded, err := decodeBrotliURLV3(compressed)
		if err != nil {
			return "", fmt.Errorf("%w: %s: %v", errMalformedToken, brotliModeNameV3(mode), err)
		}
		link := string(decoded)
		if err := validateURL(link); err != nil {
			return "", fmt.Errorf("%w: decoded value is not a URL", errMalformedToken)
		}
		return link, nil
	}
	if isUnicodeModeV4(mode) {
		decoded, err := decodeUnicodeURLV4(compressed)
		if err != nil {
			return "", fmt.Errorf("%w: %s: %v", errMalformedToken, unicodeModeNameV4(mode), err)
		}
		link := string(decoded)
		if err := validateURL(link); err != nil {
			return "", fmt.Errorf("%w: decoded value is not a URL", errMalformedToken)
		}
		return link, nil
	}
	if isPunycodeModeV5(mode) {
		decoded, err := decodePunycodeURLV5(compressed)
		if err != nil {
			return "", fmt.Errorf("%w: %s: %v", errMalformedToken, punycodeModeNameV5(mode), err)
		}
		link := string(decoded)
		if err := validateURL(link); err != nil {
			return "", fmt.Errorf("%w: decoded value is not a URL", errMalformedToken)
		}
		return link, nil
	}

	encodedPayload := compressed[1:]
	if !isRawBase64URL(encodedPayload) {
		return "", errMalformedToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encodedPayload)
	if err != nil || len(payload) == 0 {
		return "", errMalformedToken
	}

	var decoded []byte
	switch mode {
	case modeTokenized:
		decoded, err = detokenizeV1(payload)
	case modeDeflate:
		decoded, err = inflate(payload, nil, maxURLBytes)
	case modeDeflateWithDict:
		decoded, err = inflate(payload, rawFlateDictionaryV1, maxURLBytes)
	case modeTokenizedWithDeflate:
		var tokenized []byte
		tokenized, err = inflate(payload, tokenFlateDictionaryV1, maxTokenizedBytes)
		if err == nil {
			decoded, err = detokenizeV1(tokenized)
		}
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", errMalformedToken, err)
	}

	link := string(decoded)
	if err := validateURL(link); err != nil {
		return "", fmt.Errorf("%w: decoded value is not a URL", errMalformedToken)
	}
	return link, nil
}

func validateURL(link string) error {
	if link == "" {
		return errEmptyInput
	}
	if len(link) > maxURLBytes {
		return errInputTooLarge
	}

	parsed, err := url.Parse(link)
	if err != nil || !parsed.IsAbs() {
		return errUnsupportedInput
	}

	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Hostname() == "" {
		return errUnsupportedInput
	}
	return nil
}

func isRawBase64URL(input string) bool {
	if input == "" {
		return false
	}
	for i := 0; i < len(input); i++ {
		b := input[i]
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') &&
			(b < '0' || b > '9') && b != '-' && b != '_' {
			return false
		}
	}
	return true
}

func makeToken(mode byte, payload []byte) string {
	encodedLen := base64.RawURLEncoding.EncodedLen(len(payload))
	output := make([]byte, 1+encodedLen)
	output[0] = mode
	base64.RawURLEncoding.Encode(output[1:], payload)
	return string(output)
}

func shorter(current, candidate string) string {
	if len(candidate) < len(current) {
		return candidate
	}
	return current
}

func isMode(mode byte) bool {
	if rangeMarkerIndexV2(mode) >= 0 || isBrotliModeV3(mode) || isUnicodeModeV4(mode) || isPunycodeModeV5(mode) {
		return true
	}
	switch mode {
	case modeTokenized, modeDeflate, modeDeflateWithDict, modeTokenizedWithDeflate:
		return true
	default:
		return false
	}
}

func bestDeflate(input, dictionary []byte) ([]byte, error) {
	var best []byte
	// These five levels cover every winning stream in the URL regression
	// corpus while avoiding dominated writer allocations at the other levels.
	for _, level := range compressionLevelsToTest {
		var buffer bytes.Buffer
		var writer *kflate.Writer
		var err error
		if dictionary == nil {
			writer, err = kflate.NewWriter(&buffer, level)
		} else {
			writer, err = kflate.NewWriterDict(&buffer, level, dictionary)
		}
		if err != nil {
			return nil, err
		}
		if _, err = writer.Write(input); err != nil {
			_ = writer.Close()
			return nil, err
		}
		if err = writer.Close(); err != nil {
			return nil, err
		}
		best = chooseCompressedBytes(best, buffer.Bytes())
	}
	return best, nil
}

func chooseCompressedBytes(current, candidate []byte) []byte {
	if current == nil || len(candidate) < len(current) ||
		(len(candidate) == len(current) && bytes.Compare(candidate, current) < 0) {
		return append(current[:0], candidate...)
	}
	return current
}

func inflate(input, dictionary []byte, limit int) ([]byte, error) {
	source := bytes.NewReader(input)
	var reader io.ReadCloser
	if dictionary == nil {
		reader = flate.NewReader(source)
	} else {
		reader = flate.NewReaderDict(source, dictionary)
	}

	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(decoded) > limit {
		return nil, errDecodedTooLarge
	}
	if source.Len() != 0 {
		return nil, errors.New("compressed link contains trailing data")
	}
	return decoded, nil
}

const usage = `Usage:
  srl encode <url>       compress a URL
  srl decode <token-or-redirect-url>
                         restore the original URL
  srl <url-or-token>      detect the input and convert it

If the value after encode or decode is omitted, it is read from standard input.
Short or incompressible URLs may be returned unchanged to avoid expansion.
`

func run(args []string, input io.Reader, output io.Writer) error {
	operation := "auto"
	var valueArgs []string

	if len(args) > 0 {
		switch args[0] {
		case "encode", "-e":
			operation = "encode"
			valueArgs = args[1:]
		case "decode", "-d":
			operation = "decode"
			valueArgs = args[1:]
		case "help", "-h", "--help":
			_, err := fmt.Fprint(output, usage)
			return err
		default:
			valueArgs = args
		}
	}

	value, err := commandValue(valueArgs, input)
	if err != nil {
		return err
	}

	var result string
	switch operation {
	case "decode":
		result, err = decodeCommandValue(value)
	case "encode":
		result, err = Encode(value)
	default:
		if token, matched, redirectErr := redirectTokenFromURL(value); matched && redirectErr == nil {
			if decoded, decodeErr := Decode(token); decodeErr == nil {
				result = decoded
				break
			}
		}
		if validateURL(value) == nil {
			result, err = Encode(value)
		} else {
			result, err = Decode(value)
		}
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, result)
	return err
}

// decodeCommandValue accepts either a raw self-contained token or the complete
// clickable URL produced by the SRL server. Decode itself intentionally keeps
// treating ordinary HTTP(S) URLs as pass-through values.
func decodeCommandValue(value string) (string, error) {
	token, matched, err := redirectTokenFromURL(value)
	if err != nil {
		return "", err
	}
	if matched {
		return Decode(token)
	}
	return Decode(value)
}

func redirectTokenFromURL(value string) (string, bool, error) {
	if validateURL(value) != nil {
		return "", false, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || !strings.HasPrefix(parsed.Path, "/r/") ||
		!strings.HasPrefix(parsed.EscapedPath(), "/r/") {
		return "", false, nil
	}
	token := strings.TrimPrefix(parsed.Path, "/r/")
	if token == "" || strings.Contains(token, "/") {
		return "", false, nil
	}
	isUnicode := isUnicodeTokenV1(token)
	if !isUnicode && !isMode(token[0]) {
		return "", false, nil
	}
	if parsed.User != nil {
		return "", true, errors.New("SRL redirect URL must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return "", true, errors.New("SRL redirect URL must not contain a query or fragment")
	}
	if !isUnicode && parsed.EscapedPath() != parsed.Path {
		return "", true, errors.New("ASCII SRL redirect tokens must not be percent-encoded")
	}
	return token, true, nil
}

func commandValue(args []string, input io.Reader) (string, error) {
	if len(args) > 1 {
		return "", errors.New("expected exactly one URL or token; quote shell-special characters")
	}
	if len(args) == 1 {
		return args[0], nil
	}

	data, err := io.ReadAll(io.LimitReader(input, maxCommandInputBytes+1))
	if err != nil {
		return "", fmt.Errorf("read standard input: %w", err)
	}
	if len(data) > maxCommandInputBytes {
		return "", errInputTooLarge
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	if len(data) == 0 {
		return "", errEmptyInput
	}
	return string(data), nil
}

func main() {
	err := run(os.Args[1:], os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
