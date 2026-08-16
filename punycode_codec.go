package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	// V5 first applies raw RFC 3492 Punycode to the complete suffix after the
	// lowercase scheme, then feeds those ASCII bytes to the frozen v2 range
	// models. Unlike IDNA, this transform is not limited to domain labels, so it
	// preserves Unicode in paths, queries, and fragments as well as host names.
	modePunycodeHTTPSV5 byte = 'p'
	modePunycodeHTTPV5  byte = 'q'

	// Punycode decoding inserts code points into the result. Keep that work
	// tightly bounded for untrusted redirect tokens; larger URLs still use the
	// other lossless codec candidates.
	maximumPunycodeRunesV5 = 4096
	maximumPunycodeBytesV5 = 64 << 10

	punycodeBaseV5        int64 = 36
	punycodeDampV5        int64 = 700
	punycodeInitialBiasV5 int64 = 72
	punycodeInitialNV5    int64 = 128
	punycodeSkewV5        int64 = 38
	punycodeTMaxV5        int64 = 26
	punycodeTMinV5        int64 = 1
)

var (
	errPunycodeMalformedV5 = errors.New("malformed RFC 3492 Punycode")
	errPunycodeLimitV5     = errors.New("Punycode candidate exceeds its safety limit")
)

func encodePunycodeURLV5(link string) (string, bool, error) {
	var mode byte
	var suffix string
	switch {
	case strings.HasPrefix(link, "https://"):
		mode = modePunycodeHTTPSV5
		suffix = link[len("https://"):]
	case strings.HasPrefix(link, "http://"):
		mode = modePunycodeHTTPV5
		suffix = link[len("http://"):]
	default:
		return "", false, nil
	}

	if !utf8.ValidString(suffix) || isASCIIStringV5(suffix) || utf8.RuneCountInString(suffix) > maximumPunycodeRunesV5 {
		return "", false, nil
	}
	punycode, err := encodeRawPunycodeV5(suffix)
	if errors.Is(err, errPunycodeLimitV5) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}

	raw := makePunycodeRangeTokenV5(mode, prependSelectorV2(false, encodeRangeSuffixV2(punycode, false)))
	withDictionary := makePunycodeRangeTokenV5(mode, prependSelectorV2(true, encodeRangeSuffixV2(punycode, true)))
	if len(withDictionary) < len(raw) {
		return withDictionary, true, nil
	}
	return raw, true, nil
}

func isASCIIStringV5(input string) bool {
	for i := 0; i < len(input); i++ {
		if input[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func makePunycodeRangeTokenV5(mode byte, bits packedBitsV2) string {
	output := make([]byte, 1, 1+(bits.length+5)/6)
	output[0] = mode
	for position := 0; position < bits.length; position += 6 {
		value := 0
		for offset := 0; offset < 6; offset++ {
			value = (value << 1) | int(bits.at(position+offset))
		}
		output = append(output, base64URLAlphabet[value])
	}
	return string(output)
}

func punycodeRangeTokenBitsV5(payload string) (packedBitsV2, error) {
	if payload == "" {
		return packedBitsV2{}, errMalformedToken
	}
	var bits packedBitsV2
	for i := 0; i < len(payload); i++ {
		value := strings.IndexByte(base64URLAlphabet, payload[i])
		if value < 0 {
			return packedBitsV2{}, errMalformedToken
		}
		for shift := 5; shift >= 0; shift-- {
			bits.write(uint64((value >> shift) & 1))
		}
	}
	return bits, nil
}

func decodePunycodeURLV5(token string) ([]byte, error) {
	if len(token) < 2 || !isPunycodeModeV5(token[0]) {
		return nil, errMalformedToken
	}
	bits, err := punycodeRangeTokenBitsV5(token[1:])
	if err != nil {
		return nil, err
	}
	punycode, err := decodePunycodeRangePayloadV5(bits)
	if err != nil {
		return nil, err
	}
	suffix, err := decodeRawPunycodeV5(punycode)
	if err != nil {
		return nil, err
	}

	prefix := "https://"
	if token[0] == modePunycodeHTTPV5 {
		prefix = "http://"
	}
	if len(suffix) > maxURLBytes-len(prefix) {
		return nil, errDecodedTooLarge
	}
	link := append([]byte(prefix), suffix...)

	// Both Punycode and arithmetic coding have representations that can decode
	// through extra padding or aliases. Only the one emitted by this version is
	// accepted, keeping every URL-to-token mapping unique.
	canonical, ok, encodeErr := encodePunycodeURLV5(string(link))
	if encodeErr != nil || !ok || !bytes.Equal([]byte(canonical), []byte(token)) {
		return nil, errors.New("noncanonical or corrupt v5 Punycode compressed link")
	}
	return link, nil
}

func decodePunycodeRangePayloadV5(bits packedBitsV2) ([]byte, error) {
	useDictionary := bits.at(0) == 1
	decoder := newArithmeticDecoderV2(sliceBitsV2(bits, 1))
	models := rangeModelsRawV2
	if useDictionary {
		models = rangeModelsWithDictionaryV2
	}

	context := contextAuthorityV2
	output := make([]byte, 0, len(bits.data))
	for len(output) <= maximumPunycodeBytesV5 {
		symbol, err := decoder.decode(models[context])
		if err != nil {
			return nil, err
		}
		if decoder.position > decoder.bits.length+32 {
			return nil, errors.New("truncated v5 arithmetic stream")
		}
		if symbol == eofSymbolV2(useDictionary) {
			return output, nil
		}

		if symbol < 256 {
			output = append(output, byte(symbol))
			context = advanceContextV2(context, byte(symbol))
			continue
		}
		if !useDictionary {
			return nil, errMalformedToken
		}
		entry := symbol - 256
		if entry < 0 || entry >= len(dictionaryV2) {
			return nil, errMalformedToken
		}
		fragment := dictionaryV2[entry]
		if len(output) > maximumPunycodeBytesV5-len(fragment) {
			return nil, errDecodedTooLarge
		}
		output = append(output, fragment...)
		for _, b := range fragment {
			context = advanceContextV2(context, b)
		}
	}
	return nil, errDecodedTooLarge
}

func isPunycodeModeV5(mode byte) bool {
	return mode == modePunycodeHTTPSV5 || mode == modePunycodeHTTPV5
}

func punycodeModeNameV5(mode byte) string {
	switch mode {
	case modePunycodeHTTPSV5:
		return "Punycode+range HTTPS"
	case modePunycodeHTTPV5:
		return "Punycode+range HTTP"
	default:
		return fmt.Sprintf("unknown Punycode mode %q", mode)
	}
}

// encodeRawPunycodeV5 implements RFC 3492 section 6.3 for one unrestricted
// Unicode string. It deliberately performs no IDNA mapping or normalization.
func encodeRawPunycodeV5(input string) ([]byte, error) {
	if !utf8.ValidString(input) {
		return nil, errPunycodeMalformedV5
	}
	runes := []rune(input)
	if len(runes) > maximumPunycodeRunesV5 {
		return nil, errPunycodeLimitV5
	}
	output := make([]byte, 0, len(input))
	var basic, remaining int64
	for _, r := range runes {
		if r < utf8.RuneSelf {
			output = append(output, byte(r))
			basic++
		} else {
			remaining++
		}
	}
	if basic > 0 {
		output = append(output, '-')
	}

	delta, n, bias := int64(0), punycodeInitialNV5, punycodeInitialBiasV5
	h := basic
	for remaining > 0 {
		m := int64(utf8.MaxRune) + 1
		for _, r := range runes {
			value := int64(r)
			if value >= n && value < m {
				m = value
			}
		}
		if m > utf8.MaxRune || m-n > (math.MaxInt64-delta)/(h+1) {
			return nil, errPunycodeMalformedV5
		}
		delta += (m - n) * (h + 1)
		n = m

		for _, r := range runes {
			value := int64(r)
			if value < n {
				if delta == math.MaxInt64 {
					return nil, errPunycodeMalformedV5
				}
				delta++
				continue
			}
			if value != n {
				continue
			}

			q := delta
			for k := punycodeBaseV5; ; k += punycodeBaseV5 {
				t := punycodeThresholdV5(k, bias)
				if q < t {
					break
				}
				if len(output) == maximumPunycodeBytesV5 {
					return nil, errPunycodeLimitV5
				}
				output = append(output, encodePunycodeDigitV5(t+(q-t)%(punycodeBaseV5-t)))
				q = (q - t) / (punycodeBaseV5 - t)
			}
			if len(output) == maximumPunycodeBytesV5 {
				return nil, errPunycodeLimitV5
			}
			output = append(output, encodePunycodeDigitV5(q))
			bias = adaptPunycodeBiasV5(delta, h+1, h == basic)
			delta = 0
			h++
			remaining--
		}
		if remaining > 0 {
			if delta == math.MaxInt64 || n == utf8.MaxRune {
				return nil, errPunycodeMalformedV5
			}
			delta++
			n++
		}
	}
	return output, nil
}

// decodeRawPunycodeV5 implements RFC 3492 section 6.2 and rejects outputs
// beyond the v5 resource limits before allocating an unbounded result.
func decodeRawPunycodeV5(input []byte) (string, error) {
	if len(input) > maximumPunycodeBytesV5 {
		return "", errPunycodeLimitV5
	}
	for _, b := range input {
		if b >= utf8.RuneSelf {
			return "", errPunycodeMalformedV5
		}
	}

	delimiter := bytes.LastIndexByte(input, '-')
	position := 0
	output := make([]rune, 0, len(input))
	outputBytes := 0
	if delimiter >= 0 {
		if delimiter == 0 {
			return "", errPunycodeMalformedV5
		}
		if delimiter > maximumPunycodeRunesV5 {
			return "", errPunycodeLimitV5
		}
		for _, b := range input[:delimiter] {
			output = append(output, rune(b))
		}
		outputBytes = delimiter
		position = delimiter + 1
	}

	i, n, bias := int64(0), punycodeInitialNV5, punycodeInitialBiasV5
	for position < len(input) {
		oldI, weight := i, int64(1)
		for k := punycodeBaseV5; ; k += punycodeBaseV5 {
			if position == len(input) {
				return "", errPunycodeMalformedV5
			}
			digit, ok := decodePunycodeDigitV5(input[position])
			if !ok || digit > (math.MaxInt64-i)/weight {
				return "", errPunycodeMalformedV5
			}
			position++
			i += digit * weight
			t := punycodeThresholdV5(k, bias)
			if digit < t {
				break
			}
			factor := punycodeBaseV5 - t
			if weight > math.MaxInt64/factor {
				return "", errPunycodeMalformedV5
			}
			weight *= factor
		}

		if len(output) == maximumPunycodeRunesV5 {
			return "", errPunycodeLimitV5
		}
		points := int64(len(output) + 1)
		bias = adaptPunycodeBiasV5(i-oldI, points, oldI == 0)
		increment := i / points
		if increment > int64(utf8.MaxRune)-n {
			return "", errPunycodeMalformedV5
		}
		n += increment
		decodedRune := rune(n)
		if !utf8.ValidRune(decodedRune) {
			return "", errPunycodeMalformedV5
		}
		i %= points
		runeBytes := utf8.RuneLen(decodedRune)
		if runeBytes < 0 || outputBytes > maxURLBytes-runeBytes {
			return "", errDecodedTooLarge
		}
		outputBytes += runeBytes

		index := int(i)
		output = append(output, 0)
		copy(output[index+1:], output[index:])
		output[index] = decodedRune
		i++
	}
	return string(output), nil
}

func punycodeThresholdV5(k, bias int64) int64 {
	switch {
	case k <= bias:
		return punycodeTMinV5
	case k >= bias+punycodeTMaxV5:
		return punycodeTMaxV5
	default:
		return k - bias
	}
}

func encodePunycodeDigitV5(digit int64) byte {
	switch {
	case digit >= 0 && digit < 26:
		return byte(digit + 'a')
	case digit >= 26 && digit < punycodeBaseV5:
		return byte(digit + ('0' - 26))
	default:
		panic("Punycode digit is outside base 36")
	}
}

func decodePunycodeDigitV5(input byte) (int64, bool) {
	switch {
	case input >= '0' && input <= '9':
		return int64(input - ('0' - 26)), true
	case input >= 'A' && input <= 'Z':
		return int64(input - 'A'), true
	case input >= 'a' && input <= 'z':
		return int64(input - 'a'), true
	default:
		return 0, false
	}
}

func adaptPunycodeBiasV5(delta, points int64, first bool) int64 {
	if first {
		delta /= punycodeDampV5
	} else {
		delta /= 2
	}
	delta += delta / points
	k := int64(0)
	for delta > ((punycodeBaseV5-punycodeTMinV5)*punycodeTMaxV5)/2 {
		delta /= punycodeBaseV5 - punycodeTMinV5
		k += punycodeBaseV5
	}
	return k + (punycodeBaseV5-punycodeTMinV5+1)*delta/(delta+punycodeSkewV5)
}
