package main

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	// Unicode token v1 uses normalization-stable CJK Unified Ideographs as a
	// base-65536 alphabet. Each payload rune carries 16 bits, versus 6 bits in
	// Base64URL, so eight ASCII token characters become three Unicode symbols.
	// The eight headers encode the original token length modulo eight.
	unicodeTokenHeaderBaseV1  rune = 0x3400 // U+3400..U+3407.
	unicodeTokenHeaderCountV1      = 8

	// These three ranges contain exactly 65,536 assigned CJK Unified
	// Ideographs. They are letters with no decomposition, combining, bidi
	// control, whitespace, or URL-delimiter behavior. Do not change these
	// ranges: their order is part of the v1 wire format.
	unicodeTokenPayloadAStartV1 rune = 0x3408
	unicodeTokenPayloadAEndV1   rune = 0x4dbf
	unicodeTokenPayloadBStartV1 rune = 0x4e00
	unicodeTokenPayloadBEndV1   rune = 0x9fff
	unicodeTokenPayloadCStartV1 rune = 0x20000
	unicodeTokenPayloadCEndV1   rune = 0x29447

	unicodeTokenPayloadACountV1 = int(unicodeTokenPayloadAEndV1-unicodeTokenPayloadAStartV1) + 1
	unicodeTokenPayloadBCountV1 = int(unicodeTokenPayloadBEndV1-unicodeTokenPayloadBStartV1) + 1
	unicodeTokenRadixV1         = 1 << 16
	unicodeTokenBitsV1          = 16
	unicodeTokenValueBitsV1     = 6

	// A raw token is bounded by maxCommandInputBytes. In the worst case its
	// base-65536 form uses four UTF-8 bytes for every 16 packed bits, or 3/2 as
	// many bytes as the six-bit ASCII form, plus one header rune.
	maxUnicodeRedirectTokenBytesV1 = maxCommandInputBytes*3/2 + utf8.UTFMax

	// Frozen mapping for the first/mode character of every existing raw wire
	// family: v1, v2, Brotli v3, SCSU v4, and Punycode+range v5.
	unicodeTokenModesV1 = "0123" + rangeMarkersV2 + ".-bcstpq"
)

var (
	errMalformedUnicodeToken = errors.New("malformed Unicode compressed token")
	errUnsupportedTokenMode  = errors.New("raw token mode cannot be represented by Unicode token v1")
)

// EncodeUnicodeTokenV1 converts an existing canonical ASCII SRL token into a
// much shorter sequence of visible Unicode code points. It does not alter the
// underlying compression format or URL bytes.
func EncodeUnicodeTokenV1(token string) (string, error) {
	if len(token) < 2 {
		return "", errMalformedUnicodeToken
	}
	if len(token) > maxCommandInputBytes {
		return "", errTokenTooLarge
	}
	mode := strings.IndexByte(unicodeTokenModesV1, token[0])
	if mode < 0 {
		return "", errUnsupportedTokenMode
	}

	bitLength := len(token) * unicodeTokenValueBitsV1
	digitCount := (bitLength + unicodeTokenBitsV1 - 1) / unicodeTokenBitsV1

	var output strings.Builder
	output.Grow((digitCount + 1) * utf8.UTFMax)
	output.WriteRune(unicodeTokenHeaderBaseV1 + rune(len(token)%unicodeTokenHeaderCountV1))

	var accumulator uint64
	bits := 0
	for i := 0; i < len(token); i++ {
		value := mode
		if i > 0 {
			value = strings.IndexByte(base64URLAlphabet, token[i])
			if value < 0 {
				return "", errMalformedUnicodeToken
			}
		}
		accumulator = (accumulator << unicodeTokenValueBitsV1) | uint64(value)
		bits += unicodeTokenValueBitsV1
		for bits >= unicodeTokenBitsV1 {
			shift := bits - unicodeTokenBitsV1
			digit := (accumulator >> shift) & (unicodeTokenRadixV1 - 1)
			output.WriteRune(unicodeTokenRuneV1(uint16(digit)))
			bits -= unicodeTokenBitsV1
			accumulator &= lowBitsMaskV1(bits)
		}
	}
	if bits > 0 {
		digit := (accumulator << (unicodeTokenBitsV1 - bits)) & (unicodeTokenRadixV1 - 1)
		output.WriteRune(unicodeTokenRuneV1(uint16(digit)))
	}
	return output.String(), nil
}

// DecodeUnicodeTokenV1 restores the exact ASCII SRL token wrapped by
// EncodeUnicodeTokenV1 and rejects noncanonical spellings/padding.
func DecodeUnicodeTokenV1(encoded string) (string, error) {
	header, headerSize := utf8.DecodeRuneInString(encoded)
	if header == utf8.RuneError || headerSize == 0 || header < unicodeTokenHeaderBaseV1 || header >= unicodeTokenHeaderBaseV1+unicodeTokenHeaderCountV1 {
		return "", errMalformedUnicodeToken
	}
	lengthRemainder := int(header - unicodeTokenHeaderBaseV1)
	payload := encoded[headerSize:]
	if payload == "" || len(payload) > maxUnicodeRedirectTokenBytesV1 {
		return "", errMalformedUnicodeToken
	}

	digitCount := 0
	for _, r := range payload {
		if _, ok := unicodeTokenValueV1(r); !ok {
			return "", errMalformedUnicodeToken
		}
		digitCount++
	}
	meaningfulRemainders := [...]int{0, 6, 12, 2, 8, 14, 4, 10}
	meaningfulTailBits := meaningfulRemainders[lengthRemainder]
	padding := 0
	if meaningfulTailBits != 0 {
		padding = unicodeTokenBitsV1 - meaningfulTailBits
	}
	totalBits := digitCount*unicodeTokenBitsV1 - padding
	if totalBits < unicodeTokenValueBitsV1*2 || totalBits%unicodeTokenValueBitsV1 != 0 {
		return "", errMalformedUnicodeToken
	}
	tokenLength := totalBits / unicodeTokenValueBitsV1
	if tokenLength%unicodeTokenHeaderCountV1 != lengthRemainder {
		return "", errMalformedUnicodeToken
	}
	if tokenLength > maxCommandInputBytes {
		return "", errTokenTooLarge
	}

	var token strings.Builder
	token.Grow(tokenLength)
	var accumulator uint64
	bits := 0
	emitted := 0
	for _, r := range payload {
		mapped, _ := unicodeTokenValueV1(r)
		value := uint64(mapped)
		accumulator = (accumulator << unicodeTokenBitsV1) | value
		bits += unicodeTokenBitsV1
		for bits >= unicodeTokenValueBitsV1 && emitted < tokenLength {
			shift := bits - unicodeTokenValueBitsV1
			value := byte((accumulator >> shift) & 0x3f)
			if emitted == 0 {
				if int(value) >= len(unicodeTokenModesV1) {
					return "", errMalformedUnicodeToken
				}
				token.WriteByte(unicodeTokenModesV1[value])
			} else {
				token.WriteByte(base64URLAlphabet[value])
			}
			emitted++
			bits -= unicodeTokenValueBitsV1
			accumulator &= lowBitsMaskV1(bits)
		}
	}
	if emitted != tokenLength || bits != padding || accumulator != 0 {
		return "", errMalformedUnicodeToken
	}

	raw := token.String()
	canonical, err := EncodeUnicodeTokenV1(raw)
	if err != nil || canonical != encoded {
		return "", errMalformedUnicodeToken
	}
	return raw, nil
}

func isUnicodeTokenV1(input string) bool {
	r, size := utf8.DecodeRuneInString(input)
	return size > 0 && r >= unicodeTokenHeaderBaseV1 && r < unicodeTokenHeaderBaseV1+unicodeTokenHeaderCountV1
}

func unicodeTokenRuneV1(value uint16) rune {
	index := int(value)
	if index < unicodeTokenPayloadACountV1 {
		return unicodeTokenPayloadAStartV1 + rune(index)
	}
	index -= unicodeTokenPayloadACountV1
	if index < unicodeTokenPayloadBCountV1 {
		return unicodeTokenPayloadBStartV1 + rune(index)
	}
	return unicodeTokenPayloadCStartV1 + rune(index-unicodeTokenPayloadBCountV1)
}

func unicodeTokenValueV1(r rune) (uint16, bool) {
	switch {
	case r >= unicodeTokenPayloadAStartV1 && r <= unicodeTokenPayloadAEndV1:
		return uint16(r - unicodeTokenPayloadAStartV1), true
	case r >= unicodeTokenPayloadBStartV1 && r <= unicodeTokenPayloadBEndV1:
		return uint16(unicodeTokenPayloadACountV1 + int(r-unicodeTokenPayloadBStartV1)), true
	case r >= unicodeTokenPayloadCStartV1 && r <= unicodeTokenPayloadCEndV1:
		return uint16(unicodeTokenPayloadACountV1 + unicodeTokenPayloadBCountV1 + int(r-unicodeTokenPayloadCStartV1)), true
	default:
		return 0, false
	}
}

func lowBitsMaskV1(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	return (uint64(1) << bits) - 1
}
