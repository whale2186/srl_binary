package main

import (
	"bytes"
	"errors"
	"math"
	"sort"
	"strings"
)

// V2 uses 32 markers. The marker index stores one scheme bit and the first
// four arithmetic-coded bits, so the format itself costs only two bits. These
// characters exclude h/H (the only possible first byte of a pass-through URL)
// and the frozen v1 markers 0..3.
const rangeMarkersV2 = "456789ABCDEFGIJKLMNOPQRSTUVWXYZ_"

const (
	contextAuthorityV2 = iota
	contextPathV2
	contextQueryV2
	contextFragmentV2
	contextCountV2
)

const (
	arithmeticTopV2          uint64 = 0xffffffff
	arithmeticFirstQuarterV2 uint64 = 0x40000000
	arithmeticHalfV2         uint64 = 0x80000000
	arithmeticThirdQuarterV2 uint64 = 0xc0000000
	probabilityScaleV2              = 1024
)

// This corpus and all weighting below are part of the frozen v2 wire format.
// They model URL syntax and character distributions, not a lookup database.
// Changing any value requires a new marker family.
var trainingSuffixesV2 = []string{
	"example.com",
	"www.example.com/path/to/resource",
	"api.example.com/v1/users/123?active=true&format=json",
	"subdomain.example.org/articles/2026/08/title-of-article",
	"store.example.net/products/category/item?id=12345&currency=usd",
	"docs.example.dev/guides/getting-started/index.html#installation",
	"assets.example.io/static/images/photo.webp?width=1200&height=800",
	"service.example.app/oauth/callback?code=abcdef&state=123456",
	"research.example.edu/publications/paper.pdf",
	"department.example.gov/api/v2/search?q=public+records&page=2",
	"independent.photography/galleries/landscape/summer-collection",
	"community.museum/exhibitions/archive/ancient-history",
	"engineering.technology/projects/open-source/releases/latest",
	"long-unfamiliar-domain-name.xyz/a/b/c?first=value&second=value",
	"news.ycombinator.com/item?id=12345678",
	"xn--r8jz45g.xn--zckzah/%E6%97%A5%E6%9C%AC%E8%AA%9E",
	"localhost:3000/api/v1/health?verbose=false",
	"127.0.0.1:8080/debug/status",
	"[2001:db8::1]:8443/api/v3/resources?page=1",
	"user:p%40ss@host.example:080/path?flag&x=&x=1",
}

// dictionaryAdditionsV2 favors generic URL grammar, public suffixes, common
// host roles, and reusable language fragments. It deliberately does not need
// to know a site's full domain name.
var dictionaryAdditionsV2 = []string{
	".photography", ".technology", ".solutions", ".museum", ".online",
	".website", ".store", ".shop", ".cloud", ".digital", ".agency",
	".media", ".news", ".live", ".world", ".info", ".biz", ".name",
	".pro", ".mobi", ".travel", ".space", ".tech", ".social",
	".network", ".services", ".systems", ".software", ".company",
	".center", ".international", ".email", ".life", ".today",
	".co.uk", ".org.uk", ".com.au", ".co.jp", ".co.in", ".com.br",
	".co.nz", "api.", "app.", "docs.", "blog.", "shop.", "store.",
	"cdn.", "static.", "assets.", "media.", "news.", "support.",
	"help.", "dev.", "staging.",
	"/health", "/settings", "/profile", "/preferences", "/notifications",
	"/resources/", "/articles/", "/releases/", "/projects/", "/gallery/",
	"/galleries/", "/exhibitions/", "/archive/", "/history/", "/latest",
	"/getting-started", "notification=", "platform=", "format=", "active=",
	"verbose=", "width=", "height=", "currency=", "sort=", "filter=",
	"true", "false", "null", "latest", "linux", "windows", "android",
	"tion", "ing", "ment", "able", "ance", "ence", "ally", "ious",
	"ology", "graph", "photo", "tech", "solution", "service", "system",
	"software", "project", "source", "release", "customer", "preference",
	"notification", "community", "engineer", "independent", "gallery",
	"landscape", "summer", "collection", "archive", "history", "exhibition",
	"account", "setting", "profile", "resource", "article", "category",
	"search", "example", "domain", "company", "public", "private",
}

var (
	dictionaryV2     = buildDictionaryV2()
	dictionaryTrieV2 = buildTrieV2(dictionaryV2)
)

func buildDictionaryV2() [][]byte {
	dictionary := make([][]byte, 0, len(dictionaryV1)+len(dictionaryAdditionsV2))
	for _, fragment := range dictionaryV1 {
		dictionary = append(dictionary, append([]byte(nil), fragment...))
	}
	for _, fragment := range dictionaryAdditionsV2 {
		dictionary = append(dictionary, []byte(fragment))
	}
	return dictionary
}

func buildTrieV2(entries [][]byte) []trieNode {
	nodes := []trieNode{{children: make(map[byte]int), entry: -1}}
	for entry, fragment := range entries {
		if len(fragment) < 2 {
			panic("v2 URL dictionary entries must contain at least two bytes")
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
			panic("duplicate v2 URL dictionary entry: " + string(fragment))
		}
		nodes[node].entry = entry
	}
	return nodes
}

type rangeModelV2 struct {
	cumulative []uint32
	total      uint32
	cost       []uint32
}

type symbolChoiceV2 struct {
	entry  int
	length int
}

type packedBitsV2 struct {
	data   []byte
	length int
}

func (b *packedBitsV2) write(bit uint64) {
	if b.length%8 == 0 {
		b.data = append(b.data, 0)
	}
	if bit&1 != 0 {
		b.data[len(b.data)-1] |= 1 << (7 - uint(b.length%8))
	}
	b.length++
}

func (b packedBitsV2) at(position int) uint64 {
	if position < 0 || position >= b.length {
		return 0
	}
	return uint64((b.data[position/8] >> (7 - uint(position%8))) & 1)
}

type arithmeticEncoderV2 struct {
	low       uint64
	high      uint64
	following int
	bits      packedBitsV2
}

func newArithmeticEncoderV2() *arithmeticEncoderV2 {
	return &arithmeticEncoderV2{high: arithmeticTopV2}
}

func (e *arithmeticEncoderV2) encode(symbol int, model rangeModelV2) {
	span := e.high - e.low + 1
	e.high = e.low + span*uint64(model.cumulative[symbol+1])/uint64(model.total) - 1
	e.low += span * uint64(model.cumulative[symbol]) / uint64(model.total)

	for {
		switch {
		case e.high < arithmeticHalfV2:
			e.emitWithFollowing(0)
		case e.low >= arithmeticHalfV2:
			e.emitWithFollowing(1)
			e.low -= arithmeticHalfV2
			e.high -= arithmeticHalfV2
		case e.low >= arithmeticFirstQuarterV2 && e.high < arithmeticThirdQuarterV2:
			e.following++
			e.low -= arithmeticFirstQuarterV2
			e.high -= arithmeticFirstQuarterV2
		default:
			return
		}
		e.low <<= 1
		e.high = (e.high << 1) | 1
	}
}

func (e *arithmeticEncoderV2) emitWithFollowing(bit uint64) {
	e.bits.write(bit)
	for e.following > 0 {
		e.bits.write(bit ^ 1)
		e.following--
	}
}

func (e *arithmeticEncoderV2) finish() packedBitsV2 {
	e.following++
	if e.low < arithmeticFirstQuarterV2 {
		e.emitWithFollowing(0)
	} else {
		e.emitWithFollowing(1)
	}
	return e.bits
}

type arithmeticDecoderV2 struct {
	low      uint64
	high     uint64
	value    uint64
	bits     packedBitsV2
	position int
}

func newArithmeticDecoderV2(bits packedBitsV2) *arithmeticDecoderV2 {
	d := &arithmeticDecoderV2{high: arithmeticTopV2, bits: bits}
	for i := 0; i < 32; i++ {
		d.value = (d.value << 1) | d.read()
	}
	return d
}

func (d *arithmeticDecoderV2) decode(model rangeModelV2) (int, error) {
	if d.value < d.low || d.value > d.high {
		return 0, errors.New("arithmetic value is outside the current interval")
	}
	span := d.high - d.low + 1
	scaled := ((d.value-d.low+1)*uint64(model.total) - 1) / span
	if scaled >= uint64(model.total) {
		return 0, errors.New("arithmetic value is outside the probability model")
	}

	symbol := sort.Search(len(model.cumulative)-1, func(i int) bool {
		return uint64(model.cumulative[i+1]) > scaled
	})
	if symbol >= len(model.cumulative)-1 {
		return 0, errors.New("arithmetic symbol is outside the probability model")
	}

	d.high = d.low + span*uint64(model.cumulative[symbol+1])/uint64(model.total) - 1
	d.low += span * uint64(model.cumulative[symbol]) / uint64(model.total)
	for {
		switch {
		case d.high < arithmeticHalfV2:
		case d.low >= arithmeticHalfV2:
			d.value -= arithmeticHalfV2
			d.low -= arithmeticHalfV2
			d.high -= arithmeticHalfV2
		case d.low >= arithmeticFirstQuarterV2 && d.high < arithmeticThirdQuarterV2:
			d.value -= arithmeticFirstQuarterV2
			d.low -= arithmeticFirstQuarterV2
			d.high -= arithmeticFirstQuarterV2
		default:
			return symbol, nil
		}
		d.low <<= 1
		d.high = (d.high << 1) | 1
		d.value = (d.value << 1) | d.read()
	}
}

func (d *arithmeticDecoderV2) read() uint64 {
	bit := d.bits.at(d.position)
	d.position++
	return bit
}

var (
	rangeModelsRawV2            = buildRangeModelsV2(false)
	rangeModelsWithDictionaryV2 = buildRangeModelsV2(true)
)

func eofSymbolV2(useDictionary bool) int {
	if useDictionary {
		return 256 + len(dictionaryV2)
	}
	return 256
}

func buildRangeModelsV2(useDictionary bool) [contextCountV2]rangeModelV2 {
	symbolCount := eofSymbolV2(useDictionary) + 1
	frequencies := [contextCountV2][]uint32{}
	for context := 0; context < contextCountV2; context++ {
		frequencies[context] = make([]uint32, symbolCount)
		for symbol := range frequencies[context] {
			frequencies[context][symbol] = 1
		}
	}

	for b := byte('a'); b <= 'z'; b++ {
		frequencies[contextAuthorityV2][b] += 24
		frequencies[contextPathV2][b] += 14
		frequencies[contextQueryV2][b] += 14
		frequencies[contextFragmentV2][b] += 12
	}
	for b := byte('A'); b <= 'Z'; b++ {
		frequencies[contextAuthorityV2][b] += 3
		frequencies[contextPathV2][b] += 4
		frequencies[contextQueryV2][b] += 3
		frequencies[contextFragmentV2][b] += 4
	}
	for b := byte('0'); b <= '9'; b++ {
		frequencies[contextAuthorityV2][b] += 12
		frequencies[contextPathV2][b] += 12
		frequencies[contextQueryV2][b] += 16
		frequencies[contextFragmentV2][b] += 10
	}

	addByteWeightV2(frequencies[contextAuthorityV2], '.', 110)
	addByteWeightV2(frequencies[contextAuthorityV2], '-', 45)
	addByteWeightV2(frequencies[contextAuthorityV2], ':', 24)
	addByteWeightV2(frequencies[contextAuthorityV2], '/', 80)
	addByteWeightV2(frequencies[contextAuthorityV2], '?', 30)
	addByteWeightV2(frequencies[contextAuthorityV2], '#', 12)
	addByteWeightV2(frequencies[contextAuthorityV2], '[', 8)
	addByteWeightV2(frequencies[contextAuthorityV2], ']', 8)
	addByteWeightV2(frequencies[contextAuthorityV2], '@', 8)

	addByteWeightV2(frequencies[contextPathV2], '/', 120)
	addByteWeightV2(frequencies[contextPathV2], '-', 55)
	addByteWeightV2(frequencies[contextPathV2], '_', 38)
	addByteWeightV2(frequencies[contextPathV2], '.', 44)
	addByteWeightV2(frequencies[contextPathV2], '%', 32)
	addByteWeightV2(frequencies[contextPathV2], '?', 65)
	addByteWeightV2(frequencies[contextPathV2], '#', 20)

	addByteWeightV2(frequencies[contextQueryV2], '=', 120)
	addByteWeightV2(frequencies[contextQueryV2], '&', 95)
	addByteWeightV2(frequencies[contextQueryV2], '%', 50)
	addByteWeightV2(frequencies[contextQueryV2], '+', 34)
	addByteWeightV2(frequencies[contextQueryV2], '_', 45)
	addByteWeightV2(frequencies[contextQueryV2], '-', 34)
	addByteWeightV2(frequencies[contextQueryV2], '.', 24)
	addByteWeightV2(frequencies[contextQueryV2], '/', 20)
	addByteWeightV2(frequencies[contextQueryV2], ':', 15)
	addByteWeightV2(frequencies[contextQueryV2], '#', 25)

	addByteWeightV2(frequencies[contextFragmentV2], '/', 55)
	addByteWeightV2(frequencies[contextFragmentV2], '-', 40)
	addByteWeightV2(frequencies[contextFragmentV2], '_', 30)
	addByteWeightV2(frequencies[contextFragmentV2], '.', 25)
	addByteWeightV2(frequencies[contextFragmentV2], '=', 15)
	addByteWeightV2(frequencies[contextFragmentV2], '&', 12)

	for _, suffix := range trainingSuffixesV2 {
		context := contextAuthorityV2
		for i := 0; i < len(suffix); i++ {
			frequencies[context][suffix[i]] += 3
			context = advanceContextV2(context, suffix[i])
		}
	}

	if useDictionary {
		for entry, fragment := range dictionaryV2 {
			symbol := 256 + entry
			base := uint32(2 + len(fragment)/3)
			for context := 0; context < contextCountV2; context++ {
				frequencies[context][symbol] += base
			}

			text := string(fragment)
			switch fragment[0] {
			case '.':
				frequencies[contextAuthorityV2][symbol] += 45
			case '/':
				frequencies[contextAuthorityV2][symbol] += 28
				frequencies[contextPathV2][symbol] += 55
			case '?':
				frequencies[contextAuthorityV2][symbol] += 15
				frequencies[contextPathV2][symbol] += 45
			case '&':
				frequencies[contextQueryV2][symbol] += 55
			case '%':
				for context := 0; context < contextCountV2; context++ {
					frequencies[context][symbol] += 24
				}
			}
			if text == "www." {
				frequencies[contextAuthorityV2][symbol] += 90
			}
			if strings.Contains(text, ".") && !strings.ContainsAny(text, "/?&%") {
				frequencies[contextAuthorityV2][symbol] += 22
			}
			if !strings.ContainsAny(text, "/?&%=.") {
				frequencies[contextAuthorityV2][symbol] += 8
				frequencies[contextPathV2][symbol] += 24
				frequencies[contextQueryV2][symbol] += 14
				frequencies[contextFragmentV2][symbol] += 16
			}
		}
	}

	for context := 0; context < contextCountV2; context++ {
		frequencies[context][eofSymbolV2(useDictionary)] += 64
	}

	models := [contextCountV2]rangeModelV2{}
	for context := 0; context < contextCountV2; context++ {
		cumulative := make([]uint32, symbolCount+1)
		for symbol, frequency := range frequencies[context] {
			cumulative[symbol+1] = cumulative[symbol] + frequency
		}
		total := cumulative[len(cumulative)-1]
		if uint64(total) >= arithmeticFirstQuarterV2 {
			panic("v2 arithmetic probability total is too large")
		}

		cost := make([]uint32, symbolCount)
		for symbol, frequency := range frequencies[context] {
			bits := math.Log2(float64(total) / float64(frequency))
			cost[symbol] = uint32(math.Round(bits * probabilityScaleV2))
			if cost[symbol] == 0 {
				cost[symbol] = 1
			}
		}
		models[context] = rangeModelV2{cumulative: cumulative, total: total, cost: cost}
	}
	return models
}

func addByteWeightV2(frequencies []uint32, b byte, weight uint32) {
	frequencies[b] += weight
}

func advanceContextV2(context int, b byte) int {
	switch context {
	case contextAuthorityV2:
		switch b {
		case '/':
			return contextPathV2
		case '?':
			return contextQueryV2
		case '#':
			return contextFragmentV2
		}
	case contextPathV2:
		if b == '?' {
			return contextQueryV2
		}
		if b == '#' {
			return contextFragmentV2
		}
	case contextQueryV2:
		if b == '#' {
			return contextFragmentV2
		}
	}
	return context
}

func tokenizeSymbolsV2(input []byte) []int {
	contexts := make([]int, len(input)+1)
	context := contextAuthorityV2
	for i, b := range input {
		contexts[i] = context
		context = advanceContextV2(context, b)
	}
	contexts[len(input)] = context

	cost := make([]uint64, len(input)+1)
	choices := make([]symbolChoiceV2, len(input))
	for i := len(input) - 1; i >= 0; i-- {
		model := rangeModelsWithDictionaryV2[contexts[i]]
		cost[i] = uint64(model.cost[input[i]]) + cost[i+1]
		choices[i] = symbolChoiceV2{entry: -1, length: 1}

		node := 0
		for j := i; j < len(input); j++ {
			next, ok := dictionaryTrieV2[node].children[input[j]]
			if !ok {
				break
			}
			node = next
			entry := dictionaryTrieV2[node].entry
			if entry < 0 {
				continue
			}
			candidate := uint64(model.cost[256+entry]) + cost[j+1]
			if candidate < cost[i] {
				cost[i] = candidate
				choices[i] = symbolChoiceV2{entry: entry, length: j - i + 1}
			}
		}
	}

	symbols := make([]int, 0, len(input))
	for i := 0; i < len(input); {
		choice := choices[i]
		if choice.entry >= 0 {
			symbols = append(symbols, 256+choice.entry)
			i += choice.length
		} else {
			symbols = append(symbols, int(input[i]))
			i++
		}
	}
	return symbols
}

func encodeRangeSuffixV2(input []byte, useDictionary bool) packedBitsV2 {
	var symbols []int
	if useDictionary {
		symbols = tokenizeSymbolsV2(input)
	} else {
		symbols = make([]int, len(input))
		for i, b := range input {
			symbols[i] = int(b)
		}
	}

	encoder := newArithmeticEncoderV2()
	models := rangeModelsRawV2
	if useDictionary {
		models = rangeModelsWithDictionaryV2
	}
	context := contextAuthorityV2
	for _, symbol := range symbols {
		encoder.encode(symbol, models[context])
		if symbol < 256 {
			context = advanceContextV2(context, byte(symbol))
			continue
		}
		for _, b := range dictionaryV2[symbol-256] {
			context = advanceContextV2(context, b)
		}
	}
	encoder.encode(eofSymbolV2(useDictionary), models[context])
	return encoder.finish()
}

func prependSelectorV2(useDictionary bool, bits packedBitsV2) packedBitsV2 {
	var selected packedBitsV2
	if useDictionary {
		selected.write(1)
	} else {
		selected.write(0)
	}
	for position := 0; position < bits.length; position++ {
		selected.write(bits.at(position))
	}
	return selected
}

func sliceBitsV2(bits packedBitsV2, start int) packedBitsV2 {
	var sliced packedBitsV2
	for position := start; position < bits.length; position++ {
		sliced.write(bits.at(position))
	}
	return sliced
}

func encodeRangeURLV2(link string) (string, bool) {
	var scheme int
	var suffix string
	switch {
	case strings.HasPrefix(link, "https://"):
		scheme = 0
		suffix = link[len("https://"):]
	case strings.HasPrefix(link, "http://"):
		scheme = 1
		suffix = link[len("http://"):]
	default:
		return "", false
	}

	raw := makeRangeTokenV2(scheme, prependSelectorV2(false, encodeRangeSuffixV2([]byte(suffix), false)))
	withDictionary := makeRangeTokenV2(scheme, prependSelectorV2(true, encodeRangeSuffixV2([]byte(suffix), true)))
	if len(withDictionary) < len(raw) {
		return withDictionary, true
	}
	return raw, true
}

func makeRangeTokenV2(scheme int, bits packedBitsV2) string {
	first := 0
	for position := 0; position < 4; position++ {
		first = (first << 1) | int(bits.at(position))
	}
	marker := rangeMarkersV2[scheme*16+first]

	remaining := bits.length - 4
	if remaining < 0 {
		remaining = 0
	}
	output := make([]byte, 1, 1+(remaining+5)/6)
	output[0] = marker
	for position := 4; position < bits.length; position += 6 {
		value := 0
		for offset := 0; offset < 6; offset++ {
			value = (value << 1) | int(bits.at(position+offset))
		}
		output = append(output, base64URLAlphabet[value])
	}
	return string(output)
}

func rangeMarkerIndexV2(marker byte) int {
	return strings.IndexByte(rangeMarkersV2, marker)
}

func rangeTokenBitsV2(markerIndex int, payload string) (packedBitsV2, error) {
	var bits packedBitsV2
	nibble := markerIndex % 16
	for shift := 3; shift >= 0; shift-- {
		bits.write(uint64((nibble >> shift) & 1))
	}
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

func decodeRangeURLV2(token string, markerIndex int) ([]byte, error) {
	bits, err := rangeTokenBitsV2(markerIndex, token[1:])
	if err != nil {
		return nil, err
	}
	useDictionary := bits.at(0) == 1
	decoder := newArithmeticDecoderV2(sliceBitsV2(bits, 1))
	models := rangeModelsRawV2
	if useDictionary {
		models = rangeModelsWithDictionaryV2
	}
	context := contextAuthorityV2
	suffix := make([]byte, 0, len(token))
	for len(suffix) <= maxURLBytes {
		symbol, err := decoder.decode(models[context])
		if err != nil {
			return nil, err
		}
		// Arithmetic decoding needs a 32-bit zero look-ahead, but it must not
		// consume an unbounded imaginary zero stream after truncated input.
		if decoder.position > decoder.bits.length+32 {
			return nil, errors.New("truncated v2 arithmetic stream")
		}
		if symbol == eofSymbolV2(useDictionary) {
			break
		}

		if symbol < 256 {
			suffix = append(suffix, byte(symbol))
			context = advanceContextV2(context, byte(symbol))
		} else {
			if !useDictionary {
				return nil, errMalformedToken
			}
			entry := symbol - 256
			if entry < 0 || entry >= len(dictionaryV2) {
				return nil, errMalformedToken
			}
			fragment := dictionaryV2[entry]
			if len(suffix) > maxURLBytes-len(fragment) {
				return nil, errDecodedTooLarge
			}
			suffix = append(suffix, fragment...)
			for _, b := range fragment {
				context = advanceContextV2(context, b)
			}
		}
	}
	if len(suffix) > maxURLBytes {
		return nil, errDecodedTooLarge
	}

	prefix := "https://"
	if markerIndex/16 == 1 {
		prefix = "http://"
	}
	link := append([]byte(prefix), suffix...)
	canonical, ok := encodeRangeURLV2(string(link))
	if !ok || !bytes.Equal([]byte(canonical), []byte(token)) {
		return nil, errors.New("noncanonical or corrupt v2 compressed link")
	}
	return link, nil
}
