package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	links := []string{
		"https://example.com/a/repeated/path/a/repeated/path?query=value#result",
		"http://localhost:8080/api/v1/users?id=123",
		"https://[2001:db8::1]:8443/a//b?x=&x=1",
		"https://example.com/%2f/%2F?q=a+b&empty=#fragment",
		"https://例え.テスト/検索?q=日本語",
	}
	for _, link := range links {
		link := link
		t.Run(link, func(t *testing.T) {
			encoded, err := Encode(link)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) > len(link) {
				t.Fatalf("Encode expanded %d bytes to %d", len(link), len(encoded))
			}
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != link {
				t.Fatalf("Decode(Encode(link)) = %q, want %q", decoded, link)
			}
		})
	}
}

func TestRunCommandsAndAutoDetection(t *testing.T) {
	const link = "https://example.com/search?q=golang&utm_source=test&utm_medium=cli"

	var encoded bytes.Buffer
	if err := run([]string{"encode", link}, strings.NewReader(""), &encoded); err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSuffix(encoded.String(), "\n")

	for name, args := range map[string][]string{
		"explicit decode":  {"decode", token},
		"automatic decode": {token},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(args, strings.NewReader(""), &output); err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSuffix(output.String(), "\n"); got != link {
				t.Fatalf("output = %q, want %q", got, link)
			}
		})
	}

	var fromStdin bytes.Buffer
	if err := run(nil, strings.NewReader(link+"\n"), &fromStdin); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSuffix(fromStdin.String(), "\n"); got != token {
		t.Fatalf("stdin encode = %q, want %q", got, token)
	}
}

func TestDecodeBackendUnicodeToken(t *testing.T) {
	const token = "㐀𣒒𩍊𧜺𦭈𤼫㬇捒𥜾𧜜𥍆𨼫㫰𩌦𥝇㜃㣾𩍊𨼗㛊𨜺𧝊𨼒𥜾𧜜"
	const want = "https://пример.испытание/поиск?запрос=программирование"
	got, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Decode(token) = %q, want %q", got, want)
	}
}

func TestRunDecodesCompleteRedirectURL(t *testing.T) {
	const token = "㐁刢蝨𧋜𥗧𧑺檳媒𡲂𧍳𡫊備垎寡垝𩀬𣲧𨓗偯㺠芜𡿾𧯌𢀋轁𧅚𠒮武𠲿貰摀䀈"
	const want = "https://drive.google.com/drive/folders/1f6MYTL-5CqaH5G9sEzknHL9xlYUe24t9?usp=drive_link"

	inputs := map[string]string{
		"literal Unicode":         "http://127.0.0.1:8080/r/" + token,
		"percent-encoded Unicode": "http://127.0.0.1:8080/r/" + url.PathEscape(token),
	}
	for name, input := range inputs {
		input := input
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]string{{"decode", input}, {input}} {
				var output bytes.Buffer
				if err := run(args, strings.NewReader(""), &output); err != nil {
					t.Fatal(err)
				}
				if got := strings.TrimSuffix(output.String(), "\n"); got != want {
					t.Fatalf("output = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestRunDecodesCompleteASCIIRedirectURL(t *testing.T) {
	const want = "https://example.com/a/repeated/path/a/repeated/path?query=value#result"
	token, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if token == want {
		t.Fatal("test URL did not produce a token")
	}
	redirect := "https://short.example/r/" + token
	for _, args := range [][]string{{"decode", redirect}, {redirect}} {
		var output bytes.Buffer
		if err := run(args, strings.NewReader(""), &output); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSuffix(output.String(), "\n"); got != want {
			t.Fatalf("output = %q, want %q", got, want)
		}
	}
}

func TestRunAutoEncodesOrdinaryRPath(t *testing.T) {
	const input = "https://example.com/r/not-a-token"
	want, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{input}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSuffix(output.String(), "\n"); got != want {
		t.Fatalf("auto output = %q, want encoded URL %q", got, want)
	}
}

func TestRunRejectsMalformedRedirectURL(t *testing.T) {
	for _, input := range []string{
		"http://127.0.0.1:8080/r/4",
		"http://127.0.0.1:8080/r/4?query",
		"http://127.0.0.1:8080/r/4?",
		"http://127.0.0.1:8080/r/4#fragment",
		"http://127.0.0.1:8080/r/4#",
		"http://user@127.0.0.1:8080/r/4",
		"http://127.0.0.1:8080/r/%34",
	} {
		var output bytes.Buffer
		if err := run([]string{"decode", input}, strings.NewReader(""), &output); err == nil {
			t.Fatalf("decode accepted malformed redirect %q", input)
		}
	}
}
