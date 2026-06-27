package ccme

import (
	"net/url"
	"strings"
	"testing"
)

func TestTrampolineURL(t *testing.T) {
	cases := []struct {
		name   string
		target string
		opts   []func(*urlConfig)
		// checks operate on the parsed result so we don't depend on map order.
		wantBase  string
		wantAt    string
		wantQuery map[string]string
	}{
		{
			name:     "default base",
			target:   "https://app.example/callback",
			wantBase: "https://cc.me/",
			wantAt:   "https://app.example/callback",
		},
		{
			name:     "extra params",
			target:   "https://app.example/cb",
			opts:     []func(*urlConfig){WithParams(map[string]string{"state": "xyz", "code": "1"})},
			wantBase: "https://cc.me/",
			wantAt:   "https://app.example/cb",
			wantQuery: map[string]string{
				"state": "xyz",
				"code":  "1",
			},
		},
		{
			name:     "base override",
			target:   "https://t/cb",
			opts:     []func(*urlConfig){WithBaseURL("https://staging.cc.me/")},
			wantBase: "https://staging.cc.me/",
			wantAt:   "https://t/cb",
		},
		{
			name:     "target with query is at-encoded",
			target:   "https://app.example/cb?a=1&b=2",
			wantBase: "https://cc.me/",
			wantAt:   "https://app.example/cb?a=1&b=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TrampolineURL(tc.target, tc.opts...)
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("result not a URL: %v", err)
			}
			gotBase := u.Scheme + "://" + u.Host + "/"
			if gotBase != tc.wantBase {
				t.Fatalf("base = %q, want %q", gotBase, tc.wantBase)
			}
			q := u.Query()
			if q.Get("at") != tc.wantAt {
				t.Fatalf("at = %q, want %q", q.Get("at"), tc.wantAt)
			}
			for k, v := range tc.wantQuery {
				if q.Get(k) != v {
					t.Fatalf("param %q = %q, want %q", k, q.Get(k), v)
				}
			}
		})
	}
}

func TestInboxPathOrderingTable(t *testing.T) {
	cases := []struct {
		name string
		opts InboxOptions
		want string
	}{
		{"no options", InboxOptions{}, "/i/KEY"},
		{"limit only", InboxOptions{Limit: 5}, "/i/KEY?l=5"},
		{"cursor only", InboxOptions{Cursor: "abc"}, "/i/KEY?c=abc"},
		{"poll only empty value", InboxOptions{Poll: true}, "/i/KEY?p="},
		{"limit and cursor", InboxOptions{Limit: 3, Cursor: "x"}, "/i/KEY?l=3&c=x"},
		{"limit and poll", InboxOptions{Limit: 7, Poll: true}, "/i/KEY?l=7&p="},
		{"all in order l,c,p", InboxOptions{Limit: 10, Cursor: "abc", Poll: true}, "/i/KEY?l=10&c=abc&p="},
		{"zero limit omitted", InboxOptions{Limit: 0}, "/i/KEY"},
		{"cursor needs escaping", InboxOptions{Cursor: "a b&c"}, "/i/KEY?c=a+b%26c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inboxPath("KEY", tc.opts); got != tc.want {
				t.Fatalf("inboxPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProtocolURLs(t *testing.T) {
	c, err := NewClient("", knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "https://cc.me/i/" + knownPublicKey
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"webmention", c.WebmentionURL(), prefix + "/webmention"},
		{"websub", c.WebsubURL(), prefix + "/websub"},
		{"slack", c.SlackURL(), prefix + "/slack"},
		{"pingback", c.PingbackURL(), prefix + "/pingback"},
		{"cloudevents", c.CloudEventsURL(), prefix + "/cloudevents"},
		{"meta no token", c.MetaURL(""), prefix + "/meta"},
		{"meta with token", c.MetaURL("tok123"), prefix + "/meta?v=tok123"},
		{"meta token escaped", c.MetaURL("a b/c"), prefix + "/meta?v=a+b%2Fc"},
		{"discord", c.DiscordURL("appkey"), prefix + "/discord/appkey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestInboxURLWithOptions(t *testing.T) {
	c, err := NewClient("https://staging.cc.me/", knownSeed)
	if err != nil {
		t.Fatal(err)
	}
	got := c.InboxURL(InboxOptions{Limit: 4, Poll: true})
	want := "https://staging.cc.me/i/" + knownPublicKey + "?l=4&p="
	if got != want {
		t.Fatalf("inbox URL = %q, want %q", got, want)
	}
}

func TestJoinBase(t *testing.T) {
	cases := []struct {
		name string
		base string
		path string
		want string
	}{
		{"empty base uses default", "", "/c", "https://cc.me/c"},
		{"trailing slash base", "https://cc.me/", "/i/KEY", "https://cc.me/i/KEY"},
		{"no trailing slash base", "https://x.test", "/c", "https://x.test/c"},
		{"base with subpath", "https://x.test/api/", "/c", "https://x.test/c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinBase(tc.base, tc.path); got != tc.want {
				t.Fatalf("joinBase(%q,%q) = %q, want %q", tc.base, tc.path, got, tc.want)
			}
		})
	}
}

func TestPathAndQueryEscapeHelpers(t *testing.T) {
	if got := pathEscape("a/b c"); !strings.Contains(got, "%20") && !strings.Contains(got, "c") {
		t.Fatalf("pathEscape unexpected: %q", got)
	}
	if got := queryEscape("a b&c"); got != "a+b%26c" {
		t.Fatalf("queryEscape = %q", got)
	}
}
