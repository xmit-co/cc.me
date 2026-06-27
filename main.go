// Command cc-me claims deliveries from a cc.me inbox and replays them to a
// local forward URL.
//
// Usage: cc-me [--key <path>] <forward-url>
//
// Environment: CC_ME_KEY, CC_ME_URL, CC_ME_LIMIT.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ccme "cc.me/ccme"
)

const defaultLimit = 10

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  cc-me [--key <path>] <forward-url>")
}

func defaultKeyFile() string {
	if env := os.Getenv("CC_ME_KEY"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cc-me.key"
	}
	return filepath.Join(home, ".cc-me.key")
}

type options struct {
	keyFile string
	target  string
}

func parseArgs(args []string) (options, error) {
	opts := options{keyFile: defaultKeyFile()}
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			usage()
			os.Exit(0)
		case arg == "--key":
			i++
			if i >= len(args) || args[i] == "" {
				return opts, fmt.Errorf("--key needs a value")
			}
			opts.keyFile = args[i]
		case strings.HasPrefix(arg, "--key="):
			value := strings.TrimPrefix(arg, "--key=")
			if value == "" {
				return opts, fmt.Errorf("--key needs a value")
			}
			opts.keyFile = value
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown option: %s", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	if len(positionals) > 1 {
		return opts, fmt.Errorf("only one forward URL is supported")
	}
	if len(positionals) == 1 {
		opts.target = positionals[0]
	}
	return opts, nil
}

func limitFromEnv() int {
	if env := os.Getenv("CC_ME_LIMIT"); env != "" {
		if n, err := strconv.Atoi(env); err == nil {
			return n
		}
	}
	return defaultLimit
}

var hopByHop = map[string]struct{}{
	"connection":          {},
	"content-length":      {},
	"host":                {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func isHopByHop(name string) bool {
	_, ok := hopByHop[strings.ToLower(name)]
	return ok
}

// forwardURL merges the delivery query into the target URL's query.
func forwardURL(base *url.URL, query string) string {
	u := *base
	if query != "" {
		if u.RawQuery != "" {
			u.RawQuery = u.RawQuery + "&" + query
		} else {
			u.RawQuery = query
		}
	}
	return u.String()
}

func forwardRequest(client *http.Client, base *url.URL, d *ccme.Delivery) error {
	hasBody := d.Method != http.MethodGet && d.Method != http.MethodHead && len(d.BodyBytes) > 0
	var body *bytes.Reader
	if hasBody {
		body = bytes.NewReader(d.BodyBytes)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(d.Method, forwardURL(base, d.Query), body)
	if err != nil {
		return err
	}
	// Reset headers; net/http would otherwise populate Host etc.
	req.Header = http.Header{}
	for _, h := range d.Headers {
		if !isHopByHop(h.Name) {
			req.Header.Add(h.Name, h.Value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward failed with %d", resp.StatusCode)
	}
	return nil
}

func forwardLoop(opts options) error {
	if opts.target == "" {
		usage()
		os.Exit(64)
	}

	targetURL, err := url.Parse(opts.target)
	if err != nil {
		return err
	}

	key, err := ccme.PrivateKey(opts.keyFile)
	if err != nil {
		return err
	}
	client, err := ccme.NewClient(os.Getenv("CC_ME_URL"), key)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "cc.me inbox: %s\n", client.InboxURL(ccme.InboxOptions{}))
	fmt.Fprintf(os.Stderr, "forwarding to: %s\n", targetURL.String())

	httpClient := &http.Client{}
	limit := limitFromEnv()

	for {
		resp, err := client.Claim(ccme.ClaimOptions{Limit: limit, Poll: true})
		if err != nil {
			return err
		}

		var acked []string
		for i, d := range resp.Requests {
			if err := forwardRequest(httpClient, targetURL, d); err != nil {
				releaseIDs := make([]string, 0, len(resp.Requests)-i)
				for _, rem := range resp.Requests[i:] {
					releaseIDs = append(releaseIDs, rem.ID)
				}
				if len(acked) > 0 {
					_, _ = client.Ack(acked)
				}
				if len(releaseIDs) > 0 {
					_, _ = client.Release(releaseIDs)
				}
				return err
			}
			acked = append(acked, d.ID)
			line := d.Method + " " + d.Path
			if d.Query != "" {
				line += "?" + d.Query
			}
			fmt.Fprintln(os.Stderr, line)
		}
		if len(acked) > 0 {
			if _, err := client.Ack(acked); err != nil {
				return err
			}
		}
	}
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if err := forwardLoop(opts); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
