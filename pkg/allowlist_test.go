package pkg

import (
	"net/url"
	"testing"
	"time"
)

func urlMustParse(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}

	return url
}

func assertAllowlistMatch(t *testing.T, allowlist *Allowlist, method string, rawURL string, shouldMatch bool) {
	_, match := allowlist.FindMatch(method, urlMustParse(rawURL))
	if match != shouldMatch {
		t.Errorf("%v %v match result was %v, expected %v", method, rawURL, match, shouldMatch)
	}
}

func TestAllowlistSchemeMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/https-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "http://foo.com/http-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/https-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/http-only", false)
	assertAllowlistMatch(t, allowlist, "GET", "http://foo.com/https-only", false)
	assertAllowlistMatch(t, allowlist, "GET", "http://foo.com/http-only", true)
}

func TestAllowlistMethodMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/get-only",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/post-only",
			Methods: ParseHttpMethods([]string{"POST"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/get-or-post",
			Methods: ParseHttpMethods([]string{"GET", "POST"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-only", false)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/post-only", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/post-only", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/post-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-or-post", false)
}

func TestAllowlistDomainMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://bar.com/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://bar.com/bar-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://baz.com/baz", false)
}

func TestAllowlistPathMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://foo.com/hardcoded-path",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/wildcard-path/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/variable-path/:variable",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://foo.com/variable-path/:variable/suffix",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	// test path matching
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a/b", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a/b?foo=bar", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a/b?foo=bar#baz", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a/b", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path/bla", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/bla%2Fbla/suffix", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/bla/bla/suffix", false)
}

func TestAllowlistEncodedPathMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://gitlab.example.com/api/v4/projects/group%2Fproject/repository/files/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://gitlab.example.com/api/v4/projects/:group%2F:project/repository/files/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	// Test that encoded forward slashes in the path match correctly
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/group%2Fproject/repository/files/path/to/file", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/group/project/repository/files/path/to/file", false)

	// Test with variables containing encoded characters
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/test-group%2Ftest-project/repository/files/path/to/file", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/test-group/test-project/repository/files/path/to/file", false)
}

func createCombinedAllowlist() *Allowlist {
	config := &Config{
		Inbound: InboundProxyConfig{
			GitHub: &GitHub{
				BaseURL:         "https://api.github.com",
				AllowCodeAccess: true,
			},
			GitLab: &GitLab{
				BaseURL:         "https://gitlab.com/api/v4",
				AllowCodeAccess: true,
			},
			BitBucket: &BitBucket{
				BaseURL:         "https://bitbucket.org/rest/api/1.0",
				AllowCodeAccess: true,
			},
			AzureDevOps: &AzureDevOps{
				BaseURL:         "https://dev.azure.com",
				AllowCodeAccess: true,
			},
			Allowlist: Allowlist{},
		},
	}

	err := PopulateAllowLists(config)
	if err != nil {
		panic(err)
	}

	return &config.Inbound.Allowlist
}

func TestAllowlistFindMatchPerformance(t *testing.T) {
	const maxAllowedDurationPerFindMatch = 1 // 1 millisecond

	allowlist := createCombinedAllowlist()
	testUrls := []struct {
		method string
		url    string
		name   string
	}{
		{"GET", "https://api.github.com/repos/testorg/testrepo", "GitHub_RepoInfo"},
		{"POST", "https://api.github.com/repos/testorg/testrepo/pulls/123/comments", "GitHub_PRComments"},
		{"GET", "https://api.github.com/orgs/testorg/hooks", "GitHub_OrgHooks"},

		{"GET", "https://gitlab.com/api/v4/projects/123", "GitLab_Projects"},
		{"POST", "https://gitlab.com/api/v4/projects/123/merge_requests/456/discussions", "GitLab_MRDiscussions"},
		{"GET", "https://gitlab.com/api/v4/projects/123/repository/branches", "GitLab_Branches"},

		{"GET", "https://bitbucket.org/rest/api/1.0/application-properties", "BitBucket_AppProperties"},
		{"POST", "https://bitbucket.org/rest/api/1.0/projects/TEST/repos/testrepo/pull-requests/123/comments", "BitBucket_PRComments"},
		{"GET", "https://bitbucket.org/rest/api/1.0/projects/TEST/webhooks", "BitBucket_Webhooks"},

		{"GET", "https://dev.azure.com/testorg/_apis/connectionData", "AzureDevOps_ConnectionData"},
		{"GET", "https://dev.azure.com/testorg/testproject/_apis/git/repositories", "AzureDevOps_Repositories"},
		{"GET", "https://dev.azure.com/testorg/testproject/_apis/git/repositories/testrepo/pullRequests", "AzureDevOps_PullRequests"},

		// Include some no-match scenarios (worst case performance)
		{"GET", "https://unknown.com/some/random/endpoint", "NoMatch_UnknownDomain"},
		{"GET", "https://api.github.com/nonexistent/endpoint", "NoMatch_WrongPath"},
		{"GET", "https://api.github.com/nonexistent/endpoint/with/terribly/many/path/segments/to/ensure/url/parsing/is/sufficiently/performant", "NoMatch_WrongLongPath"},
	}

	t.Logf("Testing combined allowlist with %d items against %d URLs", len(*allowlist), len(testUrls))
	t.Logf("Budget: %dms per find match", maxAllowedDurationPerFindMatch)

	var totalDuration time.Duration
	matches := 0

	// Test that evaluating each URL against the allowlist is within the budget
	for _, testCase := range testUrls {
		t.Run(testCase.name, func(t *testing.T) {
			testURL := urlMustParse(testCase.url)

			// Measure time for this specific URL lookup
			start := time.Now()
			_, match := allowlist.FindMatch(testCase.method, testURL)
			duration := time.Since(start)

			totalDuration += duration
			if match {
				matches++
			}

			durationMillis := float64(duration.Nanoseconds()) / 1_000_000
			t.Logf("%s: %.1fms (match: %v)", testCase.name, durationMillis, match)

			// Check if this URL exceeded the per-URL budget
			if durationMillis > float64(maxAllowedDurationPerFindMatch) {
				t.Errorf("%s took %.1fms, exceeds budget of %dms",
					testCase.name,
					durationMillis,
					maxAllowedDurationPerFindMatch)
			}
		})
	}

	// Report summary
	avgDurationMillis := float64(totalDuration.Nanoseconds()) / float64(len(testUrls)) / 1_000_000
	t.Logf("Summary: %d matches out of %d URLs", matches, len(testUrls))
	t.Logf("Average time per lookup: %.1fms", avgDurationMillis)
	t.Logf("Total time for all lookups: %.1fms", float64(totalDuration.Nanoseconds())/1_000_000)
}
