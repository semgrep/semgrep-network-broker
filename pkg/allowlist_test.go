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

func TestAllowlistWildcardMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://gitlab.example.com/*/:repo/info/refs",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://gitlab.example.com/api/v3/*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
		AllowlistItem{
			URL:     "https://gitlab.example.com/api/v4*",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	// Test leading wildcard matches
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/user/repo/info/refs", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/group/subgroup/repo/info/refs", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/endpoint?path=/info/refs", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/endpoint#repo/info/refs", false)

	// Test trailing wildcard matches
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/*", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v3", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v3/", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v3/projects/123", true)

	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/123", true)
}

func TestAllowlistParamMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:     "https://gitlab.example.com/api/v4/projects/:group/repository/files/:file_path",
			Methods: ParseHttpMethods([]string{"GET"}),
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/123/repository/files/path%2Fto%2Ffile", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/api/v4/projects/123/repository/files/path/to/file", false)
}

func TestAllowlistGitLabSubgroupMatch(t *testing.T) {
	config := &Config{
		Inbound: InboundProxyConfig{
			GitLab: &GitLab{
				BaseURL:         "https://gitlab.example.com/api/v4",
				AllowCodeAccess: true,
			},
			Allowlist: Allowlist{},
		},
	}
	if err := PopulateAllowLists(config); err != nil {
		t.Fatalf("PopulateAllowLists: %v", err)
	}
	allowlist := &config.Inbound.Allowlist

	// Flat group still works.
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/group/repo.git/info/refs?service=git-upload-pack", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/group/repo.git/git-upload-pack", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/group/repo.git/git-receive-pack", true)

	// One level of subgroup (the bug this test guards against).
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/group/subgroup/repo.git/info/refs?service=git-upload-pack", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/group/subgroup/repo.git/git-upload-pack", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/group/subgroup/repo.git/git-receive-pack", true)

	// Deep nesting — GitLab supports up to 20 levels.
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/g/s1/s2/s3/s4/s5/repo.git/info/refs", true)

	// Negative: no namespace at all is not a real GitLab git URL.
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com/repo/info/refs", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/repo.git/git-upload-pack", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/repo.git/git-receive-pack", false)

	// Negative: empty namespace via double-slash must not bypass the namespace
	// requirement. With a `*` wildcard this would match (zero-or-more includes
	// empty); the `{:namespace/}+` form rejects it.
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com//evil/info/refs", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com//evil/git-upload-pack", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com//evil/git-receive-pack", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://gitlab.example.com//group/repo/info/refs", false)

	// Negative: wrong host.
	assertAllowlistMatch(t, allowlist, "GET", "https://evil.example.com/group/subgroup/repo/info/refs", false)

	// Negative: method mismatch.
	assertAllowlistMatch(t, allowlist, "DELETE", "https://gitlab.example.com/group/repo.git/info/refs", false)
}

func gitHubAllowlist(t *testing.T, allowCodeAccess bool) *Allowlist {
	t.Helper()

	config := &Config{
		Inbound: InboundProxyConfig{
			GitHub: &GitHub{
				BaseURL:         "https://github.example.com/api/v3",
				AllowCodeAccess: allowCodeAccess,
			},
			Allowlist: Allowlist{},
		},
	}
	if err := PopulateAllowLists(config); err != nil {
		t.Fatalf("PopulateAllowLists: %v", err)
	}

	return &config.Inbound.Allowlist
}

// Code Autofix on GitHub resolves the base branch SHA, creates a branch at that
// SHA, writes the fix as a commit through the Git database API, and opens a PR.
// The commit is assembled object by object rather than pushed over the git
// transfer protocol, so every leg needs its own allowlist entry — a subset gets
// partway through and fails mid-commit.
func TestAllowlistGitHubAutofixWrites(t *testing.T) {
	allowlist := gitHubAllowlist(t, true)

	const repo = "https://github.example.com/api/v3/repos/testorg/testrepo"
	const sha = "fb82f3624fb363332009bd8a3be1c681877e5aaf"

	// Resolve the base SHA and create the branch at it.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/ref/heads/main", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/refs", true)

	// Commit the fix, then open the PR.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/commits/"+sha, true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/blobs", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/trees", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/commits", true)
	assertAllowlistMatch(t, allowlist, "PATCH", repo+"/git/refs/heads/semgrep-autofix/1787673035", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pulls", true)

	// Ref names contain slashes, so both ref entries must match across segments.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/ref/heads/feature/DEV-1/fix", true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/ref/tags/v1.2.3", true)
	assertAllowlistMatch(t, allowlist, "PATCH", repo+"/git/refs/heads/feature/DEV-1/fix", true)

	// The Git database commit read is a different endpoint from the REST
	// list-commits one. Both are allowed, by separate entries — the presence of
	// /commits is not what admits /git/commits/:sha.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/commits", true)

	// Reading the repo (for its default branch) still works.
	assertAllowlistMatch(t, allowlist, "GET", repo, true)

	// Not part of this flow — asserted here because this is the only coverage
	// the git transfer protocol entries have, and they share the same gate.
	assertAllowlistMatch(t, allowlist, "POST", "https://github.example.com/testorg/testrepo/git-receive-pack", true)

	// Negative: the ref lookup is read-only, and does not widen /git/refs.
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/ref/heads/main", false)
	assertAllowlistMatch(t, allowlist, "DELETE", repo+"/git/ref/heads/main", false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/refs", false)

	// Negative: moving a ref is the only write /git/refs/* admits. Deleting a
	// branch is not part of the flow.
	assertAllowlistMatch(t, allowlist, "DELETE", repo+"/git/refs/heads/main", false)
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/git/refs/heads/main", false)

	// Negative: the Git database entries are single-method.
	assertAllowlistMatch(t, allowlist, "DELETE", repo+"/git/commits/"+sha, false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/blobs", false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/trees", false)
}

// Every leg of the write path reads or writes repository contents, so all of
// them are gated behind allowCodeAccess.
func TestAllowlistGitHubAutofixWritesRequireCodeAccess(t *testing.T) {
	allowlist := gitHubAllowlist(t, false)

	const repo = "https://github.example.com/api/v3/repos/testorg/testrepo"
	const sha = "fb82f3624fb363332009bd8a3be1c681877e5aaf"

	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/ref/heads/main", false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/git/commits/"+sha, false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/blobs", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/trees", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/git/commits", false)
	assertAllowlistMatch(t, allowlist, "PATCH", repo+"/git/refs/heads/semgrep-autofix/1787673035", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://github.example.com/testorg/testrepo/git-receive-pack", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pulls", false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/commits", false)

	// Sanity check: the read-only entries on neighbouring paths are unaffected.
	assertAllowlistMatch(t, allowlist, "GET", repo, true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/branches/main", true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/pulls", true)
}

func gitLabAllowlist(t *testing.T, allowCodeAccess bool) *Allowlist {
	t.Helper()

	config := &Config{
		Inbound: InboundProxyConfig{
			GitLab: &GitLab{
				BaseURL:         "https://gitlab.example.com/api/v4",
				AllowCodeAccess: allowCodeAccess,
			},
			Allowlist: Allowlist{},
		},
	}
	if err := PopulateAllowLists(config); err != nil {
		t.Fatalf("PopulateAllowLists: %v", err)
	}

	return &config.Inbound.Allowlist
}

// Code Autofix on GitLab creates a branch, writes the fix through the commits
// endpoint, and then opens an MR. The project is passed URL-encoded, so
// `:project` has to match a single segment containing %2F.
func TestAllowlistGitLabAutofixWrites(t *testing.T) {
	allowlist := gitLabAllowlist(t, true)

	const project = "https://gitlab.example.com/api/v4/projects/caleb-testing%2Fproblems"

	// Create the branch, commit the fix onto it, then open the MR.
	assertAllowlistMatch(t, allowlist, "POST", project+"/repository/branches", true)
	assertAllowlistMatch(t, allowlist, "POST", project+"/repository/commits", true)
	assertAllowlistMatch(t, allowlist, "POST", project+"/merge_requests", true)

	// Reading the same endpoints still works.
	assertAllowlistMatch(t, allowlist, "GET", project+"/repository/commits", true)
	assertAllowlistMatch(t, allowlist, "GET", project+"/merge_requests", true)

	// A numeric project id is the other form the platform sends.
	assertAllowlistMatch(t, allowlist, "POST", "https://gitlab.example.com/api/v4/projects/123/repository/commits", true)

	// Negative: the write verbs stop at the endpoints above.
	assertAllowlistMatch(t, allowlist, "DELETE", project+"/repository/commits", false)
	assertAllowlistMatch(t, allowlist, "PUT", project+"/repository/commits", false)
	assertAllowlistMatch(t, allowlist, "POST", project+"/repository/files/auth.py", false)
}

func TestAllowlistGitLabAutofixWritesRequireCodeAccess(t *testing.T) {
	allowlist := gitLabAllowlist(t, false)

	const project = "https://gitlab.example.com/api/v4/projects/caleb-testing%2Fproblems"

	assertAllowlistMatch(t, allowlist, "POST", project+"/repository/commits", false)
	assertAllowlistMatch(t, allowlist, "GET", project+"/repository/commits", false)
	assertAllowlistMatch(t, allowlist, "POST", project+"/merge_requests", false)
	// Creating a branch mutates the repo, so it is gated too.
	assertAllowlistMatch(t, allowlist, "POST", project+"/repository/branches", false)

	// Sanity check: the read-only entries on the same paths are unaffected.
	assertAllowlistMatch(t, allowlist, "GET", project+"/merge_requests", true)
	assertAllowlistMatch(t, allowlist, "GET", project+"/repository/branches", true)
}

func bitBucketAllowlist(t *testing.T, allowCodeAccess bool) *Allowlist {
	t.Helper()

	config := &Config{
		Inbound: InboundProxyConfig{
			BitBucket: &BitBucket{
				BaseURL:         "https://bitbucket.example.com/rest/api/latest",
				AllowCodeAccess: allowCodeAccess,
			},
			Allowlist: Allowlist{},
		},
	}
	if err := PopulateAllowLists(config); err != nil {
		t.Fatalf("PopulateAllowLists: %v", err)
	}

	return &config.Inbound.Allowlist
}

// Code Autofix on Bitbucket Data Center writes the fix through the edit-file
// endpoint and then opens a PR. Both are writes, so both are gated behind
// allowCodeAccess (matching GitHub's create-pull and GitLab's create-MR).
func TestAllowlistBitBucketAutofixWrites(t *testing.T) {
	allowlist := bitBucketAllowlist(t, true)

	const repo = "https://bitbucket.example.com/rest/api/latest/projects/CAL/repos/problems-on-purpose"

	// Write the fix. The `browse/*` wildcard has to span a multi-segment file path.
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/browse/vulnapp/auth.py", true)
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/browse/auth.py", true)
	// Reading the same path still works.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/browse/vulnapp/auth.py", true)

	// Create the branch the fix commits onto, then open the PR.
	assertAllowlistMatch(t, allowlist, "POST", repo+"/branches", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pull-requests", true)

	// Negative: the write verbs stop at the endpoints above.
	assertAllowlistMatch(t, allowlist, "DELETE", repo+"/browse/vulnapp/auth.py", false)
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/pull-requests", false)

	// Negative: the permission preflight's admin endpoint is deliberately not
	// allowlisted. See the note in PopulateAllowLists.
	assertAllowlistMatch(t, allowlist, "GET", "https://bitbucket.example.com/rest/api/latest/admin/groups", false)
}

func TestAllowlistBitBucketAutofixWritesRequireCodeAccess(t *testing.T) {
	allowlist := bitBucketAllowlist(t, false)

	const repo = "https://bitbucket.example.com/rest/api/latest/projects/CAL/repos/problems-on-purpose"

	assertAllowlistMatch(t, allowlist, "PUT", repo+"/browse/vulnapp/auth.py", false)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/browse/vulnapp/auth.py", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pull-requests", false)
	// Creating a branch mutates the repo, so it is gated too.
	assertAllowlistMatch(t, allowlist, "POST", repo+"/branches", false)

	// Sanity check: the read-only entries on the same paths are unaffected.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/pull-requests", true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/branches", true)
}

func azureDevOpsAllowlist(t *testing.T, allowCodeAccess bool) *Allowlist {
	t.Helper()

	config := &Config{
		Inbound: InboundProxyConfig{
			AzureDevOps: &AzureDevOps{
				BaseURL:         "https://dev.azure.com",
				AllowCodeAccess: allowCodeAccess,
			},
			Allowlist: Allowlist{},
		},
	}
	if err := PopulateAllowLists(config); err != nil {
		t.Fatalf("PopulateAllowLists: %v", err)
	}

	return &config.Inbound.Allowlist
}

// Code Autofix on Azure DevOps resolves the base SHA from the refs API, creates
// the branch as a ref update, then writes the fix as a push — Azure DevOps has
// no create-commit endpoint — and opens a PR. Creating the branch is allowed by
// the on-by-default list, so a gap in the later legs strands the flow with the
// branch already created rather than failing up front.
func TestAllowlistAzureDevOpsAutofixWrites(t *testing.T) {
	allowlist := azureDevOpsAllowlist(t, true)

	const repo = "https://dev.azure.com/testorg/testproject/_apis/git/repositories/testrepo"

	// Resolve the base SHA, create the branch at it.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/refs?filter=heads/main", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/refs", true)

	// Decide add-vs-edit per file, commit the fix as a push, open the PR.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/items?path=/vulnapp/auth.py", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pushes", true)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pullRequests", true)

	// Reading the repo (for its default branch) still works.
	assertAllowlistMatch(t, allowlist, "GET", repo, true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/pullRequests", true)

	// Negative: the write verbs stop at the endpoints above.
	assertAllowlistMatch(t, allowlist, "GET", repo+"/pushes", false)
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/pushes", false)
	assertAllowlistMatch(t, allowlist, "DELETE", repo+"/refs", false)
	assertAllowlistMatch(t, allowlist, "PATCH", repo+"/pullRequests", false)
	assertAllowlistMatch(t, allowlist, "PUT", repo+"/items?path=/vulnapp/auth.py", false)
}

func TestAllowlistAzureDevOpsAutofixWritesRequireCodeAccess(t *testing.T) {
	allowlist := azureDevOpsAllowlist(t, false)

	const repo = "https://dev.azure.com/testorg/testproject/_apis/git/repositories/testrepo"

	assertAllowlistMatch(t, allowlist, "GET", repo+"/items?path=/vulnapp/auth.py", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pushes", false)
	assertAllowlistMatch(t, allowlist, "POST", repo+"/pullRequests", false)

	// Sanity check: the read-only entries on the same paths are unaffected.
	assertAllowlistMatch(t, allowlist, "GET", repo, true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/refs?filter=heads/main", true)
	assertAllowlistMatch(t, allowlist, "GET", repo+"/pullRequests", true)

	// Creating a branch is on by default here, as it is on GitHub, while GitLab
	// and Bitbucket Data Center gate it. Asserted so that difference is a
	// deliberate, visible choice rather than something nobody checked.
	assertAllowlistMatch(t, allowlist, "POST", repo+"/refs", true)
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
	const maxAllowedDurationPerFindMatch = 100 // 100 milliseconds

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
	t.Logf("Budget: %dms per call to find match", maxAllowedDurationPerFindMatch)

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
}
