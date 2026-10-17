// Package reputation runs the opt-in --online checks: it asks the public
// module registry, the GitHub API and the OpenSSF Scorecard API about the
// third-party modules in a report. Nothing here runs unless the user asks;
// tfcap is offline by default.
package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// Client holds endpoints (overridable in tests) and the HTTP client.
type Client struct {
	HTTP      *http.Client
	Registry  string // https://registry.terraform.io
	GitHub    string // https://api.github.com
	Scorecard string // https://api.securityscorecards.dev
	// GitHubToken is sent only to the GitHub endpoint, to raise the rate limit.
	GitHubToken string
	Now         func() time.Time
}

// New returns a client for the public services.
func New(token string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect},
		Registry: "https://registry.terraform.io", GitHub: "https://api.github.com",
		Scorecard: "https://api.securityscorecards.dev", GitHubToken: token, Now: time.Now,
	}
}

// noRedirect lets us see GitHub's 301 for renamed repositories.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

var errNotFound = errors.New("not found")

func (c *Client) get(ctx context.Context, url string, auth bool, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tfcap (+https://github.com/r-morato/tfcap)")
	if auth && c.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.GitHubToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resp.StatusCode, errNotFound
	case resp.StatusCode == http.StatusMovedPermanently:
		if out != nil {
			_ = json.Unmarshal(body, out)
		}
		return resp.StatusCode, nil
	case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) && auth && c.GitHubToken == "":
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d (likely the unauthenticated rate limit; set GITHUB_TOKEN)", url, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, fmt.Errorf("GET %s: %w", url, err)
		}
	}
	return resp.StatusCode, nil
}

var githubRe = regexp.MustCompile(`(?i)github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?([/?#]|$)`)

// githubRepo extracts owner/repo from a source or URL.
func githubRepo(s string) (string, string, bool) {
	m := githubRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

type registryModule struct {
	Source      string `json:"source"`
	PublishedAt string `json:"published_at"`
	Downloads   int    `json:"downloads"`
	Verified    bool   `json:"verified"`
}

type ghRepo struct {
	FullName  string `json:"full_name"`
	Archived  bool   `json:"archived"`
	CreatedAt string `json:"created_at"`
	URL       string `json:"url"` // set on 301 responses
	Message   string `json:"message"`
}

type scorecard struct {
	Score float64 `json:"score"`
}

// Check returns findings for every third-party module in rep, plus
// non-fatal errors (network failures, rate limits) as warnings.
func (c *Client) Check(ctx context.Context, rep *model.Report) ([]model.Capability, []string) {
	var caps []model.Capability
	var warns []string
	repos := map[string]bool{}
	for _, m := range rep.Modules {
		if !m.ThirdParty || m.Source == "" {
			continue
		}
		info := analyze.ClassifySource(m.Source)
		add := func(id, msg, detail string) {
			r := rules.Get(id)
			addr := "module." + m.Key[strings.LastIndex(m.Key, ".")+1:]
			cp := model.Capability{RuleID: r.ID, Severity: r.Severity, Phase: r.Phase, Module: m.Key, Address: addr, Message: msg, Detail: detail}
			if m.Anchor != nil {
				cp.File, cp.Line = m.Anchor.File, m.Anchor.Line
			}
			caps = append(caps, cp)
		}
		repoURL := m.Source
		if info.Kind == model.SourceRegistry {
			ns, name, prov, host, ok := registryParts(m.Source)
			if !ok || host != "registry.terraform.io" || m.Version == "" {
				continue // private registries are out of scope
			}
			var rm registryModule
			url := fmt.Sprintf("%s/v1/modules/%s/%s/%s/%s", c.Registry, ns, name, prov, m.Version)
			if _, err := c.get(ctx, url, false, &rm); err != nil {
				if errors.Is(err, errNotFound) {
					add(rules.RepUnknownModule, fmt.Sprintf("Registry does not know %s/%s/%s %s", ns, name, prov, m.Version), "registry:"+m.Source+"@"+m.Version)
				} else {
					warns = append(warns, "registry: "+err.Error())
				}
				continue
			}
			if t, err := time.Parse(time.RFC3339, rm.PublishedAt); err == nil && c.Now().Sub(t) < 7*24*time.Hour {
				add(rules.RepFreshRelease, fmt.Sprintf("%s %s was published %s", m.Source, m.Version, t.Format("2006-01-02")), "fresh:"+m.Source+"@"+m.Version)
			}
			repoURL = rm.Source
		}
		owner, repo, ok := githubRepo(repoURL)
		if !ok {
			continue
		}
		key := strings.ToLower(owner + "/" + repo)
		if repos[key] {
			continue
		}
		repos[key] = true
		var gr ghRepo
		code, err := c.get(ctx, fmt.Sprintf("%s/repos/%s/%s", c.GitHub, owner, repo), true, &gr)
		switch {
		case errors.Is(err, errNotFound):
			add(rules.RepRepoMissing, fmt.Sprintf("GitHub repository %s/%s does not exist", owner, repo), "repo:"+key)
			continue
		case err != nil:
			warns = append(warns, "github: "+err.Error())
			continue
		case code == http.StatusMovedPermanently:
			add(rules.RepRepoMoved, fmt.Sprintf("GitHub repository %s/%s was renamed or transferred", owner, repo), "repo:"+key)
			continue
		}
		if gr.Archived {
			add(rules.RepRepoArchived, fmt.Sprintf("GitHub repository %s is archived", gr.FullName), "repo:"+key)
		}
		if t, err := time.Parse(time.RFC3339, gr.CreatedAt); err == nil && c.Now().Sub(t) < 90*24*time.Hour {
			add(rules.RepRepoYoung, fmt.Sprintf("GitHub repository %s was created %s", gr.FullName, t.Format("2006-01-02")), "repo:"+key)
		}
		var sc scorecard
		if _, err := c.get(ctx, fmt.Sprintf("%s/projects/github.com/%s/%s", c.Scorecard, owner, repo), false, &sc); err == nil {
			if sc.Score < 4 {
				add(rules.RepLowScorecard, fmt.Sprintf("OpenSSF Scorecard for %s is %.1f/10", key, sc.Score), "repo:"+key)
			}
		} else if !errors.Is(err, errNotFound) {
			warns = append(warns, "scorecard: "+err.Error())
		}
	}
	return caps, warns
}

// registryParts splits [host/]ns/name/provider[//sub].
func registryParts(src string) (ns, name, prov, host string, ok bool) {
	p := strings.Split(strings.SplitN(src, "//", 2)[0], "/")
	switch len(p) {
	case 3:
		return p[0], p[1], p[2], "registry.terraform.io", true
	case 4:
		return p[1], p[2], p[3], strings.ToLower(p[0]), true
	}
	return "", "", "", "", false
}
