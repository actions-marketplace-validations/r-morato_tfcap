package output

import (
	"regexp"
	"strings"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/lock"
)

var githubRepoRe = regexp.MustCompile(`(?i)github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?(//|[/?#]|$)`)

var safeRefRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// CompareURL returns a GitHub "compare" link showing the code that changed
// between the locked and current version of a git module hosted on GitHub,
// or "" when there is nothing to compare or no way to build the link
// offline. Commits are preferred over refs because a moved tag is exactly
// the case where the ref looks the same and the commit does not.
func CompareURL(m lock.ModuleStatus) string {
	if m.Status != lock.StatusUpgraded && m.Status != lock.StatusMutated {
		return ""
	}
	locked := m.LockedSource
	if locked == "" {
		locked = m.Source
	}
	cur := githubRepoRe.FindStringSubmatch(m.Source)
	old := githubRepoRe.FindStringSubmatch(locked)
	if cur == nil || old == nil || !strings.EqualFold(cur[1]+"/"+cur[2], old[1]+"/"+old[2]) {
		return "" // not on GitHub, or the module moved to another repository
	}
	base := m.LockedCommit
	if base == "" {
		base = analyze.ClassifySource(locked).Ref
	}
	head := m.CurrentCommit
	if head == "" {
		head = analyze.ClassifySource(m.Source).Ref
	}
	if base == "" || head == "" || base == head || !safeRefRe.MatchString(base) || !safeRefRe.MatchString(head) {
		return ""
	}
	return "https://github.com/" + cur[1] + "/" + cur[2] + "/compare/" + base + "..." + head
}
