// Package textdiff is the longest-common-subsequence diff the session viewer
// uses for drifted tool definitions (internal/viewer/static/log.js), ported so
// the command line shows the same changes the viewer does.
package textdiff

import "regexp"

// Op says what happened to a token.
type Op int

const (
	Eq  Op = iota // in both
	Del           // only in the old text
	Ins           // only in the new text
)

// Part is one token of a diff.
type Part struct {
	Op   Op
	Text string
}

// maxCells bounds the DP table, as in the viewer. Above it the diff is the
// whole of a deleted and the whole of b inserted.
const maxCells = 4_000_000

// Diff returns an LCS diff of two token lists. Ties prefer deletions, so a
// replaced token reads "old, then new".
func Diff(a, b []string) []Part {
	n, m := len(a), len(b)
	if n*m > maxCells {
		out := make([]Part, 0, n+m)
		for _, t := range a {
			out = append(out, Part{Del, t})
		}
		for _, t := range b {
			out = append(out, Part{Ins, t})
		}
		return out
	}
	dp := make([][]uint32, n+1)
	for i := range dp {
		dp[i] = make([]uint32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	out := make([]Part, 0, max(n, m))
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, Part{Eq, a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, Part{Del, a[i]})
			i++
		default:
			out = append(out, Part{Ins, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, Part{Del, a[i]})
	}
	for ; j < m; j++ {
		out = append(out, Part{Ins, b[j]})
	}
	return out
}

var reWords = regexp.MustCompile(`\s+|[^\s]+`)

// Words splits s into words and the whitespace between them, so a word diff
// joins back into the original text.
func Words(s string) []string {
	return reWords.FindAllString(s, -1)
}

// Merge joins neighbouring parts with the same op.
func Merge(parts []Part) []Part {
	var out []Part
	for _, p := range parts {
		if k := len(out) - 1; k >= 0 && out[k].Op == p.Op {
			out[k].Text += p.Text
			continue
		}
		out = append(out, p)
	}
	return out
}
