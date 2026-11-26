package textdiff

import (
	"strings"
	"testing"
)

func render(parts []Part) string {
	var b strings.Builder
	for _, p := range Merge(parts) {
		switch p.Op {
		case Del:
			b.WriteString("[-" + p.Text + "-]")
		case Ins:
			b.WriteString("{+" + p.Text + "+}")
		default:
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func TestWordDiff(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"Get the forecast.", "Get the forecast.", "Get the forecast."},
		{"Get the forecast.", "Get the weather forecast.", "Get the {+weather +}forecast."},
		{"Read a file.", "Read a text file.", "Read a {+text +}file."},
		{"List alerts for a region.", "List alerts.", "List [-alerts for a region.-]{+alerts.+}"},
		{"", "New tool.", "{+New tool.+}"},
		{"Old tool.", "", "[-Old tool.-]"},
	} {
		if got := render(Diff(Words(tc.a), Words(tc.b))); got != tc.want {
			t.Errorf("%q -> %q:\n got %s\nwant %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestWordsJoinBack(t *testing.T) {
	for _, s := range []string{"", "one", "  leading and  double  spaces ", "tabs\tand\nnewlines\n"} {
		if got := strings.Join(Words(s), ""); got != s {
			t.Errorf("Words(%q) joins to %q", s, got)
		}
	}
}

func TestDiffKeepsBothSides(t *testing.T) {
	a := strings.Split("a b c d e f", " ")
	b := strings.Split("a x c d y f z", " ")
	var gotA, gotB []string
	for _, p := range Diff(a, b) {
		if p.Op != Ins {
			gotA = append(gotA, p.Text)
		}
		if p.Op != Del {
			gotB = append(gotB, p.Text)
		}
	}
	if strings.Join(gotA, " ") != strings.Join(a, " ") || strings.Join(gotB, " ") != strings.Join(b, " ") {
		t.Fatalf("diff does not reproduce its inputs: %v / %v", gotA, gotB)
	}
}

func TestDiffTooLargeFallsBack(t *testing.T) {
	a := make([]string, 2001)
	b := make([]string, 2001)
	for i := range a {
		a[i], b[i] = "x", "x"
	}
	parts := Diff(a, b)
	if len(parts) != len(a)+len(b) || parts[0].Op != Del || parts[len(parts)-1].Op != Ins {
		t.Fatalf("expected the whole-text fallback above the cell limit, got %d parts", len(parts))
	}
}
