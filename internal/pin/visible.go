package pin

import (
	"fmt"
	"strings"
)

// Visible makes the characters Scan flags readable in a terminal. A run of
// Unicode tag characters becomes ‹tags:"the ASCII they encode"›, and each
// zero-width, bidi or other invisible character becomes ‹U+XXXX›. Everything
// else is unchanged.
func Visible(s string) string {
	var b, tags strings.Builder
	inTags := false
	flush := func() {
		if inTags {
			fmt.Fprintf(&b, "‹tags:%q›", tags.String())
			tags.Reset()
			inTags = false
		}
	}
	for _, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			inTags = true
			if r >= 0xE0020 && r <= 0xE007E {
				tags.WriteRune(r - 0xE0000)
			}
		case isInvisible(r):
			flush()
			fmt.Fprintf(&b, "‹U+%04X›", r)
		default:
			flush()
			b.WriteRune(r)
		}
	}
	flush()
	return b.String()
}
