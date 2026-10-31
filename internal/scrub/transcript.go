package scrub

import "regexp"

// ansi matches terminal escape sequences: CSI (colours, cursor moves), OSC
// (titles, hyperlinks; BEL- or ST-terminated) and two-byte escapes.
var ansi = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|\x1b[@-Z\\\\-_]")

// StripANSI removes terminal escape sequences.
func StripANSI(text string) string { return ansi.ReplaceAllString(text, "") }

// Transcript scrubs a session transcript with the session's set (nil for the
// process-wide one): escape sequences are stripped first, so a colour code
// inside a token cannot split it past both layers.
func Transcript(set *Set, text string) string {
	if set == nil {
		set = global
	}
	return set.String(StripANSI(text))
}
