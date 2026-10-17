package analyze

// knownMalicious lists packages with a public, verified incident report,
// keyed by provider namespace/type. Keep entries to confirmed cases only,
// each with its reference; suspicion belongs in the heuristic rules.
var knownMalicious = map[string]string{
	"kreuzwenker/docker": "Corgea, September 2026: typosquat that unpacked and ran a hidden Go payload",
}
