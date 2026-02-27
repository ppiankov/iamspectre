package report

import "encoding/json"

type spectrehubEnvelope struct {
	Schema string `json:"schema"`
	Data
}

// Generate produces spectre/v1 envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	envelope := spectrehubEnvelope{
		Schema: "spectre/v1",
		Data:   data,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
