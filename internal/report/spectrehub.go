package report

import "encoding/json"

type spectrehubEnvelope struct {
	Schema string `json:"$schema"`
	Data
}

// Generate produces spectrehub/v1 envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	envelope := spectrehubEnvelope{
		Schema: "spectrehub/v1",
		Data:   data,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
