package report

import "encoding/json"

type jsonEnvelope struct {
	Schema string `json:"$schema"`
	Data
}

// Generate produces spectre/v1 envelope JSON output.
func (r *JSONReporter) Generate(data Data) error {
	envelope := jsonEnvelope{
		Schema: "spectre/v1",
		Data:   data,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
