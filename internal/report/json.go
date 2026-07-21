package report

import "encoding/json"

type jsonEnvelope struct {
	Schema string `json:"$schema"`
	Data
}

// Generate produces spectre/v1 envelope JSON output.
func (r *JSONReporter) Generate(data Data) error {
	data.Status = resolvedCompletionState(data) // WO-86@v2: retained errors structurally force partial JSON.
	envelope := jsonEnvelope{
		Schema: "spectre/v1",
		Data:   data,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
