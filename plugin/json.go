package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func ensureNoTrailingJSON(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected trailing JSON")
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return ensureNoTrailingJSON(dec)
}

func rawJSON(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	switch value := v.(type) {
	case json.RawMessage:
		return append(json.RawMessage(nil), value...), nil
	default:
		return json.Marshal(value)
	}
}
