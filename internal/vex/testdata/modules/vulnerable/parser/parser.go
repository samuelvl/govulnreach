package jsonutils

func WriteJSON(any) ([]byte, error) { return []byte(`{}`), nil }

func ReadJSON([]byte, any) error { return nil }

func ConcatJSON(values ...[]byte) []byte {
	var result []byte
	for _, value := range values {
		result = append(result, value...)
	}
	return result
}

type JSONMapSlice []map[string]any

func (JSONMapSlice) MarshalJSON() ([]byte, error) { return []byte(`[]`), nil }

func (*JSONMapSlice) UnmarshalJSON([]byte) error { return nil }
