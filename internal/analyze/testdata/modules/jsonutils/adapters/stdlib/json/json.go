package json

type Adapter struct{}

func (Adapter) OrderedMarshal(any) ([]byte, error) { return []byte(`{}`), nil }

func (Adapter) OrderedUnmarshal([]byte, any) error { return nil }

type MapSlice []map[string]any

func (MapSlice) MarshalJSON() ([]byte, error) { return []byte(`[]`), nil }

func (*MapSlice) UnmarshalJSON([]byte) error { return nil }

func (MapSlice) OrderedMarshalJSON() ([]byte, error) { return []byte(`[]`), nil }

func (*MapSlice) OrderedUnmarshalJSON([]byte) error { return nil }
