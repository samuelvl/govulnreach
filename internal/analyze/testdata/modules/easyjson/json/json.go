package json

type Adapter struct{}

func (Adapter) OrderedMarshal(any) ([]byte, error) { return []byte(`{}`), nil }

func (Adapter) OrderedUnmarshal([]byte, any) error { return nil }

type MapItem struct{}

func (MapItem) MarshalEasyJSON() []byte { return []byte(`{}`) }

func (*MapItem) UnmarshalEasyJSON([]byte) error { return nil }

type MapSlice []MapItem

func (MapSlice) MarshalEasyJSON() []byte { return []byte(`[]`) }

func (*MapSlice) UnmarshalEasyJSON([]byte) error { return nil }

func (MapSlice) MarshalJSON() ([]byte, error) { return []byte(`[]`), nil }

func (*MapSlice) UnmarshalJSON([]byte) error { return nil }

func (MapSlice) OrderedMarshalJSON() ([]byte, error) { return []byte(`[]`), nil }

func (*MapSlice) OrderedUnmarshalJSON([]byte) error { return nil }
