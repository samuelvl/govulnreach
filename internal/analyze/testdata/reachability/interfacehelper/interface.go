package interfacehelper

type marshaler interface {
	MarshalJSON() ([]byte, error)
}

func Marshal(value marshaler) { _, _ = value.MarshalJSON() }
