package advisory

import "testing"

func TestContainsVersion(t *testing.T) {
	affected := Affected{Ranges: []Range{{Events: []Event{
		{Introduced: "0"}, {Fixed: "1.2.0"}, {Introduced: "1.3.0"}, {LastAffected: "1.4.0"},
	}}}}
	tests := []struct {
		name    string
		give    string
		want    bool
		wantErr bool
	}{
		{name: "introduced", give: "v0.1.0", want: true},
		{name: "fixed", give: "v1.2.0"},
		{name: "second range", give: "v1.3.1", want: true},
		{name: "last affected inclusive", give: "v1.4.0", want: true},
		{name: "after last affected", give: "v1.4.1"},
		{name: "invalid", give: "local", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := affected.ContainsVersion(tt.give)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ContainsVersion(%q) error = %v, wantErr %v", tt.give, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ContainsVersion(%q) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}

func TestParseRejectsUnsupportedFormat(t *testing.T) {
	if _, err := Parse("cve", nil); err == nil {
		t.Fatal("Parse(cve) succeeded, want unsupported-format error")
	}
}
