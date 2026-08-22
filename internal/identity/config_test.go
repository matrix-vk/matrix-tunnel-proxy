package identity

import (
	"encoding/json"
	"testing"
)

func TestJSONAndYAMLRoundTrip(t *testing.T) {
	want := Config{Role: "client", ClientID: "cli_test", Server: "edge.example.com:7000", Token: "secret:token", CAPEM: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"}
	jsonContents, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := Parse(jsonContents)
	if err != nil {
		t.Fatal(err)
	}
	if fromJSON.ClientID != want.ClientID || fromJSON.Token != want.Token || fromJSON.CAPEM != want.CAPEM {
		t.Fatalf("JSON round trip mismatch: %#v", fromJSON)
	}
	fromYAML, err := Parse(MarshalYAML(want))
	if err != nil {
		t.Fatal(err)
	}
	if fromYAML.ClientID != want.ClientID || fromYAML.Token != want.Token || fromYAML.CAPEM != want.CAPEM {
		t.Fatalf("YAML round trip mismatch: %#v", fromYAML)
	}
}
