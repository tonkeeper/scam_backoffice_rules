package scam_backoffice_rules

import "testing"

func TestNormalizeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "USD₮", expected: "usdt"},
		{input: "subbotin.ton", expected: "subbotinton"},
		{input: "MAJOR", expected: "major"},
		{input: "TON Believers Fund", expected: "tonbelieversfund"},
		{input: "Tést.ton", expected: "testton"},
		{input: "123USD", expected: "123usd"},
		{input: "  special*chars! ", expected: "specialchars"},
		{input: "Multiple   Spaces", expected: "multiplespaces"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := NormalizeString(test.input)
			if result != test.expected {
				t.Errorf("For input %v, got %v but expected %v", test.input, result, test.expected)
			}
		})
	}
}
