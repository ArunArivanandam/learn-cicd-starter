package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name    string
		headers http.Header
		want    string
		err     error
	}{
		{
			name:    "Valid Authorization Header",
			headers: http.Header{"Authorization": []string{"ApiKey my-api-key"}},
			want:    "my-api-key",
			err:     nil,
		},
		{
			name:    "No Authorization Header",
			headers: http.Header{},
			want:    "",
			err:     ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header",
			headers: http.Header{"Authorization": []string{"WrongKey my-api-key"}},
			want:    "",
			err:     errors.New("malformed authorization header"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.want {
				t.Errorf("got key %s; want %s", key, tc.want)
			}

			if (err != nil && tc.err == nil) || (err == nil && tc.err != nil) || (err != nil && tc.err != nil && err.Error() != tc.err.Error()) {
				t.Errorf("got error %v; want %v", err, tc.err)
			}
		})
	}
}
