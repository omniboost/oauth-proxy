package types

import (
	"strings"
	"testing"
)

func Test_encryptString(t *testing.T) {
	newIV = func() string {
		return "cEyVqCcgQK5Uk2fF0Iy7cA=="
	}
	type args struct {
		plain string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "basic encryption",
			args: args{
				plain: "9893d1a0-66b3-4b49-b509-af4097991c38",
			},
			want:    "eyJpdiI6ImNFeVZxQ2NnUUs1VWsyZkYwSXk3Y0E9PSIsInZhbHVlIjoiWUNwcnBWaE4wekh2MnFNQ3NNaDNTZjlqY2x1VVlSakpTUTVZaWtEaWhXRkJJR1F0a1NrNE01d2xlL1UzSGFHYyIsIm1hYyI6IjIxMjlmZjZkMDRhYWFmOTI4NTVkNDEyZjcwOWI1YzU1NjVhYThiNjI1MjczNmE2ZThhNGI4ODY5YzFjODdmOWIiLCJ0YWciOiIifQ==",
			wantErr: false,
		},
		{
			name: "256 chars",
			args: args{
				plain: strings.Repeat("a", 256),
			},
			want:    "eyJpdiI6ImNFeVZxQ2NnUUs1VWsyZkYwSXk3Y0E9PSIsInZhbHVlIjoiYm5nQzkvaG9vcEtubGZWand6YUpqZ1hXcEdLV0loSHZ4cUtEalpBblZwb2R0dTA5QjZ6c0dlWkxRQTl2M2g3dmNsSkwxQU5TNmRhZGE1NXNtL25IOURtZ0dIQU1FWC9XVzFGZ0xUMmJmb0YvQTUvTEErNW4rSGVYb3VUaTFxYWFET0E4REJBdW50ajhCRFNRS1RXWEZBOUNLeXZ2MXFRWlk5YWxxME5ES05paHBkWEFLQ1I5N0E1cWFLcm9Yc3M4andvbjNwcFBGTk45TDF5M25FNGtpeGhwdkJMQjVJY01PZjB3dWRlZ293TXFDL3dObnRmRXZ5SlNWUlJWdzYrQWU0cW42clJ4T0h1RkhGcWNGazFFTnMza0VjTHRxSjVsN3ZsMi9MaTl5RksxMDlaLzhubXEvU0pRNUl5UStEVGcvdEJEVDFxQnhTQnFTM0JFSFdZMkhOcHBiWVdQNmprYVZmUlJTWWFBYmhFPSIsIm1hYyI6IjIxYmQ2Yjk0YmJlYjYzZWRhZDdiZjM5NzEyNTkwZmVmNDI5NjZlNDU1NGJjNzFiYzIzYjZhMzExZjExOGZiNTYiLCJ0YWciOiIifQ==",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptString(tt.args.plain)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("encryptString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decryptString(t *testing.T) {
	type args struct {
		encrypted string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "basic decryption",
			args: args{
				encrypted: "eyJpdiI6ImNFeVZxQ2NnUUs1VWsyZkYwSXk3Y0E9PSIsInZhbHVlIjoiWUNwcnBWaE4wekh2MnFNQ3NNaDNTZjlqY2x1VVlSakpTUTVZaWtEaWhXRkJJR1F0a1NrNE01d2xlL1UzSGFHYyIsIm1hYyI6IjIxMjlmZjZkMDRhYWFmOTI4NTVkNDEyZjcwOWI1YzU1NjVhYThiNjI1MjczNmE2ZThhNGI4ODY5YzFjODdmOWIiLCJ0YWciOiIifQ==",
			},
			want:    "9893d1a0-66b3-4b49-b509-af4097991c38",
			wantErr: false,
		},
		{
			name: "unencrypted string",
			args: args{
				encrypted: "plain-string-without-encryption",
			},
			want:    "plain-string-without-encryption",
			wantErr: false,
		},
		{
			name: "invalid hmac",
			args: args{
				encrypted: "eyJpdiI6IndHZTJCOStVUXZrQjVBMXExVVJxelE9PSIsInZhbHVlIjoiQzlaSGgxQlgxUEloUnFqZFNpUEJyK0hFOFprTVdBK0xqOTdOTm5ZaENTTHlveHRxMkJkc3MyZ05OQjdqM0k0cis0TzVJOEE3bytrREtFUDFoQStSZ0xuWmlDZEkwWVFDWHlING9tZVY3Y28wd0QrMmUwRmhEL2RIaUpjWXJveG4iLCJtYWMiOiJiYjJhNjA2NGI3YWQzN2JjM2ZkMDYyZTMyOWQ0NDkzZDY0N2Q0YzEwNWU3ZTg1ODVlOGVmMzg5OGNmY2MxZGE3IiwidGFnIjoiIn0=",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decryptString(tt.args.encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("decryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decryptString() got = %v, want %v", got, tt.want)
			}
		})
	}
}
