package main

import (
	"strings"
	"testing"
)

func TestRefuseInsecureListen(t *testing.T) {
	cases := []struct {
		insecure bool
		noAuth   bool
		addr     string
		wantErr  string
	}{
		{addr: "127.0.0.1:30970"},
		{addr: "[::1]:30970"},
		{addr: "localhost:30970"},
		{addr: "0.0.0.0:30970", insecure: true},
		{addr: "10.1.2.3:30970", wantErr: "refusing plain HTTP"},
		{addr: ":30970", wantErr: "refusing plain HTTP"},
		{addr: "0.0.0.0:30970", noAuth: true, insecure: true, wantErr: "-no-auth"},
		{addr: "127.0.0.1:30970", noAuth: true},
	}
	for _, tc := range cases {
		err := refuseInsecureListen(tc.addr, tc.insecure, tc.noAuth)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s insecure=%v noauth=%v: %v", tc.addr, tc.insecure, tc.noAuth, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s insecure=%v noauth=%v: got %v, want %q", tc.addr, tc.insecure, tc.noAuth, err, tc.wantErr)
		}
	}
}
