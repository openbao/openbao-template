// Copyright (c) OpenBao contributors
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCertificateRenewalDelay(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{NotBefore: now.Add(-1 * time.Hour), NotAfter: now.Add(9 * time.Hour)}

	tests := []struct {
		name          string
		cert          *x509.Certificate
		threshold     float64
		jitterPercent int
		want          time.Duration
		ok            bool
	}{
		{name: "default threshold", cert: cert, threshold: .90, want: 8 * time.Hour, ok: true},
		{name: "earlier threshold", cert: cert, threshold: .50, want: 4 * time.Hour, ok: true},
		{name: "negative jitter", cert: cert, threshold: .90, jitterPercent: -3, want: 7*time.Hour + 42*time.Minute, ok: true},
		{name: "positive jitter", cert: cert, threshold: .90, jitterPercent: 2, want: 8*time.Hour + 12*time.Minute, ok: true},
		{name: "rotation reached", cert: cert, threshold: .10},
		{name: "expired", cert: &x509.Certificate{NotBefore: now.Add(-10 * time.Hour), NotAfter: now}},
		{name: "missing certificate", threshold: .90},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := certificateRenewalDelay(tc.cert, tc.threshold, now, tc.jitterPercent)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("certificateRenewalDelay() = (%s, %t), want (%s, %t)", got, ok, tc.want, tc.ok)
			}
		})
	}
}
