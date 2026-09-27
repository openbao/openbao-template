// Copyright (c) OpenBao contributors
// SPDX-License-Identifier: MPL-2.0

package dependency

import (
	"crypto/x509"
	"math/rand"
	"time"
)

// goodFor returns the time until a certificate should be rotated. As with
// non-renewable secret leases, rotation is staggered around the configured
// fraction of the certificate's original lifetime.
func goodFor(cert *x509.Certificate, threshold float64) (time.Duration, bool) {
	return certificateRenewalDelay(cert, threshold, time.Now().UTC(), rand.Intn(6)-3)
}

func certificateRenewalDelay(cert *x509.Certificate, threshold float64, now time.Time, jitterPercent int) (time.Duration, bool) {
	if cert == nil || !now.Before(cert.NotAfter) {
		return 0, false
	}

	lifespan := cert.NotAfter.Sub(cert.NotBefore)
	rotationTime := cert.NotBefore.Add(time.Duration(float64(lifespan) * (threshold + float64(jitterPercent)/100)))
	sleepFor := rotationTime.Sub(now)
	if sleepFor <= 0 {
		return 0, false
	}
	return sleepFor, true
}
