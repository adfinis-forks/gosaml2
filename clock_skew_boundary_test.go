// Copyright 2016 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml2

import (
	"testing"
	"time"

	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestClockSkewAppliesToAssertionConditions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	const skew = time.Minute
	tests := []struct {
		name         string
		notBefore    time.Time
		notOnOrAfter time.Time
		clockSkew    time.Duration
		invalid      bool
	}{
		{
			name:      "future NotBefore at skew boundary",
			notBefore: now.Add(skew), notOnOrAfter: now.Add(time.Hour), clockSkew: skew,
		},
		{
			name:      "future NotBefore beyond skew",
			notBefore: now.Add(skew + time.Nanosecond), notOnOrAfter: now.Add(time.Hour),
			clockSkew: skew, invalid: true,
		},
		{
			name:      "expired within skew",
			notBefore: now.Add(-time.Hour), notOnOrAfter: now.Add(-skew + time.Nanosecond), clockSkew: skew,
		},
		{
			name:      "expiry at exclusive skew boundary",
			notBefore: now.Add(-time.Hour), notOnOrAfter: now.Add(-skew), clockSkew: skew, invalid: true,
		},
		{
			name:      "negative skew fails closed",
			notBefore: now.Add(time.Nanosecond), notOnOrAfter: now.Add(time.Hour),
			clockSkew: -skew, invalid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sp := &SAMLServiceProvider{
				Clock:     dsig.NewFakeClockAt(now),
				ClockSkew: test.clockSkew,
			}
			warnings, err := sp.VerifyAssertionConditions(&types.Assertion{
				Conditions: &types.Conditions{
					NotBefore:    test.notBefore.Format(time.RFC3339Nano),
					NotOnOrAfter: test.notOnOrAfter.Format(time.RFC3339Nano),
				},
			})
			if err != nil {
				t.Fatalf("VerifyAssertionConditions() error = %v", err)
			}
			if warnings.InvalidTime != test.invalid {
				t.Fatalf("InvalidTime = %t, want %t", warnings.InvalidTime, test.invalid)
			}
		})
	}
}

func TestClockSkewAppliesToSubjectConfirmationExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	const skew = time.Minute
	tests := []struct {
		name         string
		notOnOrAfter time.Time
		wantErr      bool
	}{
		{name: "expired within skew", notOnOrAfter: now.Add(-skew + time.Nanosecond)},
		{name: "expiry at exclusive skew boundary", notOnOrAfter: now.Add(-skew), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sp := &SAMLServiceProvider{
				AssertionConsumerServiceURL: "https://sp.example.test/callback",
				Clock:                       dsig.NewFakeClockAt(now),
				ClockSkew:                   skew,
			}
			response := &types.Response{
				Version: "2.0",
				Issuer:  &types.Issuer{},
				Status:  &types.Status{StatusCode: &types.StatusCode{Value: StatusCodeSuccess}},
				Assertions: []types.Assertion{{
					Issuer: &types.Issuer{},
					Subject: &types.Subject{SubjectConfirmation: &types.SubjectConfirmation{
						Method: SubjMethodBearer,
						SubjectConfirmationData: &types.SubjectConfirmationData{
							Recipient:    sp.AssertionConsumerServiceURL,
							NotOnOrAfter: test.notOnOrAfter.Format(time.RFC3339Nano),
						},
					}},
				}},
			}
			err := sp.Validate(response)
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}
