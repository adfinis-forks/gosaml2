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

package types

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNameIDRetainsOptionalAttributes(t *testing.T) {
	t.Parallel()

	var subject Subject
	err := xml.Unmarshal([]byte(`
<Subject xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <NameID
    NameQualifier="https://idp.example.test"
    SPNameQualifier="https://sp.example.test"
    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    SPProvidedID="sp-local-id">opaque-subject</NameID>
</Subject>`), &subject)
	require.NoError(t, err)
	require.NotNil(t, subject.NameID)
	require.Equal(t, "https://idp.example.test", *subject.NameID.NameQualifier)
	require.Equal(t, "https://sp.example.test", *subject.NameID.SPNameQualifier)
	require.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", *subject.NameID.Format)
	require.Equal(t, "sp-local-id", *subject.NameID.SPProvidedID)
	require.Equal(t, "opaque-subject", subject.NameID.Value)
}

func TestNameIDAllowsOmittedOptionalAttributes(t *testing.T) {
	t.Parallel()

	var subject Subject
	err := xml.Unmarshal([]byte(`
<Subject xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <NameID>opaque-subject</NameID>
</Subject>`), &subject)
	require.NoError(t, err)
	require.NotNil(t, subject.NameID)
	require.Nil(t, subject.NameID.NameQualifier)
	require.Nil(t, subject.NameID.SPNameQualifier)
	require.Nil(t, subject.NameID.Format)
	require.Nil(t, subject.NameID.SPProvidedID)
	require.Equal(t, "opaque-subject", subject.NameID.Value)

	encoded, err := xml.Marshal(subject.NameID)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "NameQualifier=")
	require.NotContains(t, string(encoded), "SPNameQualifier=")
	require.NotContains(t, string(encoded), "Format=")
	require.NotContains(t, string(encoded), "SPProvidedID=")
}

func TestNameIDPreservesPresentEmptyAttributes(t *testing.T) {
	t.Parallel()

	var nameID NameID
	err := xml.Unmarshal([]byte(`<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="" SPProvidedID="">opaque-subject</NameID>`), &nameID)
	require.NoError(t, err)
	require.NotNil(t, nameID.NameQualifier)
	require.Empty(t, *nameID.NameQualifier)
	require.NotNil(t, nameID.SPProvidedID)
	require.Empty(t, *nameID.SPProvidedID)

	encoded, err := xml.Marshal(nameID)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `NameQualifier=""`)
	require.Contains(t, string(encoded), `SPProvidedID=""`)
}
