// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package saml_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/cap/saml"
	testprovider "github.com/hashicorp/cap/saml/test"
	"github.com/stretchr/testify/require"
)

func TestParseResponseRejectsRetargetedSignedAssertion(t *testing.T) {
	t.Parallel()

	provider := testprovider.StartTestProvider(t)
	defer provider.Close()
	config, err := saml.NewConfig(
		"http://hashicorp-cap.test",
		"http://hashicorp-cap.test/saml/acs",
		fmt.Sprintf("%s/saml/metadata", provider.ServerURL()),
	)
	require.NoError(t, err)
	sp, err := saml.NewServiceProvider(config)
	require.NoError(t, err)

	raw := provider.SamlResponse(t, testprovider.WithJustAssertionSigned())
	_, err = sp.ParseResponse(base64.StdEncoding.EncodeToString([]byte(raw)), "test-request-id", saml.ValidateAssertionSignature())
	require.NoError(t, err)

	// Change only the unsigned envelope. The signed assertion still identifies
	// the original request and its signature remains valid.
	original := `InResponseTo="test-request-id"`
	require.Equal(t, 2, strings.Count(raw, original))
	retargeted := strings.Replace(raw, original, `InResponseTo="new-request-id"`, 1)
	_, err = sp.ParseResponse(base64.StdEncoding.EncodeToString([]byte(retargeted)), "new-request-id", saml.ValidateAssertionSignature())
	require.ErrorContains(t, err, "SubjectConfirmationData.InResponseTo")
}
