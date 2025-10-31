package additionalsourceresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

type rtFunc func(*http.Request) *http.Response

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r), nil }

func newMockClient(fn rtFunc) *http.Client {
	return &http.Client{Transport: fn}
}

func jsonHTTP(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func mustDID(t *testing.T, s string) w3c.DID {
	d, err := w3c.ParseDID(s)
	require.NoError(t, err)
	return *d
}

func didResJSON(t *testing.T, dr *document.DidResolution) string {
	b, err := json.Marshal(dr)
	require.NoError(t, err)
	return string(b)
}

func mkDidRes(
	id string,
	didDocContext interface{},
	vms []verifiable.CommonVerificationMethod,
	auth []verifiable.Authentication,
	svc []interface{},
) *document.DidResolution {
	return &document.DidResolution{
		DidDocument: &verifiable.DIDDocument{
			ID:                 id,
			Context:            didDocContext,
			VerificationMethod: vms,
			Authentication:     auth,
			Service:            svc,
		},
	}
}

func deepEqualDidDoc(t *testing.T, got, want *verifiable.DIDDocument) {
	require.NotNil(t, got)
	require.NotNil(t, want)
	require.Equal(t, want.ID, got.ID, "DID mismatch")

	gb, _ := json.Marshal(got.Context)
	wb, _ := json.Marshal(want.Context)
	require.Equal(t, string(wb), string(gb), "@context mismatch")

	gotVMIDs := make([]string, 0, len(got.VerificationMethod))
	for i := range got.VerificationMethod {
		gotVMIDs = append(gotVMIDs, got.VerificationMethod[i].ID)
	}
	wantVMIDs := make([]string, 0, len(want.VerificationMethod))
	for i := range want.VerificationMethod {
		wantVMIDs = append(wantVMIDs, want.VerificationMethod[i].ID)
	}
	require.ElementsMatch(t, wantVMIDs, gotVMIDs, "verificationMethod mismatch")

	jsonSlice := func(v any) []string {
		b, _ := json.Marshal(v)
		var arr []any
		_ = json.Unmarshal(b, &arr)
		out := make([]string, 0, len(arr))
		for _, it := range arr {
			j, _ := json.Marshal(it)
			out = append(out, string(j))
		}
		return out
	}

	require.ElementsMatch(t, jsonSlice(want.Authentication), jsonSlice(got.Authentication), "authentication mismatch")
	require.ElementsMatch(t, jsonSlice(want.AssertionMethod), jsonSlice(got.AssertionMethod), "assertionMethod mismatch")
	require.ElementsMatch(t, jsonSlice(want.KeyAgreement), jsonSlice(got.KeyAgreement), "keyAgreement mismatch")
	require.ElementsMatch(t, jsonSlice(want.Service), jsonSlice(got.Service), "service mismatch")
}

func TestResolveAndMerge_Table(t *testing.T) {
	const baseURL = "http://resolver.test"
	const theDID = "did:iden3:polygon:amoy:abc"

	tests := []struct {
		name       string
		origin     *document.DidResolution
		additional *document.DidResolution
		httpStatus int
		expected   *document.DidResolution
	}{
		{
			name:   "Origin nil → take additional as-is",
			origin: nil,
			additional: mkDidRes(theDID, []string{"https://www.w3.org/ns/did/v1", "https://schema.iden3.io/core/jsonld"},
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}},
				[]verifiable.Authentication{
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key1",
						},
					},
				},
				[]interface{}{map[string]any{"id": "svc:1", "type": "Foo"}}),
			expected: mkDidRes(theDID, []string{"https://www.w3.org/ns/did/v1", "https://schema.iden3.io/core/jsonld"},
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}},
				[]verifiable.Authentication{
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key1",
						},
					},
				},
				[]interface{}{map[string]any{"id": "svc:1", "type": "Foo"}}),
		},
		{
			name: "404 additional → no-op",
			origin: mkDidRes(theDID, "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}}, nil, nil),
			additional: nil,
			httpStatus: http.StatusNotFound,
			expected: mkDidRes(theDID, "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}}, nil, nil),
		},
		{
			name: "Merge contexts + dedup VMs + append auth/service",
			origin: mkDidRes(theDID, "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}},
				[]verifiable.Authentication{
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key1",
						},
					},
				},
				[]interface{}{map[string]any{"id": "svc:1", "type": "Foo"}},
			),
			additional: mkDidRes(theDID, []string{"https://www.w3.org/ns/did/v1", "https://schema.iden3.io/core/jsonld"},
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}, {ID: theDID + "#vm2"}},
				[]verifiable.Authentication{
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key2",
						},
					},
				},
				[]interface{}{map[string]any{"id": "svc:2", "type": "Bar"}},
			),
			expected: mkDidRes(theDID, []string{"https://www.w3.org/ns/did/v1", "https://schema.iden3.io/core/jsonld"},
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}, {ID: theDID + "#vm2"}},
				[]verifiable.Authentication{
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key1",
						},
					},
					{
						CommonVerificationMethod: verifiable.CommonVerificationMethod{
							ID: "did:iden3:polygon:amoy:abc#key2",
						},
					},
				},
				[]interface{}{map[string]any{"id": "svc:1", "type": "Foo"}, map[string]any{"id": "svc:2", "type": "Bar"}},
			),
		},
		{
			name: "Mismatched DID → merge error → return origin unchanged",
			origin: mkDidRes(theDID, "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}}, nil, nil),
			additional: mkDidRes("did:iden3:polygon:amoy:DIFFERENT", "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: "x#vm"}}, nil, nil),
			expected: mkDidRes(theDID, "https://www.w3.org/ns/did/v1",
				[]verifiable.CommonVerificationMethod{{ID: theDID + "#vm1"}}, nil, nil),
		},
	}

	for i := range tests {
		tc := &tests[i]
		t.Run(tc.name, func(t *testing.T) {
			status := tc.httpStatus
			body := ""
			if tc.additional != nil {
				body = didResJSON(t, tc.additional)
				if status == 0 {
					status = http.StatusOK
				}
			} else if status == 0 {
				status = http.StatusNotFound
			}

			client := newMockClient(func(r *http.Request) *http.Response {
				return jsonHTTP(status, body)
			})

			resolver, err := NewAdditionalSourceResolver(baseURL, client)
			require.NoError(t, err)

			orig := tc.origin
			out, err := resolver.ResolveAndMerge(context.Background(), mustDID(t, theDID), orig)
			require.NoError(t, err)

			if orig == nil {
				require.NotNil(t, out)
			} else {
				require.Same(t, orig, out)
			}

			require.NotNil(t, out)
			require.NotNil(t, tc.expected)
			deepEqualDidDoc(t, out.DidDocument, tc.expected.DidDocument)
		})
	}
}
