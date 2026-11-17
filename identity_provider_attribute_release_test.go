package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/attrname"
)

// attributeReleaseRequest builds a validated IdpAuthnRequest whose service
// provider lists services as its AttributeConsumingServices.
func attributeReleaseRequest(t *testing.T, test *IdentityProviderTest, services ...AttributeConsumingService) *IdpAuthnRequest {
	t.Helper()
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	req.SPSSODescriptor.AttributeConsumingServices = services
	return req
}

// attributeReleaseSession is a session carrying a value for every built-in
// field, an employeeNumber in URI/OID form and a departmentNumber in plain
// basic form, both supplied through CustomAttributes: that is how an
// application carries names the fixed Session fields do not cover.
func attributeReleaseSession() *Session {
	return &Session{
		ID:             "session-1",
		UserName:       "alice",
		UserEmail:      "alice@example.com",
		UserGivenName:  "Alice",
		UserSurname:    "Smith",
		UserCommonName: "Alice Smith",
		CustomAttributes: []Attribute{
			{
				FriendlyName: "employeeNumber",
				Name:         attrname.EmployeeNumber,
				NameFormat:   attrname.FormatURI,
				Values:       []AttributeValue{{Type: "xs:string", Value: "EMP-0001"}},
			},
			{
				FriendlyName: "Department number",
				Name:         "departmentNumber",
				NameFormat:   attrname.FormatBasic,
				Values:       []AttributeValue{{Type: "xs:string", Value: "DEPT-42"}},
			},
		},
	}
}

func attributeValues(t *testing.T, req *IdpAuthnRequest) map[string]Attribute {
	t.Helper()
	got := map[string]Attribute{}
	for _, statement := range req.Assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			got[attr.NameFormat+"|"+attr.Name] = attr
		}
	}
	return got
}

// TestIDPAttributeReleaseDrivenByRequest covers request-driven release of a
// non-standard plain attribute name: the request channel used to recognize
// only five hardcoded basic name groups, so any other name was silently
// dropped. Such a name must now resolve against Session.CustomAttributes.
// The classic basic "email" request is the positive control, exercising the
// historical mapping at the same time.
func TestIDPAttributeReleaseDrivenByRequest(t *testing.T) {
	const basic = attrname.FormatBasic
	test := NewIdentityProviderTest(t, applyKey)

	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{
			// Positive control: the existing email scenario, kept working.
			{Attribute: Attribute{FriendlyName: "Email address", Name: "email", NameFormat: basic}},
			// A non-standard basic name none of the five hardcoded groups
			// recognizes, supplied through CustomAttributes.
			{Attribute: Attribute{FriendlyName: "Department number", Name: "departmentNumber", NameFormat: basic}},
		},
	})
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))

	got := attributeValues(t, req)
	email, ok := got[basic+"|email"]
	assert.Assert(t, ok, "the email request must still be answered")
	assert.Check(t, is.Equal("alice@example.com", email.Values[0].Value))
	assert.Check(t, is.Equal("Email address", email.FriendlyName))

	department, ok := got[basic+"|departmentNumber"]
	assert.Assert(t, ok, "a non-standard requested name must not be silently dropped")
	assert.Check(t, is.Equal("DEPT-42", department.Values[0].Value), "it resolves against the session's custom attributes")
	assert.Check(t, is.Equal(basic, department.NameFormat), "the SP's requested NameFormat is kept")
	assert.Check(t, is.Equal("Department number", department.FriendlyName))
}

// TestIDPAttributeReleaseURIFormatOID covers a request using URI-format OID
// names, the case the group SP portal hit: an employeeNumber and a
// URI-format mail request used to produce nothing, because URI-format
// names fell outside the five basic name groups and were never matched.
func TestIDPAttributeReleaseURIFormatOID(t *testing.T) {
	const uri = attrname.FormatURI
	test := NewIdentityProviderTest(t, applyKey)

	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{
			{Attribute: Attribute{FriendlyName: "Employee number", Name: attrname.EmployeeNumber, NameFormat: uri}},
			// Positive control in the same shape: the URI-format mail OID,
			// which session.UserEmail backs.
			{Attribute: Attribute{FriendlyName: "mail", Name: attrname.Mail, NameFormat: uri}},
		},
	})
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))

	got := attributeValues(t, req)

	employee, ok := got[uri+"|"+attrname.EmployeeNumber]
	assert.Assert(t, ok, "a URI-format OID request must not be silently dropped")
	assert.Check(t, is.Equal("EMP-0001", employee.Values[0].Value))
	assert.Check(t, is.Equal(uri, employee.NameFormat))
	assert.Check(t, is.Equal("Employee number", employee.FriendlyName))

	mail, ok := got[uri+"|"+attrname.Mail]
	assert.Assert(t, ok, "the URI-format email OID is the positive control")
	assert.Check(t, is.Equal("alice@example.com", mail.Values[0].Value))
}

// TestIDPAttributeReleaseMinimization covers the minimum-disclosure policy:
// with ReleaseRequestedAttributesOnly, only requested attributes that the
// session can provide are published, in the request's order, and an SP that
// requests nothing receives no attributes at all. Without the flag, the
// historical behavior stands: unrequested attributes are still published.
func TestIDPAttributeReleaseMinimization(t *testing.T) {
	const basic = attrname.FormatBasic
	const uri = attrname.FormatURI

	t.Run("requested only", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.ReleaseRequestedAttributesOnly = true

		req := attributeReleaseRequest(t, test, AttributeConsumingService{
			Index: 0,
			RequestedAttributes: []RequestedAttribute{
				{Attribute: Attribute{FriendlyName: "Email address", Name: "email", NameFormat: basic}},
				{Attribute: Attribute{Name: attrname.EmployeeNumber, NameFormat: uri}},
				// The session cannot satisfy this one: it is omitted, not
				// answered with fabricated data.
				{Attribute: Attribute{Name: attrname.PreferredLanguage, NameFormat: uri}},
			},
		})
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))

		var names []string
		for _, statement := range req.Assertion.AttributeStatements {
			for _, attr := range statement.Attributes {
				names = append(names, attr.Name)
			}
		}
		assert.Check(t, is.DeepEqual([]string{"email", attrname.EmployeeNumber}, names),
			"only satisfiable requested attributes are published, in request order")

		got := attributeValues(t, req)
		assert.Check(t, is.Len(got, 2), "unrequested attributes such as uid, cn or subject-id must not leak")
		_, hasUID := got[uri+"|"+attrname.UID]
		assert.Check(t, !hasUID, "the unrequested uid attribute is withheld")
		_, hasPreferredLanguage := got[uri+"|"+attrname.PreferredLanguage]
		assert.Check(t, !hasPreferredLanguage, "an unsatisfiable request is omitted")
	})

	t.Run("nothing requested means nothing released", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.IDP.ReleaseRequestedAttributesOnly = true

		// An SP whose metadata lists an AttributeConsumingService without
		// RequestedAttributes, and one with no service at all, both get an
		// empty AttributeStatement.
		for _, services := range [][]AttributeConsumingService{
			{{Index: 0}},
			nil,
		} {
			req := attributeReleaseRequest(t, test, services...)
			assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))
			assert.Assert(t, is.Len(req.Assertion.AttributeStatements, 1))
			assert.Check(t, is.Len(req.Assertion.AttributeStatements[0].Attributes, 0),
				"minimum disclosure: no request, no attributes")
		}
	})

	t.Run("flag off keeps the historical full release", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)

		req := attributeReleaseRequest(t, test, AttributeConsumingService{
			Index: 0,
			RequestedAttributes: []RequestedAttribute{
				{Attribute: Attribute{Name: "email", NameFormat: basic}},
			},
		})
		assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))

		got := attributeValues(t, req)
		// The requested attribute, and the unrequested ones the IdP has
		// always published, are both present.
		_, hasEmail := got[basic+"|email"]
		assert.Check(t, hasEmail)
		_, hasUID := got[uri+"|"+attrname.UID]
		assert.Check(t, hasUID, "without the flag, unrequested attributes keep being released")
		_, hasEmployee := got[uri+"|"+attrname.EmployeeNumber]
		assert.Check(t, hasEmployee, "custom attributes keep being released unrequested")
	})
}

// TestIDPAttributeReleaseUnknownAttributeConsumingServiceIndex checks that a
// request naming an AttributeConsumingServiceIndex absent from the SP
// metadata fails with a Requester/RequestUnsupported StatusError instead of
// silently falling back to the default service, rather than being answered
// from a service the SP did not choose.
func TestIDPAttributeReleaseUnknownAttributeConsumingServiceIndex(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.ReleaseRequestedAttributesOnly = true

	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index:     1,
		IsDefault: boolPtr(true),
		RequestedAttributes: []RequestedAttribute{
			{Attribute: Attribute{Name: "email", NameFormat: attrname.FormatBasic}},
		},
	})
	req.Request.AttributeConsumingServiceIndex = "9"

	err := DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession())
	var statusErr *StatusError
	assert.Assert(t, errors.As(err, &statusErr), "got %v", err)
	assert.Check(t, is.Equal(StatusRequester, statusErr.TopLevel))
	assert.Check(t, is.Equal(StatusRequestUnsupported, statusErr.SecondLevel))
}

func boolPtr(v bool) *bool { return &v }

// A basic name that matches no built-in mapping and no session attribute is
// omitted rather than answered with an empty fabricated attribute.
func TestIDPAttributeReleaseUnknownNameIsOmitted(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{
			{Attribute: Attribute{Name: "department", NameFormat: attrname.FormatBasic}},
		},
	})
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))
	got := attributeValues(t, req)
	_, present := got[attrname.FormatBasic+"|department"]
	assert.Check(t, !present)
}

// A RequestedAttribute without a NameFormat means unspecified
// (saml-core §2.7.3.1), which leaves the interpretation of the Name to the
// parties: it matches the attribute of that Name whatever NameFormat the
// session uses, while a different explicit NameFormat does not.
func TestIDPAttributeReleaseUnspecifiedNameFormatMatchesAny(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{
			// No NameFormat: unspecified, matches the URI-format custom
			// attribute by Name.
			{Attribute: Attribute{Name: attrname.EmployeeNumber}},
			// Explicit basic, while the session's attribute is URI-format:
			// the formats differ, so it is not released.
			{Attribute: Attribute{Name: attrname.EmployeeNumber, NameFormat: attrname.FormatBasic}},
		},
	})
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))
	got := attributeValues(t, req)
	unspecified, ok := got[attrname.FormatURI+"|"+attrname.EmployeeNumber]
	assert.Assert(t, ok, "an unspecified-format request matches a URI-format attribute")
	assert.Check(t, is.Equal("EMP-0001", unspecified.Values[0].Value))
	assert.Check(t, is.Equal(attrname.FormatURI, unspecified.NameFormat),
		"with no requested NameFormat the attribute keeps its own format")
	_, wrongFormat := got[attrname.FormatBasic+"|"+attrname.EmployeeNumber]
	assert.Check(t, !wrongFormat, "a NameFormat mismatch must not release the attribute")
}

// Requesting the same attribute twice, once through the plain basic name and
// once under nothing else, must not produce duplicates: de-duplication is by
// Name and NameFormat.
func TestIDPAttributeReleaseDeduplicatesRequests(t *testing.T) {
	const basic = attrname.FormatBasic
	test := NewIdentityProviderTest(t, applyKey)
	req := attributeReleaseRequest(t, test, AttributeConsumingService{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{
			{Attribute: Attribute{Name: "email", NameFormat: basic}},
			{Attribute: Attribute{Name: "email", NameFormat: basic}},
		},
	})
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, attributeReleaseSession()))
	var count int
	for _, statement := range req.Assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if attr.Name == "email" && attr.NameFormat == basic {
				count++
			}
		}
	}
	assert.Check(t, is.Equal(1, count))
}
