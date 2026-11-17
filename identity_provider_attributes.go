package saml

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/crewjam/saml/attrname"
)

// selectAttributeConsumingService returns the AttributeConsumingService
// whose attributes the assertion must answer. It is the one the request's
// AttributeConsumingServiceIndex names, or, when the request names none,
// the SP's default one: the first marked isDefault="true", else the first
// one (saml-core §3.4.1, saml-metadata §2.4.4.1). An SP without any
// AttributeConsumingService gets an empty one.
//
// When strict is true and the request names an index that the service
// provider's metadata does not list, it returns a *StatusError with
// StatusRequester and StatusRequestUnsupported, rather than silently
// falling back to the default service. The index is the SP's own choice of
// which attributes it needs; answering it as if another service had been
// chosen could send attributes it did not ask for or omit ones it needs, so
// an unknown index, most often a sign of stale IdP metadata, must be
// reported, not hidden. When strict is false, the historical behavior
// stands: the index is ignored and the default service is used, so an IdP
// that has not opted into request-driven release behaves exactly as before.
func (req *IdpAuthnRequest) selectAttributeConsumingService(strict bool) (*AttributeConsumingService, error) {
	spsso := req.SPSSODescriptor
	if spsso == nil || len(spsso.AttributeConsumingServices) == 0 {
		return &AttributeConsumingService{}, nil
	}
	index := req.Request.AttributeConsumingServiceIndex
	if index == "" || !strict {
		return defaultAttributeConsumingService(spsso), nil
	}
	// The index is an xs:unsignedShort (saml-core §3.4.1), whose whitespace
	// is collapsed, and which may carry a leading "+".
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.Trim(index, " \t\r\n"), "+"), 10, 16)
	if err == nil {
		for i := range spsso.AttributeConsumingServices {
			if spsso.AttributeConsumingServices[i].Index == int(n) {
				return &spsso.AttributeConsumingServices[i], nil
			}
		}
	}
	return nil, fmt.Errorf("the request names attribute consuming service %q, which the service provider's metadata does not list: %w",
		index, &StatusError{
			TopLevel:    StatusRequester,
			SecondLevel: StatusRequestUnsupported,
			Message:     "the requested attribute consuming service is not in the service provider's metadata",
		})
}

// makeRequestedAttribute builds the assertion Attribute that answers
// requested, or nil when the IdP has no value for it. The returned
// attribute keeps the Name and NameFormat the service provider asked for,
// since those are what it will look the attribute up by.
func (req *IdpAuthnRequest) makeRequestedAttribute(requested RequestedAttribute, session *Session, available []Attribute) *Attribute {
	// "If no NameFormat value is provided, the identifier
	// urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified ... is in
	// effect" (saml-core §2.7.3.1).
	switch requested.NameFormat {
	case "", attrname.FormatBasic, attrname.FormatUnspecified:
		return req.makeBasicRequestedAttribute(requested, session, available)
	default:
		// A URI-format name, or any other NameFormat, is an exact name: the
		// IdP must not guess what an OID means (saml-core §1.3.1, exact
		// binary comparison). Look for an attribute the session carries
		// under that Name instead of dropping the request.
		return makeAttributeByName(requested, available)
	}
}

// makeBasicRequestedAttribute answers a RequestedAttribute whose NameFormat
// is basic or unspecified. The five groups of plain names this IdP has
// always understood are matched with punctuation removed but
// case-sensitively; a name none of them matches is looked up exactly, by
// Name, among the session's attributes, so that an uncommon plain attribute
// name the application supplies through Session.CustomAttributes is not
// silently discarded either.
func (req *IdpAuthnRequest) makeBasicRequestedAttribute(requested RequestedAttribute, session *Session, available []Attribute) *Attribute {
	// The name is compared case-sensitively: string values "MUST be compared
	// using an exact binary comparison" and implementations "MUST NOT depend
	// on case-insensitive string comparisons" (saml-core §1.3.1).
	// Punctuation is removed before comparing, as this code always has, so
	// "email_address" matches "emailaddress"; that is a convenience beyond
	// the specification.
	switch nonAlphanumeric.ReplaceAllString(requested.Name, "") {
	case "email", "emailaddress":
		return requestedAttributeWithValue(requested, session.UserEmail)
	case "name", "fullname", "cn", "commonname":
		return requestedAttributeWithValue(requested, session.UserCommonName)
	case "givenname", "firstname":
		return requestedAttributeWithValue(requested, session.UserGivenName)
	case "surname", "lastname", "familyname":
		return requestedAttributeWithValue(requested, session.UserSurname)
	case "uid", "user", "userid":
		return requestedAttributeWithValue(requested, session.UserName)
	}
	// No built-in mapping: the application may supply the attribute itself,
	// under the same Name, in Session.CustomAttributes. FriendlyName is not
	// used for identification (saml-core §2.7.3.1). A request without a
	// NameFormat means unspecified, which leaves the Name to the parties and
	// matches an attribute of any NameFormat; makeAttributeByName applies
	// that rule.
	return makeAttributeByName(requested, available)
}

// requestedAttributeWithValue returns an Attribute that answers requested
// with value. It is always non-nil, even when value is empty: the service
// provider asked for the attribute, and the IdP has historically answered
// such requests with an empty value rather than omitting the attribute.
func requestedAttributeWithValue(requested RequestedAttribute, value string) *Attribute {
	return &Attribute{
		FriendlyName: requested.FriendlyName,
		Name:         requested.Name,
		NameFormat:   requested.NameFormat,
		Values: []AttributeValue{{
			Type:  "xs:string",
			Value: value,
		}},
	}
}

// makeAttributeByName returns the attribute the session carries under the
// Name requested asks for, re-badged with the Name, NameFormat and
// FriendlyName the service provider used in its request, or nil when the
// session carries none. Comparison is exact and case-sensitive
// (saml-core §1.3.1); a RequestedAttribute without a NameFormat asks for an
// unspecified-format name and matches an attribute of any NameFormat, as in
// x/samlidp's FilterAttributes.
func makeAttributeByName(requested RequestedAttribute, available []Attribute) *Attribute {
	for i := range available {
		attr := &available[i]
		if attr.Name != requested.Name {
			continue
		}
		if requested.NameFormat != "" && requested.NameFormat != attrname.FormatUnspecified &&
			requested.NameFormat != attr.NameFormat {
			continue
		}
		return rebadgeAttribute(requested, attr)
	}
	return nil
}

// rebadgeAttribute returns attr presented as requested: the SP's own Name,
// NameFormat and FriendlyName (falling back to the attribute's
// FriendlyName when the request gives none), with a copy of the values so
// the assertion never aliases the session.
func rebadgeAttribute(requested RequestedAttribute, attr *Attribute) *Attribute {
	released := &Attribute{
		Name:       requested.Name,
		NameFormat: requested.NameFormat,
		Values:     append([]AttributeValue(nil), attr.Values...),
	}
	if requested.FriendlyName != "" {
		released.FriendlyName = requested.FriendlyName
	} else {
		released.FriendlyName = attr.FriendlyName
	}
	if released.NameFormat == "" {
		released.NameFormat = attr.NameFormat
	}
	return released
}

// sessionAttributes returns every attribute the session makes available to
// assertions, in the order MakeAssertion emits it. It is the universe
// against which requested names that have no built-in mapping are
// resolved, including the application's own Session.CustomAttributes,
// which is how uncommon and URI-format names the fixed Session fields do
// not cover reach the assertion.
func sessionAttributes(session *Session) []Attribute {
	attributes := make([]Attribute, 0, len(session.CustomAttributes)+10)
	if session.UserName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "uid",
			Name:         attrname.UID,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserName}},
		})
	}
	if session.UserEmail != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "mail",
			Name:         attrname.Mail,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserEmail}},
		})
	}
	if session.EduPersonPrincipalName != "" || session.UserEmail != "" {
		value := session.EduPersonPrincipalName
		if value == "" {
			// We used to set eduPersonPrincipalName
			// (urn:oid:1.3.6.1.4.1.5923.1.1.1.6) to the value of
			// session.UserEmail. It is more correct to set mail
			// (urn:oid:0.9.2342.19200300.100.1.3). To avoid breaking things,
			// we preserve the former behavior.
			value = session.UserEmail
		}
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         attrname.EduPersonPrincipalName,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: value}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "sn",
			Name:         attrname.Surname,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserSurname}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "givenName",
			Name:         attrname.GivenName,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserGivenName}},
		})
	}
	if session.UserCommonName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "cn",
			Name:         attrname.CommonName,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserCommonName}},
		})
	}
	if session.UserScopedAffiliation != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonScopedAffiliation",
			Name:         attrname.EduPersonScopedAffiliation,
			NameFormat:   attrname.FormatURI,
			Values:       []AttributeValue{{Type: "xs:string", Value: session.UserScopedAffiliation}},
		})
	}
	// Copy the custom attributes and their value slices so the assertion
	// never aliases Session.CustomAttributes, which the application may
	// still mutate or reuse.
	for _, custom := range session.CustomAttributes {
		attributes = append(attributes, Attribute{
			FriendlyName: custom.FriendlyName,
			Name:         custom.Name,
			NameFormat:   custom.NameFormat,
			Values:       append([]AttributeValue(nil), custom.Values...),
		})
	}
	if len(session.Groups) != 0 {
		groupMemberAttributeValues := make([]AttributeValue, 0, len(session.Groups))
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         attrname.EduPersonAffiliation,
			NameFormat:   attrname.FormatURI,
			Values:       groupMemberAttributeValues,
		})
	}
	if session.SubjectID != "" {
		attributes = append(attributes, Attribute{
			Name:       attrname.SubjectID,
			NameFormat: attrname.FormatURI,
			Values:     []AttributeValue{{Type: "xs:string", Value: session.SubjectID}},
		})
	}
	return attributes
}

// attributeKey identifies an attribute for de-duplication: the same
// attribute, whether it answered a request or was released unrequested,
// must not appear twice.
func attributeKey(attr Attribute) string {
	return attr.NameFormat + "\x00" + attr.Name
}

// releaseRequestedOnly reports whether the IdP must release only the
// attributes the service provider asks for.
func (idp *IdentityProvider) releaseRequestedOnly() bool {
	return idp != nil && idp.ReleaseRequestedAttributesOnly
}
