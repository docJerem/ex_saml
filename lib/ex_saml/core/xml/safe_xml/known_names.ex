defmodule ExSaml.Core.Xml.SafeXml.KnownNames do
  @moduledoc false

  # Element names, attribute names, namespace prefixes and namespace URIs of
  # the vocabularies a SAML service provider legitimately parses: SAML 2.0
  # assertions, protocol messages and metadata (with the common metadata
  # extensions and the WS-Federation elements found in AD FS / Entra ID
  # metadata), XML-DSig 1.0 and 1.1, exclusive canonicalisation, XML
  # Encryption 1.0 and 1.1, XML Schema instance and the `xml:` namespace.
  #
  # `ExSaml.Core.Xml.SafeXml` treats every name of this set as known: a
  # document made only of these names never draws on the atom budget. The set
  # is finite and fixed at compile time, so the atoms it can lead the parser
  # to create are bounded by its size.
  #
  # Each group is `{namespace_uris, prefixes, local_names}`. For a group, the
  # known names are its URIs, every local name (unprefixed form, also used by
  # attributes, which are unqualified in these vocabularies), `xmlns:<prefix>`
  # for each prefix, and `<prefix>:<local>` for each prefix and local name.

  @saml_core_locals ~w(
    Assertion Issuer Subject NameID BaseID EncryptedID SubjectConfirmation
    SubjectConfirmationData Conditions Condition AudienceRestriction Audience
    OneTimeUse ProxyRestriction Advice AssertionIDRef AssertionURIRef
    EncryptedAssertion Statement AuthnStatement SubjectLocality AuthnContext
    AuthnContextClassRef AuthnContextDecl AuthnContextDeclRef
    AuthenticatingAuthority AttributeStatement Attribute AttributeValue
    EncryptedAttribute AuthzDecisionStatement Action Evidence
    Response Status StatusCode StatusMessage StatusDetail Extensions
    AuthnRequest NameIDPolicy Scoping IDPList IDPEntry GetComplete RequesterID
    RequestedAuthnContext LogoutRequest LogoutResponse SessionIndex
    ArtifactResolve ArtifactResponse Artifact AttributeQuery AuthnQuery
    AuthzDecisionQuery AssertionIDRequest SubjectQuery ManageNameIDRequest
    ManageNameIDResponse NewID NewEncryptedID Terminate NameIDMappingRequest
    NameIDMappingResponse
    Version ID IssueInstant Format NameQualifier SPNameQualifier SPProvidedID
    Method NotBefore NotOnOrAfter Recipient InResponseTo Address DNSName
    AuthnInstant SessionNotOnOrAfter Name NameFormat FriendlyName Resource
    Decision Namespace Count Destination Consent Value ForceAuthn IsPassive
    ProtocolBinding AssertionConsumerServiceIndex AssertionConsumerServiceURL
    AttributeConsumingServiceIndex ProviderName AllowCreate Comparison
    ProxyCount Reason Loc
  )

  @metadata_locals ~w(
    EntitiesDescriptor EntityDescriptor Extensions RoleDescriptor
    IDPSSODescriptor SPSSODescriptor AuthnAuthorityDescriptor
    AttributeAuthorityDescriptor PDPDescriptor AffiliationDescriptor
    AffiliateMember KeyDescriptor EncryptionMethod Organization
    OrganizationName OrganizationDisplayName OrganizationURL ContactPerson
    Company GivenName SurName EmailAddress TelephoneNumber
    ArtifactResolutionService SingleLogoutService ManageNameIDService
    NameIDFormat SingleSignOnService NameIDMappingService
    AssertionIDRequestService AttributeProfile AssertionConsumerService
    AttributeConsumingService ServiceName ServiceDescription
    RequestedAttribute AttributeService AuthnQueryService AuthzService
    AdditionalMetadataLocation
    ID validUntil cacheDuration Name entityID protocolSupportEnumeration
    errorURL use Binding Location ResponseLocation index isDefault
    WantAuthnRequestsSigned AuthnRequestsSigned WantAssertionsSigned
    contactType affiliationOwnerID isRequired namespace KeySize
  )

  @dsig_locals ~w(
    Signature SignedInfo CanonicalizationMethod SignatureMethod
    HMACOutputLength Reference Transforms Transform XPath DigestMethod
    DigestValue SignatureValue KeyInfo KeyName KeyValue RSAKeyValue Modulus
    Exponent DSAKeyValue P Q G Y J Seed PgenCounter RetrievalMethod X509Data
    X509IssuerSerial X509IssuerName X509SerialNumber X509SKI X509SubjectName
    X509Certificate X509CRL PGPData PGPKeyID PGPKeyPacket SPKIData SPKISexp
    MgmtData Object Manifest SignatureProperties SignatureProperty
    Id URI Type Algorithm MimeType Encoding Target
  )

  @dsig11_locals ~w(
    ECKeyValue ECParameters NamedCurve PublicKey DEREncodedKeyValue
    KeyInfoReference X509Digest Id URI Algorithm
  )

  @xenc_locals ~w(
    EncryptedData EncryptedKey EncryptionMethod KeySize OAEPparams CipherData
    CipherValue CipherReference EncryptionProperties EncryptionProperty
    ReferenceList DataReference KeyReference CarriedKeyName AgreementMethod
    KA-Nonce OriginatorKeyInfo RecipientKeyInfo DHKeyValue Transforms
    Id Type MimeType Encoding Algorithm Recipient URI
  )

  @xenc11_locals ~w(
    MGF ConcatKDFParams DerivedKey KeyDerivationMethod DerivedKeyName
    MasterKeyName PBKDF2-params Salt Specified IterationCount KeyLength PRF
    AlgorithmID PartyUInfo PartyVInfo SuppPubInfo SuppPrivInfo
    Algorithm Recipient Id Type
  )

  @groups [
    {["urn:oasis:names:tc:SAML:2.0:assertion", "urn:oasis:names:tc:SAML:2.0:protocol"],
     ~w(saml saml2 samlp saml2p), @saml_core_locals},
    {["urn:oasis:names:tc:SAML:2.0:metadata"], ~w(md saml2md), @metadata_locals},
    {["urn:oasis:names:tc:SAML:metadata:ui"], ~w(mdui),
     ~w(UIInfo DisplayName Description Keywords Logo InformationURL
        PrivacyStatementURL DiscoHints IPHint DomainHint GeolocationHint
        height width)},
    {["urn:oasis:names:tc:SAML:metadata:attribute"], ~w(mdattr), ~w(EntityAttributes)},
    {["urn:oasis:names:tc:SAML:metadata:rpi"], ~w(mdrpi),
     ~w(RegistrationInfo RegistrationPolicy PublicationInfo Publication
        UsagePolicy registrationAuthority registrationInstant publisher
        creationInstant publicationId)},
    {["urn:oasis:names:tc:SAML:metadata:algsupport"], ~w(alg mdalg),
     ~w(DigestMethod SigningMethod MinKeySize MaxKeySize Algorithm)},
    {["urn:mace:shibboleth:metadata:1.0"], ~w(shibmd), ~w(Scope KeyAuthority regexp VerifyDepth)},
    {["urn:oasis:names:tc:SAML:profiles:SSO:request-init"], ~w(init),
     ~w(RequestInitiator Binding Location)},
    {["urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"], ~w(idpdisc),
     ~w(DiscoveryResponse Binding Location index isDefault)},
    {["urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"], ~w(x500), ~w(Encoding)},
    {["http://docs.oasis-open.org/wsfed/federation/200706"], ~w(fed),
     ~w(ClaimTypesOffered ClaimTypesRequested TokenTypesOffered TokenType
        SecurityTokenServiceEndpoint PassiveRequestorEndpoint
        ApplicationServiceEndpoint TargetScopes LogicalServiceNamesOffered
        IssuerName SingleSignOutSubscriptionEndpoint
        SingleSignOutNotificationEndpoint ServiceDisplayName
        ServiceDescription Uri Optional)},
    {["http://docs.oasis-open.org/wsfed/authorization/200706"], ~w(auth),
     ~w(ClaimType DisplayName Description Uri Optional)},
    {["http://www.w3.org/2005/08/addressing"], ~w(wsa),
     ~w(EndpointReference Address Metadata ReferenceParameters)},
    {["http://schemas.xmlsoap.org/ws/2004/09/mex"], ~w(mex wsx),
     ~w(Metadata MetadataSection MetadataReference Dialect Identifier)},
    {["http://www.w3.org/2000/09/xmldsig#"], ~w(ds dsig), @dsig_locals},
    {["http://www.w3.org/2009/xmldsig11#"], ~w(dsig11 ds11), @dsig11_locals},
    {["http://www.w3.org/2001/10/xml-exc-c14n#"], ~w(ec), ~w(InclusiveNamespaces PrefixList)},
    {["http://www.w3.org/2001/04/xmlenc#"], ~w(xenc), @xenc_locals},
    {["http://www.w3.org/2009/xmlenc11#"], ~w(xenc11), @xenc11_locals},
    {["http://www.w3.org/2001/XMLSchema-instance"], ~w(xsi),
     ~w(type nil schemaLocation noNamespaceSchemaLocation)},
    {["http://www.w3.org/2001/XMLSchema"], ~w(xs xsd), []},
    {["http://www.w3.org/XML/1998/namespace"], ~w(xml), ~w(lang space base id)}
  ]

  @local_names @groups |> Enum.flat_map(fn {_uris, _prefixes, locals} -> locals end)

  # Plain maps rather than MapSets: a MapSet literal is opaque to Dialyzer.
  @names for {uris, prefixes, locals} <- @groups,
             name <-
               uris ++
                 locals ++
                 Enum.flat_map(prefixes, fn prefix ->
                   ["xmlns:" <> prefix | Enum.map(locals, &(prefix <> ":" <> &1))]
                 end),
             into: %{"" => true, "xmlns" => true, "xml" => true},
             do: {name, true}

  @local_set Map.new(@local_names, &{&1, true})

  @doc "Whether `name` belongs to the built-in SAML vocabulary."
  @spec known?(String.t()) :: boolean()
  def known?(name) when is_binary(name), do: is_map_key(@names, name)

  @doc "Whether `local` is a local name of the built-in SAML vocabulary."
  @spec known_local?(String.t()) :: boolean()
  def known_local?(local) when is_binary(local), do: is_map_key(@local_set, local)
end
