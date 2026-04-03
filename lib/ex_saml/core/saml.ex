defmodule ExSaml.Core.Saml do
  @moduledoc """
  Core SAML protocol module for encoding and decoding SAML messages.

  Ported from the Erlang `esaml` module. Provides functions for:
  - Decoding SAML responses, assertions, logout requests/responses, and IdP metadata
  - Validating assertions
  - Converting SAML structs to XML
  """

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlAttribute, Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlNamespace, Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl"))

  alias ExSaml.Core.{
    Assertion,
    AuthnRequest,
    Contact,
    IdpMetadata,
    LogoutRequest,
    LogoutResponse,
    Org,
    Response,
    SpMetadata,
    Subject
  }

  # ---------------------------------------------------------------------------
  # SAML namespace definitions
  # ---------------------------------------------------------------------------

  @saml_namespaces [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"},
    {~c"md", :"urn:oasis:names:tc:SAML:2.0:metadata"},
    {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}
  ]

  @protocol_namespaces [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @metadata_namespaces [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"},
    {~c"md", :"urn:oasis:names:tc:SAML:2.0:metadata"}
  ]

  # ---------------------------------------------------------------------------
  # Mapping functions (private)
  # ---------------------------------------------------------------------------

  @spec nameid_map(String.t()) :: atom()
  defp nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), do: :email
  defp nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"), do: :x509
  defp nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"), do: :windows
  defp nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"), do: :krb
  defp nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), do: :persistent
  defp nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"), do: :transient
  defp nameid_map(_), do: :unknown

  @spec nameid_name_qualifier_map(String.t()) :: nil | String.t()
  defp nameid_name_qualifier_map(""), do: nil
  defp nameid_name_qualifier_map(s) when is_list(s), do: s

  @spec nameid_sp_name_qualifier_map(String.t()) :: nil | String.t()
  defp nameid_sp_name_qualifier_map(""), do: nil
  defp nameid_sp_name_qualifier_map(s) when is_list(s), do: s

  @spec nameid_format_map(String.t()) :: nil | String.t()
  defp nameid_format_map(""), do: nil
  defp nameid_format_map(s) when is_list(s), do: s

  @spec subject_method_map(String.t()) :: :bearer | :unknown
  defp subject_method_map("urn:oasis:names:tc:SAML:2.0:cm:bearer"), do: :bearer
  defp subject_method_map(_), do: :unknown

  @spec status_code_map(String.t()) :: atom()
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:Success"), do: :success
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"), do: :bad_version
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"), do: :authn_failed
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"), do: :bad_attr
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"), do: :denied
  defp status_code_map("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"), do: :bad_binding

  defp status_code_map(urn) when is_list(urn) do
    case urn do
      ~c"urn:" ++ _ ->
        urn
        |> to_string()
        |> String.split(":")
        |> List.last()

      _ ->
        :unknown
    end
  end

  defp status_code_map(_), do: :unknown

  @spec rev_status_code_map(atom()) :: String.t()
  defp rev_status_code_map(:success), do: "urn:oasis:names:tc:SAML:2.0:status:Success"
  defp rev_status_code_map(:bad_version), do: "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
  defp rev_status_code_map(:authn_failed), do: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
  defp rev_status_code_map(:bad_attr), do: "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
  defp rev_status_code_map(:denied), do: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
  defp rev_status_code_map(:bad_binding), do: "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
  defp rev_status_code_map(_), do: :erlang.error(:bad_status_code)

  @spec logout_reason_map(String.t()) :: atom()
  defp logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:user"), do: :user
  defp logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:admin"), do: :admin
  defp logout_reason_map(_), do: :unknown

  @spec rev_logout_reason_map(atom()) :: String.t()
  defp rev_logout_reason_map(:user), do: "urn:oasis:names:tc:SAML:2.0:logout:user"
  defp rev_logout_reason_map(:admin), do: "urn:oasis:names:tc:SAML:2.0:logout:admin"

  @spec common_attrib_map(String.t()) :: atom()
  defp common_attrib_map("urn:oid:2.16.840.1.113730.3.1.3"), do: :employeeNumber
  defp common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"), do: :eduPersonPrincipalName
  defp common_attrib_map("urn:oid:0.9.2342.19200300.100.1.3"), do: :mail
  defp common_attrib_map("urn:oid:2.5.4.42"), do: :givenName
  defp common_attrib_map("urn:oid:2.16.840.1.113730.3.1.241"), do: :displayName
  defp common_attrib_map("urn:oid:2.5.4.3"), do: :commonName
  defp common_attrib_map("urn:oid:2.5.4.20"), do: :telephoneNumber
  defp common_attrib_map("urn:oid:2.5.4.10"), do: :organizationName
  defp common_attrib_map("urn:oid:2.5.4.11"), do: :organizationalUnitName
  defp common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.9"), do: :eduPersonScopedAffiliation
  defp common_attrib_map("urn:oid:2.16.840.1.113730.3.1.4"), do: :employeeType
  defp common_attrib_map("urn:oid:0.9.2342.19200300.100.1.1"), do: :uid
  defp common_attrib_map("urn:oid:2.5.4.4"), do: :surName

  defp common_attrib_map(uri) when is_list(uri), do: common_attrib_map(to_string(uri))

  defp common_attrib_map("http://" <> _ = uri) do
    uri |> String.split("/") |> List.last()
  end

  defp common_attrib_map(other) when is_binary(other), do: other

  # ---------------------------------------------------------------------------
  # XPath helpers (private)
  # ---------------------------------------------------------------------------

  defp xpath_attr(xml, path, ns) do
    case :xmerl_xpath.string(to_charlist(path), xml, [{:namespace, ns}]) do
      [attr] when Record.is_record(attr, :xmlAttribute) ->
        {:ok, to_string(xmlAttribute(attr, :value))}

      _ ->
        :not_found
    end
  end

  defp xpath_text(xml, path, ns) do
    case :xmerl_xpath.string(to_charlist(path), xml, [{:namespace, ns}]) do
      [text] when Record.is_record(text, :xmlText) ->
        {:ok, to_string(xmlText(text, :value))}

      _ ->
        :not_found
    end
  end

  defp xpath_elems(xml, path, ns) do
    :xmerl_xpath.string(to_charlist(path), xml, [{:namespace, ns}])
  end

  # ---------------------------------------------------------------------------
  # Decode functions (public)
  # ---------------------------------------------------------------------------

  @doc """
  Decodes an IdP metadata XML element into an `ExSaml.Core.IdpMetadata` struct.
  """
  @spec decode_idp_metadata(tuple()) :: {:ok, IdpMetadata.t()} | {:error, term()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def decode_idp_metadata(xml) do
    ns = @saml_namespaces

    with {:ok, entity_id} <-
           require_attr(xml, "/md:EntityDescriptor/@entityID", ns, :bad_entity),
         {:ok, login_location} <-
           require_attr(
             xml,
             "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
             ns,
             :missing_sso_location
           ) do
      logout_location =
        case xpath_attr(
               xml,
               "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
               ns
             ) do
          {:ok, v} -> v
          :not_found -> nil
        end

      name_format =
        case xpath_text(
               xml,
               "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()",
               ns
             ) do
          {:ok, v} -> nameid_map(v)
          :not_found -> :unknown
        end

      certificate =
        case xpath_text(
               xml,
               "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()",
               ns
             ) do
          {:ok, v} -> :base64.decode(:erlang.list_to_binary(v))
          :not_found -> nil
        end

      tech =
        decode_optional_sub(
          xml,
          "/md:EntityDescriptor/md:ContactPerson[@contactType='technical']",
          ns,
          &decode_contact/1,
          %Contact{}
        )

      org = decode_optional_org(xml, ns)

      {:ok,
       %IdpMetadata{
         entity_id: entity_id,
         login_location: login_location,
         logout_location: logout_location,
         name_format: name_format,
         certificate: certificate,
         tech: tech,
         org: org
       }}
    end
  end

  defp decode_optional_sub(xml, path, ns, decode_fn, default) do
    case xpath_elems(xml, path, ns) do
      [elem | _] ->
        case decode_fn.(elem) do
          {:ok, val} -> val
          _ -> default
        end

      _ ->
        default
    end
  end

  defp decode_optional_org(xml, ns) do
    case xpath_elems(xml, "/md:EntityDescriptor/md:Organization", ns) do
      [elem | _] ->
        case decode_org(elem) do
          {:ok, o} -> o
          _ -> %Org{}
        end

      _ ->
        %Org{}
    end
  end

  @doc """
  Decodes a SAML Response XML element into an `ExSaml.Core.Response` struct.
  """
  @spec decode_response(tuple()) :: {:ok, Response.t()} | {:error, term()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def decode_response(xml) do
    ns = @protocol_namespaces

    with {:ok, version} <-
           require_attr(xml, "/samlp:Response/@Version", ns, :bad_version),
         {:ok, issue_instant} <-
           require_attr(xml, "/samlp:Response/@IssueInstant", ns, :bad_response) do
      destination =
        case xpath_attr(xml, "/samlp:Response/@Destination", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      issuer =
        case xpath_text(xml, "/samlp:Response/saml:Issuer/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      status =
        case xpath_attr(xml, "/samlp:Response/samlp:Status/samlp:StatusCode/@Value", ns) do
          {:ok, v} -> status_code_map(v)
          :not_found -> :unknown
        end

      assertion_result =
        case xpath_elems(xml, "/samlp:Response/saml:Assertion", ns) do
          [elem | _] -> decode_assertion(elem)
          _ -> {:ok, %Assertion{}}
        end

      case assertion_result do
        {:ok, assertion} ->
          {:ok,
           %Response{
             version: version,
             issue_instant: issue_instant,
             destination: destination,
             issuer: issuer,
             status: status,
             assertion: assertion
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Decodes a SAML Assertion XML element into an `ExSaml.Core.Assertion` struct.
  """
  @spec decode_assertion(tuple()) :: {:ok, Assertion.t()} | {:error, term()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def decode_assertion(xml) do
    ns = @protocol_namespaces

    with {:ok, version} <-
           require_attr(xml, "/saml:Assertion/@Version", ns, :bad_version),
         {:ok, issue_instant} <-
           require_attr(xml, "/saml:Assertion/@IssueInstant", ns, :bad_assertion),
         {:ok, recipient} <-
           require_attr(
             xml,
             "/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient",
             ns,
             :bad_recipient
           ) do
      issuer =
        case xpath_text(xml, "/saml:Assertion/saml:Issuer/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      subject =
        decode_optional_sub(xml, "/saml:Assertion/saml:Subject", ns,
          &decode_assertion_subject/1, %Subject{})

      conditions =
        decode_optional_sub(xml, "/saml:Assertion/saml:Conditions", ns,
          &decode_assertion_conditions/1, [])

      attributes =
        decode_optional_sub(xml, "/saml:Assertion/saml:AttributeStatement", ns,
          &decode_assertion_attributes/1, [])

      authn =
        decode_optional_sub(xml, "/saml:Assertion/saml:AuthnStatement", ns,
          &decode_assertion_authn/1, [])

      {:ok,
       %Assertion{
         version: version,
         issue_instant: issue_instant,
         recipient: recipient,
         issuer: issuer,
         subject: subject,
         conditions: conditions,
         attributes: attributes,
         authn: authn
       }}
    end
  end

  @doc """
  Decodes a SAML LogoutRequest XML element into an `ExSaml.Core.LogoutRequest` struct.
  """
  @spec decode_logout_request(tuple()) :: {:ok, LogoutRequest.t()} | {:error, term()}
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def decode_logout_request(xml) do
    ns = @protocol_namespaces

    with {:ok, version} <-
           require_attr(xml, "/samlp:LogoutRequest/@Version", ns, :bad_version),
         {:ok, issue_instant} <-
           require_attr(xml, "/samlp:LogoutRequest/@IssueInstant", ns, :bad_response),
         {:ok, name} <-
           require_text(xml, "/samlp:LogoutRequest/saml:NameID/text()", ns, :bad_name) do
      sp_name_qualifier =
        case xpath_attr(xml, "/samlp:LogoutRequest/saml:NameID/@SPNameQualifier", ns) do
          {:ok, v} -> nameid_sp_name_qualifier_map(v)
          :not_found -> nil
        end

      name_format =
        case xpath_attr(xml, "/samlp:LogoutRequest/saml:NameID/@Format", ns) do
          {:ok, v} -> nameid_format_map(v)
          :not_found -> nil
        end

      destination =
        case xpath_attr(xml, "/samlp:LogoutRequest/@Destination", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      reason =
        case xpath_attr(xml, "/samlp:LogoutRequest/@Reason", ns) do
          {:ok, v} -> logout_reason_map(v)
          :not_found -> :user
        end

      issuer =
        case xpath_text(xml, "/samlp:LogoutRequest/saml:Issuer/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      {:ok,
       %LogoutRequest{
         version: version,
         issue_instant: issue_instant,
         name: name,
         sp_name_qualifier: sp_name_qualifier,
         name_format: name_format,
         destination: destination,
         reason: reason,
         issuer: issuer
       }}
    end
  end

  @doc """
  Decodes a SAML LogoutResponse XML element into an `ExSaml.Core.LogoutResponse` struct.
  """
  @spec decode_logout_response(tuple()) :: {:ok, LogoutResponse.t()} | {:error, term()}
  def decode_logout_response(xml) do
    ns = @protocol_namespaces

    with {:ok, version} <-
           require_attr(xml, "/samlp:LogoutResponse/@Version", ns, :bad_version),
         {:ok, issue_instant} <-
           require_attr(xml, "/samlp:LogoutResponse/@IssueInstant", ns, :bad_response),
         {:ok, status} <-
           require_attr(
             xml,
             "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value",
             ns,
             :bad_response,
             &status_code_map/1
           ) do
      destination =
        case xpath_attr(xml, "/samlp:LogoutResponse/@Destination", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      issuer =
        case xpath_text(xml, "/samlp:LogoutResponse/saml:Issuer/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      {:ok,
       %LogoutResponse{
         version: version,
         issue_instant: issue_instant,
         status: status,
         destination: destination,
         issuer: issuer
       }}
    end
  end

  # ---------------------------------------------------------------------------
  # Helper decode functions (private)
  # ---------------------------------------------------------------------------

  defp decode_org(xml) do
    ns = @metadata_namespaces

    with {:ok, name} <-
           require_text(xml, "/md:Organization/md:OrganizationName/text()", ns, :bad_org) do
      displayname =
        case xpath_text(xml, "/md:Organization/md:OrganizationDisplayName/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      url =
        case xpath_text(xml, "/md:Organization/md:OrganizationURL/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      {:ok, %Org{name: name, displayname: displayname, url: url}}
    end
  end

  defp decode_contact(xml) do
    ns = @metadata_namespaces

    with {:ok, email} <-
           require_text(xml, "/md:ContactPerson/md:EmailAddress/text()", ns, :bad_contact) do
      given_name =
        case xpath_text(xml, "/md:ContactPerson/md:GivenName/text()", ns) do
          {:ok, v} -> v
          :not_found -> ""
        end

      sur_name =
        case xpath_text(xml, "/md:ContactPerson/md:SurName/text()", ns) do
          {:ok, v} -> v
          :not_found -> nil
        end

      name =
        case sur_name do
          nil -> given_name
          sn -> given_name ++ ~c" " ++ sn
        end

      {:ok, %Contact{name: name, email: email}}
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  defp decode_assertion_subject(xml) do
    ns = [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}]

    name =
      case xpath_text(xml, "/saml:Subject/saml:NameID/text()", ns) do
        {:ok, v} -> v
        :not_found -> ""
      end

    name_qualifier =
      case xpath_attr(xml, "/saml:Subject/saml:NameID/@NameQualifier", ns) do
        {:ok, v} -> nameid_name_qualifier_map(v)
        :not_found -> nil
      end

    sp_name_qualifier =
      case xpath_attr(xml, "/saml:Subject/saml:NameID/@SPNameQualifier", ns) do
        {:ok, v} -> nameid_sp_name_qualifier_map(v)
        :not_found -> nil
      end

    name_format =
      case xpath_attr(xml, "/saml:Subject/saml:NameID/@Format", ns) do
        {:ok, v} -> nameid_format_map(v)
        :not_found -> nil
      end

    confirmation_method =
      case xpath_attr(xml, "/saml:Subject/saml:SubjectConfirmation/@Method", ns) do
        {:ok, v} -> subject_method_map(v)
        :not_found -> :bearer
      end

    notonorafter =
      case xpath_attr(
             xml,
             "/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter",
             ns
           ) do
        {:ok, v} -> v
        :not_found -> ""
      end

    in_response_to =
      case xpath_attr(
             xml,
             "/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo",
             ns
           ) do
        {:ok, v} -> v
        :not_found -> ""
      end

    {:ok,
     %Subject{
       name: name,
       name_qualifier: name_qualifier,
       sp_name_qualifier: sp_name_qualifier,
       name_format: name_format,
       confirmation_method: confirmation_method,
       notonorafter: notonorafter,
       in_response_to: in_response_to
     }}
  end

  defp decode_assertion_conditions(xml) do
    ns = [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}]

    conditions =
      []
      |> maybe_add_condition(xml, "/saml:Conditions/@NotBefore", ns, :not_before, :attr)
      |> maybe_add_condition(xml, "/saml:Conditions/@NotOnOrAfter", ns, :not_on_or_after, :attr)
      |> maybe_add_condition(
        xml,
        "/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()",
        ns,
        :audience,
        :text
      )

    {:ok, conditions}
  end

  defp maybe_add_condition(acc, xml, path, ns, key, :attr) do
    case xpath_attr(xml, path, ns) do
      {:ok, v} -> [{key, v} | acc]
      :not_found -> acc
    end
  end

  defp maybe_add_condition(acc, xml, path, ns, key, :text) do
    case xpath_text(xml, path, ns) do
      {:ok, v} -> [{key, v} | acc]
      :not_found -> acc
    end
  end

  defp decode_assertion_attributes(xml) do
    ns = [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}]
    attrs = xpath_elems(xml, "/saml:AttributeStatement/saml:Attribute", ns)

    result = Enum.reduce(attrs, [], &decode_one_attribute(&1, &2, ns))
    {:ok, result}
  end

  defp decode_one_attribute(attr_elem, acc, ns) do
    name_values =
      for attr <- xmlElement(attr_elem, :attributes),
          Record.is_record(attr, :xmlAttribute),
          xmlAttribute(attr, :name) == :Name,
          do: xmlAttribute(attr, :value)

    case name_values do
      [name] -> extract_attribute_values(to_string(name), attr_elem, acc, ns)
      _ -> acc
    end
  end

  defp extract_attribute_values(name_str, attr_elem, acc, ns) do
    case :xmerl_xpath.string(~c"saml:AttributeValue/text()", attr_elem, [{:namespace, ns}]) do
      [text] when Record.is_record(text, :xmlText) ->
        [{common_attrib_map(name_str), to_string(xmlText(text, :value))} | acc]

      [_ | _] = list ->
        values = for x <- list, Record.is_record(x, :xmlText), do: to_string(xmlText(x, :value))
        [{common_attrib_map(name_str), values} | acc]

      _ ->
        acc
    end
  end

  defp decode_assertion_authn(xml) do
    ns = [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}]

    result =
      []
      |> maybe_add_condition(
        xml,
        "/saml:AuthnStatement/@AuthnInstant",
        ns,
        :authn_instant,
        :attr
      )
      |> maybe_add_condition(
        xml,
        "/saml:AuthnStatement/@SessionNotOnOrAfter",
        ns,
        :session_not_on_or_after,
        :attr
      )
      |> maybe_add_condition(
        xml,
        "/saml:AuthnStatement/@SessionIndex",
        ns,
        :session_index,
        :attr
      )
      |> maybe_add_condition(
        xml,
        "/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef/text()",
        ns,
        :authn_context,
        :text
      )

    {:ok, result}
  end

  # ---------------------------------------------------------------------------
  # Required field helpers
  # ---------------------------------------------------------------------------

  defp require_attr(xml, path, ns, error_reason) do
    case xpath_attr(xml, path, ns) do
      {:ok, value} -> {:ok, value}
      :not_found -> {:error, error_reason}
    end
  end

  defp require_attr(xml, path, ns, error_reason, transform_fn) do
    case xpath_attr(xml, path, ns) do
      {:ok, value} -> {:ok, transform_fn.(value)}
      :not_found -> {:error, error_reason}
    end
  end

  defp require_text(xml, path, ns, error_reason) do
    case xpath_text(xml, path, ns) do
      {:ok, value} -> {:ok, value}
      :not_found -> {:error, error_reason}
    end
  end

  # ---------------------------------------------------------------------------
  # Validation functions (public)
  # ---------------------------------------------------------------------------

  @doc """
  Returns the gregorian seconds at which an assertion is considered stale.

  Examines the Subject's NotOnOrAfter, the Conditions NotOnOrAfter,
  and falls back to issue_instant + 5 minutes.
  """
  @spec stale_time(Assertion.t()) :: integer()
  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def stale_time(%Assertion{} = a) do
    t = :none

    t =
      case a.subject do
        %Subject{notonorafter: ""} ->
          t

        %Subject{notonorafter: restrict} ->
          secs =
            restrict
            |> ExSaml.Core.Util.saml_to_datetime()
            |> :calendar.datetime_to_gregorian_seconds()

          if t == :none or secs < t, do: secs, else: t
      end

    t =
      case Keyword.get(a.conditions, :not_on_or_after) do
        nil ->
          t

        restrict ->
          secs =
            restrict
            |> ExSaml.Core.Util.saml_to_datetime()
            |> :calendar.datetime_to_gregorian_seconds()

          if t == :none or secs < t, do: secs, else: t
      end

    case t do
      :none ->
        ii_secs =
          a.issue_instant
          |> ExSaml.Core.Util.saml_to_datetime()
          |> :calendar.datetime_to_gregorian_seconds()

        ii_secs + 5 * 60

      _ ->
        t
    end
  end

  @doc """
  Validates a SAML assertion XML element.

  Decodes the assertion and validates:
  - Version is "2.0"
  - Recipient matches the expected value
  - Audience matches (if present in conditions)
  - Assertion is not stale
  """
  @spec validate_assertion(tuple(), String.t(), String.t()) ::
          {:ok, Assertion.t()} | {:error, term()}
  def validate_assertion(assertion_xml, recipient, audience) do
    case decode_assertion(assertion_xml) do
      {:error, reason} ->
        {:error, reason}

      {:ok, assertion} ->
        with :ok <- validate_version(assertion),
             :ok <- validate_recipient(assertion, recipient),
             :ok <- validate_audience(assertion, audience),
             :ok <- check_stale(assertion) do
          {:ok, assertion}
        end
    end
  end

  defp validate_version(%Assertion{version: "2.0"}), do: :ok
  defp validate_version(_), do: {:error, :bad_version}

  defp validate_recipient(%Assertion{recipient: r}, recipient) when r == recipient, do: :ok
  defp validate_recipient(_, _), do: {:error, :bad_recipient}

  defp validate_audience(%Assertion{conditions: conds}, audience) do
    case Keyword.get(conds, :audience) do
      nil -> :ok
      ^audience -> :ok
      _ -> {:error, :bad_audience}
    end
  end

  @doc false
  defp check_stale(%Assertion{} = a) do
    now = :erlang.localtime() |> :erlang.localtime_to_universaltime()
    now_secs = :calendar.datetime_to_gregorian_seconds(now)
    t = stale_time(a)

    if now_secs > t do
      {:error, :stale_assertion}
    else
      :ok
    end
  end

  # ---------------------------------------------------------------------------
  # XML generation (public)
  # ---------------------------------------------------------------------------

  @doc """
  Converts a SAML struct to an xmerl XML element.

  Supports `AuthnRequest`, `LogoutRequest`, `LogoutResponse`, and `SpMetadata`.
  """
  @spec to_xml(struct()) :: tuple()
  def to_xml(%AuthnRequest{
        version: v,
        issue_instant: time,
        destination: dest,
        issuer: issuer,
        name_format: format,
        consumer_location: consumer
      }) do
    ns =
      xmlNamespace(
        nodes: [
          {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
          {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
        ]
      )

    name_id_policy =
      if is_list(format) or is_binary(format) do
        fmt = if is_binary(format), do: to_charlist(format), else: format

        [
          xmlElement(
            name: :"samlp:NameIDPolicy",
            attributes: [xmlAttribute(name: :Format, value: fmt)]
          )
        ]
      else
        []
      end

    elem =
      xmlElement(
        name: :"samlp:AuthnRequest",
        attributes: [
          xmlAttribute(name: :"xmlns:samlp", value: ~c"urn:oasis:names:tc:SAML:2.0:protocol"),
          xmlAttribute(name: :"xmlns:saml", value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"),
          xmlAttribute(name: :IssueInstant, value: time),
          xmlAttribute(name: :Version, value: v),
          xmlAttribute(name: :Destination, value: dest),
          xmlAttribute(name: :AssertionConsumerServiceURL, value: consumer),
          xmlAttribute(
            name: :ProtocolBinding,
            value: ~c"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          )
        ],
        content:
          [
            xmlElement(
              name: :"saml:Issuer",
              content: [xmlText(value: issuer)]
            )
          ] ++ name_id_policy
      )

    ExSaml.Core.Util.build_nsinfo(ns, elem)
  end

  def to_xml(%LogoutRequest{
        version: v,
        issue_instant: time,
        destination: dest,
        issuer: issuer,
        name: name_id,
        name_qualifier: name_qualifier,
        sp_name_qualifier: sp_name_qualifier,
        name_format: name_format,
        session_index: session_index,
        reason: reason
      }) do
    ns =
      xmlNamespace(
        nodes: [
          {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
          {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
        ]
      )

    name_id_attrs =
      maybe_string_attr(:NameQualifier, name_qualifier) ++
        maybe_string_attr(:SPNameQualifier, sp_name_qualifier) ++
        maybe_string_attr(:Format, name_format)

    elem =
      xmlElement(
        name: :"samlp:LogoutRequest",
        attributes: [
          xmlAttribute(name: :"xmlns:samlp", value: ~c"urn:oasis:names:tc:SAML:2.0:protocol"),
          xmlAttribute(name: :"xmlns:saml", value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"),
          xmlAttribute(name: :IssueInstant, value: time),
          xmlAttribute(name: :Version, value: v),
          xmlAttribute(name: :Destination, value: dest),
          xmlAttribute(name: :Reason, value: to_charlist(rev_logout_reason_map(reason)))
        ],
        content: [
          xmlElement(
            name: :"saml:Issuer",
            content: [xmlText(value: issuer)]
          ),
          xmlElement(
            name: :"saml:NameID",
            attributes: name_id_attrs,
            content: [xmlText(value: name_id)]
          ),
          xmlElement(
            name: :"samlp:SessionIndex",
            content: [xmlText(value: session_index)]
          )
        ]
      )

    ExSaml.Core.Util.build_nsinfo(ns, elem)
  end

  def to_xml(%LogoutResponse{
        version: v,
        issue_instant: time,
        destination: dest,
        issuer: issuer,
        status: status
      }) do
    ns =
      xmlNamespace(
        nodes: [
          {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
          {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
        ]
      )

    elem =
      xmlElement(
        name: :"samlp:LogoutResponse",
        attributes: [
          xmlAttribute(name: :"xmlns:samlp", value: ~c"urn:oasis:names:tc:SAML:2.0:protocol"),
          xmlAttribute(name: :"xmlns:saml", value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"),
          xmlAttribute(name: :IssueInstant, value: time),
          xmlAttribute(name: :Version, value: v),
          xmlAttribute(name: :Destination, value: dest)
        ],
        content: [
          xmlElement(
            name: :"saml:Issuer",
            content: [xmlText(value: issuer)]
          ),
          xmlElement(
            name: :"samlp:Status",
            content: [
              xmlElement(
                name: :"samlp:StatusCode",
                content: [xmlText(value: to_charlist(rev_status_code_map(status)))]
              )
            ]
          )
        ]
      )

    ExSaml.Core.Util.build_nsinfo(ns, elem)
  end

  def to_xml(%SpMetadata{
        org: %Org{name: org_name, displayname: org_displayname, url: org_url},
        tech: %Contact{name: tech_name, email: tech_email},
        signed_requests: sign_req,
        signed_assertions: sign_ass,
        certificate: cert_bin,
        cert_chain: cert_chain,
        entity_id: entity_id,
        consumer_location: consumer_loc,
        logout_location: slo_loc
      }) do
    ns =
      xmlNamespace(
        nodes: [
          {~c"md", :"urn:oasis:names:tc:SAML:2.0:metadata"},
          {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"},
          {"dsig", :"http://www.w3.org/2000/09/xmldsig#"}
        ]
      )

    key_descriptor_elems =
      case cert_bin do
        nil ->
          []

        c when is_binary(c) ->
          x509_elems =
            [
              xmlElement(
                name: :"dsig:X509Certificate",
                content: [xmlText(value: to_charlist(:base64.encode_to_string(cert_bin)))]
              )
            ] ++
              for chain_bin <- cert_chain do
                xmlElement(
                  name: :"dsig:X509Certificate",
                  content: [xmlText(value: to_charlist(:base64.encode_to_string(chain_bin)))]
                )
              end

          [
            xmlElement(
              name: :"md:KeyDescriptor",
              attributes: [xmlAttribute(name: :use, value: ~c"signing")],
              content: [
                xmlElement(
                  name: :"dsig:KeyInfo",
                  content: [
                    xmlElement(name: :"dsig:X509Data", content: x509_elems)
                  ]
                )
              ]
            ),
            xmlElement(
              name: :"md:KeyDescriptor",
              attributes: [xmlAttribute(name: :use, value: ~c"encryption")],
              content: [
                xmlElement(
                  name: :"dsig:KeyInfo",
                  content: [
                    xmlElement(name: :"dsig:X509Data", content: x509_elems)
                  ]
                )
              ]
            )
          ]
      end

    single_logout_elems =
      case slo_loc do
        nil ->
          []

        _ ->
          [
            xmlElement(
              name: :"md:SingleLogoutService",
              attributes: [
                xmlAttribute(
                  name: :Binding,
                  value: ~c"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                ),
                xmlAttribute(name: :Location, value: slo_loc)
              ]
            ),
            xmlElement(
              name: :"md:SingleLogoutService",
              attributes: [
                xmlAttribute(
                  name: :Binding,
                  value: ~c"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                ),
                xmlAttribute(name: :Location, value: slo_loc)
              ]
            )
          ]
      end

    assertion_consumer_elems = [
      xmlElement(
        name: :"md:AssertionConsumerService",
        attributes: [
          xmlAttribute(name: :isDefault, value: ~c"true"),
          xmlAttribute(name: :index, value: ~c"0"),
          xmlAttribute(
            name: :Binding,
            value: ~c"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
          ),
          xmlAttribute(name: :Location, value: consumer_loc)
        ]
      ),
      xmlElement(
        name: :"md:AssertionConsumerService",
        attributes: [
          xmlAttribute(name: :index, value: ~c"1"),
          xmlAttribute(
            name: :Binding,
            value: ~c"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
          ),
          xmlAttribute(name: :Location, value: consumer_loc)
        ]
      )
    ]

    organization_elem =
      xmlElement(
        name: :"md:Organization",
        content:
          lang_elems(xmlElement(name: :"md:OrganizationName"), org_name) ++
            lang_elems(xmlElement(name: :"md:OrganizationDisplayName"), org_displayname) ++
            lang_elems(xmlElement(name: :"md:OrganizationURL"), org_url)
      )

    contact_elem =
      xmlElement(
        name: :"md:ContactPerson",
        attributes: [xmlAttribute(name: :contactType, value: ~c"technical")],
        content: [
          xmlElement(
            name: :"md:SurName",
            content: [xmlText(value: tech_name)]
          ),
          xmlElement(
            name: :"md:EmailAddress",
            content: [xmlText(value: tech_email)]
          )
        ]
      )

    sp_sso_descriptor =
      xmlElement(
        name: :"md:SPSSODescriptor",
        attributes: [
          xmlAttribute(
            name: :protocolSupportEnumeration,
            value: ~c"urn:oasis:names:tc:SAML:2.0:protocol"
          ),
          xmlAttribute(name: :AuthnRequestsSigned, value: to_charlist(Atom.to_string(sign_req))),
          xmlAttribute(
            name: :WantAssertionsSigned,
            value: to_charlist(Atom.to_string(sign_ass))
          )
        ],
        content: key_descriptor_elems ++ single_logout_elems ++ assertion_consumer_elems
      )

    elem =
      xmlElement(
        name: :"md:EntityDescriptor",
        attributes: [
          xmlAttribute(
            name: :"xmlns:md",
            value: ~c"urn:oasis:names:tc:SAML:2.0:metadata"
          ),
          xmlAttribute(
            name: :"xmlns:saml",
            value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
          ),
          xmlAttribute(
            name: :"xmlns:dsig",
            value: ~c"http://www.w3.org/2000/09/xmldsig#"
          ),
          xmlAttribute(name: :entityID, value: entity_id)
        ],
        content: [
          sp_sso_descriptor,
          organization_elem,
          contact_elem
        ]
      )

    ExSaml.Core.Util.build_nsinfo(ns, elem)
  end

  def to_xml(_), do: :erlang.error("unknown record")

  # ---------------------------------------------------------------------------
  # Helper functions
  # ---------------------------------------------------------------------------

  @doc """
  Produces cloned XML elements with `xml:lang` set for multi-locale strings.

  If `vals` is a keyword list of `{locale, string}` pairs, generates one element
  per locale. Otherwise generates a single element with `xml:lang="en"`.
  """
  @spec lang_elems(tuple(), String.t() | [{atom(), String.t()}]) :: [tuple()]
  def lang_elems(base_tag, [{lang, _} | _] = vals) when is_atom(lang) do
    for {l, v} <- vals do
      xmlElement(base_tag,
        attributes:
          xmlElement(base_tag, :attributes) ++
            [xmlAttribute(name: :"xml:lang", value: to_charlist(Atom.to_string(l)))],
        content:
          xmlElement(base_tag, :content) ++
            [xmlText(value: v)]
      )
    end
  end

  def lang_elems(base_tag, val) do
    [
      xmlElement(base_tag,
        attributes:
          xmlElement(base_tag, :attributes) ++
            [xmlAttribute(name: :"xml:lang", value: ~c"en")],
        content:
          xmlElement(base_tag, :content) ++
            [xmlText(value: val)]
      )
    ]
  end

  # Generates an optional xmlAttribute if the value is a string (charlist or binary)
  defp maybe_string_attr(name, value) when is_list(value) do
    [xmlAttribute(name: name, value: value)]
  end

  defp maybe_string_attr(name, value) when is_binary(value) do
    [xmlAttribute(name: name, value: to_charlist(value))]
  end

  defp maybe_string_attr(_name, _value), do: []
end
