defmodule ExSaml.Metadata do
  @moduledoc """
  Public entry point for validating SAML 2.0 metadata documents.

  `validate/2` parses an XML document (raw binary) and returns a structured
  report of structural / spec-conformance violations. It is intended to be
  called at system boundaries — for example, before persisting IdP metadata
  uploaded through an administration form, or before publishing SP metadata
  to a partner.

  This module currently implements **spec-conformance rules only** — every
  finding is an `:error`. Best-practice rules (warnings, strict mode,
  certificate linting) are added in subsequent releases.

  ## Example

      iex> ExSaml.Metadata.validate(xml)
      {:ok, %ExSaml.Metadata.ValidationResult{errors: [], warnings: []}}

  ## Options

    * `:ignore` — list of violation codes to silence. Matching violations
      are removed from both `errors` and `warnings` before the result is
      returned.

  ## Return semantics

    * `{:ok, %ValidationResult{errors: [], warnings: _}}` when no
      error-level violation remains after `:ignore` is applied.
    * `{:error, %ValidationResult{errors: errors, warnings: _}}` otherwise.

  See `ExSaml.Metadata.ValidationResult` for the shape of the returned struct.
  """

  alias ExSaml.Metadata.ValidationResult

  require Record

  Record.defrecordp(
    :xml_element,
    :xmlElement,
    Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecordp(
    :xml_attribute,
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  @md_namespace "urn:oasis:names:tc:SAML:2.0:metadata"

  @namespaces [
    {~c"md", :"urn:oasis:names:tc:SAML:2.0:metadata"},
    {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}
  ]

  @saml2_protocol "urn:oasis:names:tc:SAML:2.0:protocol"

  @binding_http_post "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  @binding_http_redirect "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  @binding_http_artifact "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
  @binding_paos "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
  @binding_soap "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

  @allowed_acs_bindings [@binding_http_post, @binding_http_artifact, @binding_paos]
  @allowed_slo_bindings [
    @binding_http_redirect,
    @binding_http_post,
    @binding_http_artifact,
    @binding_soap
  ]

  @entity_id_max 1024

  @type option :: {:ignore, [atom()]}
  @type opts :: [option()]

  @spec validate(binary()) :: {:ok, ValidationResult.t()} | {:error, ValidationResult.t()}
  def validate(xml), do: validate(xml, [])

  @spec validate(binary(), opts()) :: {:ok, ValidationResult.t()} | {:error, ValidationResult.t()}
  def validate(xml, opts) when is_binary(xml) and is_list(opts) do
    ignore = Keyword.get(opts, :ignore, [])

    violations =
      case parse(xml) do
        {:ok, root} -> run_rules(root)
        {:error, violation} -> [violation]
      end

    violations
    |> Enum.reject(&(&1.code in ignore))
    |> ValidationResult.from_violations()
    |> finalize()
  end

  # ---------------------------------------------------------------------------
  # Parsing
  # ---------------------------------------------------------------------------

  defp parse(xml) do
    charlist = String.to_charlist(xml)

    try do
      {root, _rest} =
        :xmerl_scan.string(
          charlist,
          namespace_conformant: true,
          allow_entities: false,
          quiet: true
        )

      if Record.is_record(root, :xmlElement) do
        {:ok, root}
      else
        {:error, invalid_xml_violation()}
      end
    rescue
      _ -> {:error, invalid_xml_violation()}
    catch
      _kind, _reason -> {:error, invalid_xml_violation()}
    end
  end

  # ---------------------------------------------------------------------------
  # Root dispatch
  # ---------------------------------------------------------------------------

  defp run_rules(root) do
    case classify_root(root) do
      :entity_descriptor ->
        check_entity_descriptor(root)

      :entities_descriptor ->
        [
          %{
            code: :entities_descriptor_not_supported,
            severity: :error,
            message:
              "<md:EntitiesDescriptor> federation bundles are not supported; provide a single <md:EntityDescriptor>",
            path: nil,
            spec_reference: "SAML 2.0 Metadata §2.3.1"
          }
        ]

      :other ->
        [
          %{
            code: :invalid_root_element,
            severity: :error,
            message: "Root element must be <md:EntityDescriptor> in namespace " <> @md_namespace,
            path: nil,
            spec_reference: "SAML 2.0 Metadata §2.3.2"
          }
        ]
    end
  end

  defp classify_root(root) do
    ns = namespace_uri(root)
    local = local_name(root)

    cond do
      local == "EntityDescriptor" and ns == @md_namespace -> :entity_descriptor
      local == "EntitiesDescriptor" and ns == @md_namespace -> :entities_descriptor
      true -> :other
    end
  end

  # ---------------------------------------------------------------------------
  # EntityDescriptor-level rules
  # ---------------------------------------------------------------------------

  defp check_entity_descriptor(root) do
    entity_id_violations(root) ++ descriptor_violations(root)
  end

  defp entity_id_violations(root) do
    case xpath_attr_value(root, "@entityID") do
      nil ->
        [
          %{
            code: :missing_entity_id,
            severity: :error,
            message: "entityID attribute is missing on <md:EntityDescriptor>",
            path: "/EntityDescriptor/@entityID",
            spec_reference: "SAML 2.0 Metadata §2.3.2"
          }
        ]

      id when byte_size(id) > @entity_id_max ->
        [
          %{
            code: :entity_id_too_long,
            severity: :error,
            message: "entityID length (#{byte_size(id)} bytes) exceeds the 1024-byte maximum",
            path: "/EntityDescriptor/@entityID",
            spec_reference: "SAML 2.0 Metadata §2.3.2"
          }
        ]

      _ ->
        []
    end
  end

  defp descriptor_violations(root) do
    sp_descriptors = xpath_elems(root, "./md:SPSSODescriptor")
    idp_descriptors = xpath_elems(root, "./md:IDPSSODescriptor")

    case {sp_descriptors, idp_descriptors} do
      {[], []} ->
        [
          %{
            code: :missing_role_descriptor,
            severity: :error,
            message: "At least one <md:SPSSODescriptor> or <md:IDPSSODescriptor> must be present",
            path: "/EntityDescriptor",
            spec_reference: "SAML 2.0 Metadata §2.4"
          }
        ]

      {sps, idps} ->
        protocol_violations(sps, "SPSSODescriptor") ++
          protocol_violations(idps, "IDPSSODescriptor") ++
          sp_violations(sps) ++
          idp_violations(idps)
    end
  end

  defp protocol_violations(descriptors, kind) do
    descriptors
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {desc, idx} ->
      values =
        desc
        |> xpath_attr_value("@protocolSupportEnumeration")
        |> case do
          nil -> []
          v -> String.split(v)
        end

      if @saml2_protocol in values do
        []
      else
        [
          %{
            code: :missing_saml2_protocol_support,
            severity: :error,
            message: "protocolSupportEnumeration must contain " <> @saml2_protocol,
            path: "/EntityDescriptor/#{kind}[#{idx}]/@protocolSupportEnumeration",
            spec_reference: "SAML 2.0 Metadata §2.4.1"
          }
        ]
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # SPSSODescriptor-specific rules
  # ---------------------------------------------------------------------------

  defp sp_violations([]), do: []

  defp sp_violations(sp_descriptors) do
    Enum.flat_map(sp_descriptors, fn sp ->
      acs_elems = xpath_elems(sp, "./md:AssertionConsumerService")
      slo_elems = xpath_elems(sp, "./md:SingleLogoutService")

      acs_violations(acs_elems) ++
        slo_binding_violations(slo_elems, "SPSSODescriptor")
    end)
  end

  defp acs_violations([]) do
    [
      %{
        code: :missing_acs,
        severity: :error,
        message: "SP metadata must declare at least one <md:AssertionConsumerService>",
        path: "/EntityDescriptor/SPSSODescriptor",
        spec_reference: "SAML 2.0 Metadata §2.4.4"
      }
    ]
  end

  defp acs_violations(acs_elems) do
    indexed = Enum.with_index(acs_elems, 1)

    binding_violations =
      Enum.flat_map(indexed, fn {acs, idx} ->
        case xpath_attr_value(acs, "@Binding") do
          binding when binding in @allowed_acs_bindings ->
            []

          binding ->
            [
              %{
                code: :invalid_acs_binding,
                severity: :error,
                message:
                  "Binding " <>
                    inspect(binding) <> " is not permitted for AssertionConsumerService",
                path:
                  "/EntityDescriptor/SPSSODescriptor/AssertionConsumerService[#{idx}]/@Binding",
                spec_reference: "SAML 2.0 Bindings §3.4.3, Profiles §4.1.3.5"
              }
            ]
        end
      end)

    missing_post_violations =
      if Enum.any?(acs_elems, fn acs ->
           xpath_attr_value(acs, "@Binding") == @binding_http_post
         end) do
        []
      else
        [
          %{
            code: :missing_http_post_acs,
            severity: :error,
            message:
              "At least one <md:AssertionConsumerService> must use HTTP-POST (Web Browser SSO Profile)",
            path: "/EntityDescriptor/SPSSODescriptor",
            spec_reference: "SAML 2.0 Profiles §4.1.3.5, Conformance §3.1"
          }
        ]
      end

    duplicate_index_violations = duplicate_acs_index_violations(acs_elems)

    multiple_default_violations =
      if Enum.count(acs_elems, fn acs ->
           xpath_attr_value(acs, "@isDefault") == "true"
         end) > 1 do
        [
          %{
            code: :multiple_default_acs,
            severity: :error,
            message: "At most one <md:AssertionConsumerService> may have isDefault=\"true\"",
            path: "/EntityDescriptor/SPSSODescriptor/AssertionConsumerService",
            spec_reference: "SAML 2.0 Metadata §2.4.2"
          }
        ]
      else
        []
      end

    binding_violations ++
      missing_post_violations ++ duplicate_index_violations ++ multiple_default_violations
  end

  defp duplicate_acs_index_violations(acs_elems) do
    acs_elems
    |> Enum.map(&xpath_attr_value(&1, "@index"))
    |> Enum.reject(&is_nil/1)
    |> Enum.frequencies()
    |> Enum.filter(fn {_i, count} -> count > 1 end)
    |> Enum.map(fn {i, _} ->
      %{
        code: :duplicate_acs_index,
        severity: :error,
        message: "Multiple <md:AssertionConsumerService> entries share index=" <> inspect(i),
        path: "/EntityDescriptor/SPSSODescriptor/AssertionConsumerService",
        spec_reference: "SAML 2.0 Metadata §2.4.2"
      }
    end)
  end

  # ---------------------------------------------------------------------------
  # IDPSSODescriptor-specific rules
  # ---------------------------------------------------------------------------

  defp idp_violations([]), do: []

  defp idp_violations(idp_descriptors) do
    Enum.flat_map(idp_descriptors, fn idp ->
      sso_elems = xpath_elems(idp, "./md:SingleSignOnService")
      slo_elems = xpath_elems(idp, "./md:SingleLogoutService")

      sso_missing =
        if sso_elems == [] do
          [
            %{
              code: :missing_sso_service,
              severity: :error,
              message: "IdP metadata must declare at least one <md:SingleSignOnService>",
              path: "/EntityDescriptor/IDPSSODescriptor",
              spec_reference: "SAML 2.0 Metadata §2.4.3"
            }
          ]
        else
          []
        end

      sso_missing ++ slo_binding_violations(slo_elems, "IDPSSODescriptor")
    end)
  end

  # ---------------------------------------------------------------------------
  # Shared SLO binding check
  # ---------------------------------------------------------------------------

  defp slo_binding_violations(slo_elems, descriptor_kind) do
    slo_elems
    |> Enum.with_index(1)
    |> Enum.flat_map(fn {slo, idx} ->
      case xpath_attr_value(slo, "@Binding") do
        binding when binding in @allowed_slo_bindings ->
          []

        binding ->
          [
            %{
              code: :invalid_slo_binding,
              severity: :error,
              message:
                "Binding " <>
                  inspect(binding) <> " is not permitted for SingleLogoutService",
              path: "/EntityDescriptor/#{descriptor_kind}/SingleLogoutService[#{idx}]/@Binding",
              spec_reference: "SAML 2.0 Bindings §3.4-3.7"
            }
          ]
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # XPath / xmerl helpers
  # ---------------------------------------------------------------------------

  defp xpath_elems(context, path) do
    :xmerl_xpath.string(to_charlist(path), context, [{:namespace, @namespaces}])
  end

  defp xpath_attr_value(context, path) do
    case :xmerl_xpath.string(to_charlist(path), context, [{:namespace, @namespaces}]) do
      [attr] ->
        if Record.is_record(attr, :xmlAttribute) do
          attr |> xml_attribute(:value) |> to_string()
        else
          nil
        end

      _ ->
        nil
    end
  end

  defp namespace_uri(element) do
    case xml_element(element, :expanded_name) do
      {ns, _local} when is_atom(ns) -> Atom.to_string(ns)
      _ -> nil
    end
  end

  defp local_name(element) do
    case xml_element(element, :nsinfo) do
      {_prefix, local} when is_list(local) ->
        to_string(local)

      _ ->
        element |> xml_element(:name) |> Atom.to_string()
    end
  end

  # ---------------------------------------------------------------------------
  # Building blocks
  # ---------------------------------------------------------------------------

  defp finalize(%ValidationResult{errors: []} = r), do: {:ok, r}
  defp finalize(%ValidationResult{} = r), do: {:error, r}

  defp invalid_xml_violation do
    %{
      code: :invalid_xml,
      severity: :error,
      message: "Metadata XML is not well-formed",
      path: nil,
      spec_reference: nil
    }
  end
end
