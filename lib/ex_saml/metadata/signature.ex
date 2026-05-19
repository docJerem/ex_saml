defmodule ExSaml.Metadata.Signature do
  @moduledoc false

  # Structural validation of `<ds:Signature>` elements declared inside SAML
  # metadata. Emits three always-error violations:
  #
  #   * `:invalid_signature_structure` — a `<ds:Signature>` is present but
  #     missing one of the mandatory XML-DSig children (`SignedInfo`,
  #     `SignatureValue`, `SignedInfo/SignatureMethod`, `SignedInfo/Reference`,
  #     `Reference/DigestMethod`, `Reference/DigestValue`).
  #   * `:unknown_signature_algorithm` — `<ds:SignatureMethod Algorithm>` is
  #     not in the XML-DSig / xmldsig-more spec-defined set. Deprecated but
  #     spec-defined values (RSA-SHA1, etc.) are still recognized here; the
  #     dedicated `:deprecated_signature_algorithm` rule ships with PR 3 and
  #     its strict-mode promotion.
  #   * `:unknown_digest_algorithm` — same idea for `<ds:DigestMethod>`.
  #
  # Cryptographic verification of the signature against a trust anchor is
  # out of scope (see issue #17 "Non-goals").

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

  # Spec-defined XML-DSig signature algorithm URIs (RFC 6931, RFC 4051,
  # XML-DSig §6.4). Recognised by PR 2 regardless of cryptographic strength —
  # PR 3 introduces the modern-only subset for :deprecated_signature_algorithm.
  @known_signature_algorithms MapSet.new([
                                "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
                                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                                "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
                                "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
                                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
                                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
                              ])

  @known_digest_algorithms MapSet.new([
                             "http://www.w3.org/2000/09/xmldsig#sha1",
                             "http://www.w3.org/2001/04/xmldsig-more#md5",
                             "http://www.w3.org/2001/04/xmlenc#sha256",
                             "http://www.w3.org/2001/04/xmldsig-more#sha384",
                             "http://www.w3.org/2001/04/xmlenc#sha512",
                             "http://www.w3.org/2001/04/xmlenc#ripemd160"
                           ])

  @spec violations(:xmerl.xmlElement(), keyword()) :: [ValidationResult.violation()]
  def violations(root, namespaces) do
    root
    |> signatures_with_path(namespaces)
    |> Enum.flat_map(fn {sig, path} -> signature_violations(sig, path, namespaces) end)
  end

  # ---------------------------------------------------------------------------
  # Signature discovery
  # ---------------------------------------------------------------------------

  defp signatures_with_path(root, namespaces) do
    document_level = collect("/EntityDescriptor", root, "./ds:Signature", namespaces)

    descriptor_level =
      ["SPSSODescriptor", "IDPSSODescriptor"]
      |> Enum.flat_map(fn tag ->
        root
        |> xpath_elems("./md:#{tag}", namespaces)
        |> Enum.flat_map(fn desc ->
          collect("/EntityDescriptor/#{tag}", desc, "./ds:Signature", namespaces)
        end)
      end)

    document_level ++ descriptor_level
  end

  defp collect(parent_path, context, xpath, namespaces) do
    sigs = xpath_elems(context, xpath, namespaces)
    total = length(sigs)

    sigs
    |> Enum.with_index(1)
    |> Enum.map(fn {sig, idx} ->
      index_segment = if total > 1, do: "[#{idx}]", else: ""
      {sig, "#{parent_path}/Signature#{index_segment}"}
    end)
  end

  # ---------------------------------------------------------------------------
  # Per-signature rules
  # ---------------------------------------------------------------------------

  defp signature_violations(sig, sig_path, namespaces) do
    case xpath_elems(sig, "./ds:SignedInfo", namespaces) do
      [] ->
        [missing_node(sig_path, "SignedInfo")]

      [signed_info | _] ->
        signature_value_violations(sig, sig_path, namespaces) ++
          signed_info_violations(signed_info, sig_path, namespaces)
    end
  end

  defp signature_value_violations(sig, sig_path, namespaces) do
    case xpath_elems(sig, "./ds:SignatureValue", namespaces) do
      [] -> [missing_node(sig_path, "SignatureValue")]
      _ -> []
    end
  end

  defp signed_info_violations(signed_info, sig_path, namespaces) do
    signature_method_violations(signed_info, sig_path, namespaces) ++
      reference_violations(signed_info, sig_path, namespaces)
  end

  defp signature_method_violations(signed_info, sig_path, namespaces) do
    case xpath_elems(signed_info, "./ds:SignatureMethod", namespaces) do
      [] ->
        [missing_node(sig_path, "SignedInfo/SignatureMethod")]

      [method | _] ->
        algorithm_violation(
          method,
          "#{sig_path}/SignedInfo/SignatureMethod/@Algorithm",
          @known_signature_algorithms,
          :unknown_signature_algorithm,
          "SignatureMethod"
        )
    end
  end

  defp reference_violations(signed_info, sig_path, namespaces) do
    case xpath_elems(signed_info, "./ds:Reference", namespaces) do
      [] ->
        [missing_node(sig_path, "SignedInfo/Reference")]

      refs ->
        refs
        |> Enum.with_index(1)
        |> Enum.flat_map(fn {ref, idx} ->
          ref_path = "#{sig_path}/SignedInfo/Reference[#{idx}]"
          digest_method_violations(ref, ref_path, namespaces) ++
            digest_value_violations(ref, ref_path, namespaces)
        end)
    end
  end

  defp digest_method_violations(ref, ref_path, namespaces) do
    case xpath_elems(ref, "./ds:DigestMethod", namespaces) do
      [] ->
        [missing_signature_node(ref_path <> "/DigestMethod")]

      [method | _] ->
        algorithm_violation(
          method,
          "#{ref_path}/DigestMethod/@Algorithm",
          @known_digest_algorithms,
          :unknown_digest_algorithm,
          "DigestMethod"
        )
    end
  end

  defp digest_value_violations(ref, ref_path, namespaces) do
    case xpath_elems(ref, "./ds:DigestValue", namespaces) do
      [] -> [missing_signature_node(ref_path <> "/DigestValue")]
      _ -> []
    end
  end

  defp algorithm_violation(element, path, known, code, kind) do
    case attr_value(element, "Algorithm") do
      nil ->
        [
          %{
            code: :invalid_signature_structure,
            severity: :error,
            message: "<ds:#{kind}> is missing the required Algorithm attribute",
            path: path,
            spec_reference: "XML-DSig §4.3"
          }
        ]

      value ->
        if value in known do
          []
        else
          [
            %{
              code: code,
              severity: :error,
              message: "Unknown #{kind} algorithm URI: " <> inspect(value),
              path: path,
              spec_reference: "XML-DSig §6.4, RFC 6931"
            }
          ]
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Violation builders
  # ---------------------------------------------------------------------------

  defp missing_node(sig_path, child) do
    %{
      code: :invalid_signature_structure,
      severity: :error,
      message: "<ds:Signature> is missing required child <ds:#{child}>",
      path: "#{sig_path}/#{child}",
      spec_reference: "XML-DSig §4.3"
    }
  end

  defp missing_signature_node(path) do
    %{
      code: :invalid_signature_structure,
      severity: :error,
      message: "<ds:Signature> is missing required descendant " <> path,
      path: path,
      spec_reference: "XML-DSig §4.3"
    }
  end

  # ---------------------------------------------------------------------------
  # XPath helpers
  # ---------------------------------------------------------------------------

  defp xpath_elems(context, path, namespaces) do
    :xmerl_xpath.string(to_charlist(path), context, [{:namespace, namespaces}])
  end

  defp attr_value(element, name) do
    case xpath_elems(element, "@#{name}", []) do
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
end
