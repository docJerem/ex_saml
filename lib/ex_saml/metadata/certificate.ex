defmodule ExSaml.Metadata.Certificate do
  @moduledoc false

  # Certificate-level metadata validation rules.
  #
  # Iterates every `<md:KeyDescriptor>` declared under an `<md:SPSSODescriptor>`
  # or `<md:IDPSSODescriptor>` and emits violations for the structural and
  # validity expectations of PR 2:
  #
  #   * `:missing_x509_certificate` — KeyDescriptor without a non-empty
  #     `<ds:X509Certificate>` text node.
  #   * `:invalid_x509_certificate` — text that does not decode as base64 DER
  #     or whose ASN.1 structure cannot be parsed by `:public_key`.
  #   * `:certificate_expired` — parseable certificate whose `notAfter` is in
  #     the past relative to `DateTime.utc_now/0`. Silence-able via
  #     `ExSaml.Metadata.validate/2`'s `:ignore` option.
  #
  # Best-practice rules that depend on certificate inspection (CA detection,
  # KeyUsage linting, shared signing/encryption certificate) live in the next
  # batch of rules alongside strict-mode plumbing — see issue #17 PR 3.

  alias ExSaml.Metadata.ValidationResult

  require Record

  Record.defrecordp(
    :xml_element,
    :xmlElement,
    Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecordp(
    :xml_text,
    :xmlText,
    Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl")
  )

  @descriptor_kinds [:sp, :idp]

  @spec violations(:xmerl.xmlElement(), keyword()) :: [ValidationResult.violation()]
  def violations(root, namespaces) do
    @descriptor_kinds
    |> Enum.flat_map(&key_descriptors_with_path(root, &1, namespaces))
    |> Enum.flat_map(fn {kd, path} -> kd_violations(kd, path, namespaces) end)
  end

  # ---------------------------------------------------------------------------
  # KeyDescriptor enumeration
  # ---------------------------------------------------------------------------

  defp key_descriptors_with_path(root, kind, namespaces) do
    descriptor_tag = descriptor_tag(kind)

    root
    |> xpath_elems("./md:#{descriptor_tag}", namespaces)
    |> Enum.flat_map(fn desc ->
      kds = xpath_elems(desc, "./md:KeyDescriptor", namespaces)
      total = length(kds)

      kds
      |> Enum.with_index(1)
      |> Enum.map(fn {kd, idx} ->
        index_segment = if total > 1, do: "[#{idx}]", else: ""
        {kd, "/EntityDescriptor/#{descriptor_tag}/KeyDescriptor#{index_segment}"}
      end)
    end)
  end

  defp descriptor_tag(:sp), do: "SPSSODescriptor"
  defp descriptor_tag(:idp), do: "IDPSSODescriptor"

  # ---------------------------------------------------------------------------
  # Per-KeyDescriptor rules
  # ---------------------------------------------------------------------------

  defp kd_violations(kd, kd_path, namespaces) do
    cert_elems = xpath_elems(kd, "./ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces)

    case cert_elems do
      [] ->
        [missing_cert_violation(kd_path)]

      list ->
        total = length(list)

        list
        |> Enum.with_index(1)
        |> Enum.flat_map(fn {cert_elem, idx} ->
          cert_path = cert_path(kd_path, idx, total)

          case String.trim(text_content(cert_elem)) do
            "" -> [missing_cert_violation(kd_path)]
            text -> validate_cert(text, cert_path)
          end
        end)
    end
  end

  defp cert_path(kd_path, _idx, 1), do: kd_path <> "/KeyInfo/X509Data/X509Certificate"
  defp cert_path(kd_path, idx, _), do: kd_path <> "/KeyInfo/X509Data/X509Certificate[#{idx}]"

  defp validate_cert(b64, path) do
    case parse_b64(b64) do
      {:ok, cert} ->
        if expired?(cert, DateTime.utc_now()) do
          [expired_violation(path)]
        else
          []
        end

      :error ->
        [invalid_cert_violation(path)]
    end
  end

  # ---------------------------------------------------------------------------
  # Certificate parsing
  # ---------------------------------------------------------------------------

  defp parse_b64(b64) do
    cleaned = String.replace(b64, ~r/\s+/, "")

    with {:ok, der} <- Base.decode64(cleaned),
         {:ok, cert} <- safe_pkix_decode(der) do
      {:ok, cert}
    else
      _ -> :error
    end
  end

  defp safe_pkix_decode(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp expired?(cert, now) do
    case not_after(cert) do
      %DateTime{} = dt -> DateTime.compare(now, dt) == :gt
      nil -> false
    end
  end

  defp not_after(cert) do
    cert
    |> elem(1)
    |> elem(5)
    |> elem(2)
    |> parse_asn1_time()
  rescue
    _ -> nil
  end

  defp parse_asn1_time({:utcTime, charlist}) do
    case to_string(charlist) do
      <<yy::binary-2, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2,
        "Z">> ->
        yy_int = String.to_integer(yy)
        year = if yy_int >= 50, do: 1900 + yy_int, else: 2000 + yy_int
        to_datetime(year, mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

  defp parse_asn1_time({:generalTime, charlist}) do
    case to_string(charlist) do
      <<year::binary-4, mm::binary-2, dd::binary-2, hh::binary-2, mi::binary-2, ss::binary-2,
        "Z">> ->
        to_datetime(String.to_integer(year), mm, dd, hh, mi, ss)

      _ ->
        nil
    end
  end

  defp parse_asn1_time(_), do: nil

  defp to_datetime(year, mm, dd, hh, mi, ss) do
    iso =
      "#{pad4(year)}-#{mm}-#{dd}T#{hh}:#{mi}:#{ss}Z"

    case DateTime.from_iso8601(iso) do
      {:ok, dt, 0} -> dt
      _ -> nil
    end
  end

  defp pad4(year), do: year |> Integer.to_string() |> String.pad_leading(4, "0")

  # ---------------------------------------------------------------------------
  # Text extraction
  # ---------------------------------------------------------------------------

  defp text_content(element) do
    element
    |> xml_element(:content)
    |> Enum.flat_map(fn
      child when Record.is_record(child, :xmlText) -> [xml_text(child, :value)]
      _ -> []
    end)
    |> IO.iodata_to_binary()
  end

  # ---------------------------------------------------------------------------
  # XPath wrapper
  # ---------------------------------------------------------------------------

  defp xpath_elems(context, path, namespaces) do
    :xmerl_xpath.string(to_charlist(path), context, [{:namespace, namespaces}])
  end

  # ---------------------------------------------------------------------------
  # Violation builders
  # ---------------------------------------------------------------------------

  defp missing_cert_violation(kd_path) do
    %{
      code: :missing_x509_certificate,
      severity: :error,
      message: "<md:KeyDescriptor> must contain a non-empty <ds:X509Certificate>",
      path: kd_path,
      spec_reference: "SAML 2.0 Metadata §2.4.1.1, XML-DSig §4.4.4"
    }
  end

  defp invalid_cert_violation(path) do
    %{
      code: :invalid_x509_certificate,
      severity: :error,
      message: "<ds:X509Certificate> content is not a parseable base64 DER X.509 certificate",
      path: path,
      spec_reference: "XML-DSig §4.4.4, RFC 5280 §4.1"
    }
  end

  defp expired_violation(path) do
    %{
      code: :certificate_expired,
      severity: :error,
      message: "X.509 certificate is expired (notAfter is in the past)",
      path: path,
      spec_reference: "RFC 5280 §4.1.2.5"
    }
  end
end
