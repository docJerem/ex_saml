defmodule ExSaml.Core.RedirectBindingSignature do
  @moduledoc """
  Verifies the query-string signature of a SAML HTTP-Redirect binding message.

  Per SAML 2.0 Bindings §3.4.4.1 (DEFLATE encoding), a signed Redirect binding
  message carries no XML signature. Instead, the sender signs the concatenation
  of the URL-encoded query components, in this exact order:

      SAMLRequest=value&RelayState=value&SigAlg=value

  (`SAMLResponse` instead of `SAMLRequest` for responses; `RelayState` is
  omitted when not present.) The Base64 signature is transmitted in the
  `Signature` query parameter.

  Verification MUST be performed against the *raw* (still URL-encoded) values
  as they appeared on the wire: re-encoding decoded values may not reproduce
  the original encoding (upper/lower case hex digits, space encoding, etc.).
  This mirrors `OneLogin::RubySaml::Utils.build_query_from_raw_parts` /
  `verify_signature` in ruby-saml.
  """

  require Record

  Record.defrecord(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecord(
    :otp_tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecord(
    :otp_subject_public_key_info,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  @digest_for_sig_alg %{
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => :sha,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => :sha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => :sha512
  }

  @doc """
  Verifies the Redirect binding signature carried in `query_string` against
  the given IdP DER certificates (`ExSaml.IdpData.certs`).

  `query_string` must be the raw query string as received on the wire
  (`Plug.Conn.query_string/0`), NOT decoded parameters.

  Verification succeeds if any one of the certificates validates the
  signature, so that IdP signing-certificate rotation (old and new
  certificates published side by side in metadata) keeps working.

  Returns `:ok` or:

    * `{:error, :missing_signature}` - `Signature` or `SigAlg` parameter absent,
      or no `SAMLRequest`/`SAMLResponse` payload present
    * `{:error, :unsupported_sig_alg}` - unknown `SigAlg` URI
    * `{:error, :invalid_signature}` - malformed Base64 signature, or the
      signature does not verify against any of the certificates
  """
  @spec verify(binary(), [binary()]) ::
          :ok | {:error, :missing_signature | :unsupported_sig_alg | :invalid_signature}
  def verify(query_string, der_certs) when is_binary(query_string) and is_list(der_certs) do
    raw = raw_params(query_string)

    with {:ok, sig_alg_raw, signature_raw} <- fetch_signature_params(raw),
         {:ok, digest} <- digest_for(sig_alg_raw),
         {:ok, signature} <- decode_signature(signature_raw),
         {:ok, signed_data} <- build_signed_data(raw, sig_alg_raw) do
      verify_with_certs(signed_data, digest, signature, der_certs)
    end
  end

  # ---------------------------------------------------------------------------
  # Raw query parsing
  # ---------------------------------------------------------------------------

  # Splits the raw query string into a `%{name => raw_value}` map without
  # decoding the values (parameter names are plain ASCII in this binding).
  defp raw_params(query_string) do
    query_string
    |> String.split("&")
    |> Enum.reduce(%{}, fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        [name, raw_value] -> Map.put_new(acc, name, raw_value)
        _ -> acc
      end
    end)
  end

  defp fetch_signature_params(%{"SigAlg" => sig_alg, "Signature" => signature}),
    do: {:ok, sig_alg, signature}

  defp fetch_signature_params(_), do: {:error, :missing_signature}

  defp digest_for(sig_alg_raw) do
    case Map.fetch(@digest_for_sig_alg, safe_decode(sig_alg_raw)) do
      {:ok, digest} -> {:ok, digest}
      :error -> {:error, :unsupported_sig_alg}
    end
  end

  defp decode_signature(signature_raw) do
    case signature_raw |> safe_decode() |> Base.decode64(ignore: :whitespace) do
      {:ok, signature} -> {:ok, signature}
      :error -> {:error, :invalid_signature}
    end
  end

  # Rebuilds the signed data in the canonical parameter order mandated by
  # SAML 2.0 Bindings §3.4.4.1, from the raw (still URL-encoded) values.
  defp build_signed_data(raw, sig_alg_raw) do
    case Map.take(raw, ["SAMLRequest", "SAMLResponse"]) do
      map when map_size(map) == 1 ->
        [{type, payload}] = Map.to_list(map)

        relay_state_part =
          case raw do
            %{"RelayState" => relay_state} -> "&RelayState=#{relay_state}"
            _ -> ""
          end

        {:ok, "#{type}=#{payload}#{relay_state_part}&SigAlg=#{sig_alg_raw}"}

      _ ->
        {:error, :missing_signature}
    end
  end

  defp safe_decode(raw_value) do
    URI.decode_www_form(raw_value)
  rescue
    ArgumentError -> raw_value
  end

  # ---------------------------------------------------------------------------
  # Public-key verification
  # ---------------------------------------------------------------------------

  defp verify_with_certs(signed_data, digest, signature, der_certs) do
    der_certs
    |> Enum.flat_map(&decode_public_key/1)
    |> Enum.any?(&:public_key.verify(signed_data, digest, signature, &1))
    |> case do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp decode_public_key(der_cert) do
    der_cert
    |> :public_key.pkix_decode_cert(:otp)
    |> otp_certificate(:tbsCertificate)
    |> otp_tbs_certificate(:subjectPublicKeyInfo)
    |> otp_subject_public_key_info(:subjectPublicKey)
    |> List.wrap()
  rescue
    # An undecodable certificate cannot validate anything; skip it so the
    # remaining metadata certificates still get a chance.
    _ -> []
  end
end
