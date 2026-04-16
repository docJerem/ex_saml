defmodule ExSaml.Core.Sp do
  @moduledoc """
  SAML Service Provider (SP) operations.

  Pure Elixir port of the Erlang `esaml_sp` module. Provides functions for
  generating and validating SAML AuthnRequests, LogoutRequests, LogoutResponses,
  Assertions, and SP metadata.
  """

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlNamespace,
    Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")
  )

  alias ExSaml.Core.{
    AuthnRequest,
    LogoutRequest,
    LogoutResponse,
    Saml,
    SpConfig,
    SpMetadata,
    Subject,
    Util,
    Xml.Dsig
  }

  @type xml :: record(:xmlElement)
  @type dupe_fun :: (ExSaml.Core.Assertion.t(), binary() -> :ok | term())

  @protocol_ns [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @dsig_ns [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}]

  @xenc_ns [{~c"xenc", :"http://www.w3.org/2001/04/xmlenc#"}]

  # ---------------------------------------------------------------------------
  # Setup
  # ---------------------------------------------------------------------------

  @doc """
  Initializes and validates an SP configuration.

  Validates that `metadata_uri` and `consume_uri` are set. Converts trusted
  fingerprints to normalised binaries. Enables request and metadata signing
  when both `key` and `certificate` are present.

  Raises on invalid configuration.
  """
  @spec setup(SpConfig.t()) :: SpConfig.t()
  def setup(%SpConfig{} = sp) do
    fingerprints = Util.convert_fingerprints(sp.trusted_fingerprints)

    if sp.metadata_uri == "", do: raise("must specify metadata URI")
    if sp.consume_uri == "", do: raise("must specify consume URI")

    if sp.key == nil and sp.sp_sign_requests do
      raise "must specify a key to sign requests"
    end

    if sp.key != nil and sp.certificate != nil do
      %{sp | sp_sign_requests: true, sp_sign_metadata: true, trusted_fingerprints: fingerprints}
    else
      %{sp | trusted_fingerprints: fingerprints}
    end
  end

  # ---------------------------------------------------------------------------
  # AuthnRequest generation
  # ---------------------------------------------------------------------------

  @doc """
  Generates an AuthnRequest XML element.

  Delegates to `generate_authn_request/3` with `nil` name ID format.
  """
  @spec generate_authn_request(String.t(), SpConfig.t()) :: xml()
  def generate_authn_request(idp_url, %SpConfig{} = sp) do
    generate_authn_request(idp_url, sp, nil)
  end

  @doc """
  Generates an AuthnRequest XML element with an optional NameID format.

  Returns a signed XML element when SP signing is enabled, otherwise an
  unsigned element with a generated ID attribute.
  """
  @spec generate_authn_request(String.t(), SpConfig.t(), String.t() | nil) :: xml()
  def generate_authn_request(idp_url, %SpConfig{consume_uri: consume_uri} = sp, format) do
    stamp = now_saml_stamp()
    issuer = get_entity_id(sp)

    xml =
      Saml.to_xml(%AuthnRequest{
        issue_instant: stamp,
        destination: idp_url,
        issuer: issuer,
        name_format: format,
        consumer_location: consume_uri
      })

    if sp.sp_sign_requests do
      xml |> Dsig.sign(sp.key, sp.certificate) |> reorder_issuer()
    else
      add_xml_id(xml)
    end
  end

  # ---------------------------------------------------------------------------
  # LogoutRequest generation
  # ---------------------------------------------------------------------------

  @doc """
  Generates a LogoutRequest XML element.

  Delegates to `generate_logout_request/4` with an empty session index and
  a Subject built from the given name ID string.
  """
  @spec generate_logout_request(String.t(), String.t(), SpConfig.t()) :: xml()
  def generate_logout_request(idp_url, name_id, %SpConfig{} = sp) when is_binary(name_id) do
    generate_logout_request(idp_url, "", %Subject{name: name_id}, sp)
  end

  @doc """
  Generates a LogoutRequest XML element with a session index and Subject.
  """
  @spec generate_logout_request(String.t(), String.t(), Subject.t(), SpConfig.t()) :: xml()
  def generate_logout_request(idp_url, session_index, %Subject{} = subject, %SpConfig{} = sp) do
    stamp = now_saml_stamp()
    issuer = get_entity_id(sp)

    xml =
      Saml.to_xml(%LogoutRequest{
        issue_instant: stamp,
        destination: idp_url,
        issuer: issuer,
        name: subject.name,
        name_qualifier: subject.name_qualifier,
        sp_name_qualifier: subject.sp_name_qualifier,
        name_format: subject.name_format,
        session_index: session_index,
        reason: :user
      })

    if sp.sp_sign_requests do
      xml |> Dsig.sign(sp.key, sp.certificate) |> reorder_issuer()
    else
      add_xml_id(xml)
    end
  end

  # ---------------------------------------------------------------------------
  # LogoutResponse generation
  # ---------------------------------------------------------------------------

  @doc """
  Generates a LogoutResponse XML element.
  """
  @spec generate_logout_response(String.t(), atom(), SpConfig.t()) :: xml()
  def generate_logout_response(idp_url, status, %SpConfig{} = sp) do
    stamp = now_saml_stamp()
    issuer = get_entity_id(sp)

    xml =
      Saml.to_xml(%LogoutResponse{
        issue_instant: stamp,
        destination: idp_url,
        issuer: issuer,
        status: status
      })

    if sp.sp_sign_requests do
      xml |> Dsig.sign(sp.key, sp.certificate) |> reorder_issuer()
    else
      add_xml_id(xml)
    end
  end

  # ---------------------------------------------------------------------------
  # Metadata generation
  # ---------------------------------------------------------------------------

  @doc """
  Generates SP metadata as an XML element.
  """
  @spec generate_metadata(SpConfig.t()) :: xml()
  def generate_metadata(%SpConfig{org: org, tech: tech} = sp) do
    entity_id = get_entity_id(sp)

    xml =
      Saml.to_xml(%SpMetadata{
        org: org,
        tech: tech,
        signed_requests: sp.sp_sign_requests,
        signed_assertions: sp.idp_signs_assertions or sp.idp_signs_envelopes,
        certificate: sp.certificate,
        cert_chain: sp.cert_chain,
        consumer_location: sp.consume_uri,
        logout_location: sp.logout_uri,
        entity_id: entity_id
      })

    if sp.sp_sign_metadata do
      Dsig.sign(xml, sp.key, sp.certificate)
    else
      add_xml_id(xml)
    end
  end

  # ---------------------------------------------------------------------------
  # Assertion validation
  # ---------------------------------------------------------------------------

  @doc """
  Validates and decodes a SAML Response XML element.

  Uses a no-op duplicate detection function.
  """
  @spec validate_assertion(xml(), SpConfig.t()) ::
          {:ok, ExSaml.Core.Assertion.t()} | {:error, term()}
  def validate_assertion(xml, %SpConfig{} = sp) do
    validate_assertion(xml, fn _a, _digest -> :ok end, sp)
  end

  @doc """
  Validates and decodes a SAML Response XML element.

  The `duplicate_fun` callback receives the decoded assertion and the XML
  digest, and should return `:ok` or an error term to reject duplicates.
  """
  @spec validate_assertion(xml(), dupe_fun(), SpConfig.t()) ::
          {:ok, ExSaml.Core.Assertion.t()} | {:error, term()}
  def validate_assertion(xml, duplicate_fun, %SpConfig{} = sp) do
    ns = @protocol_ns
    success_status = ~c"urn:oasis:names:tc:SAML:2.0:status:Success"

    with :ok <- check_status_code(xml, ns, success_status),
         {:ok, assertion_xml} <- extract_assertion(xml, ns, sp),
         :ok <- verify_envelope_signature(xml, sp),
         :ok <- verify_assertion_signature(assertion_xml, sp),
         {:ok, assertion} <-
           Saml.validate_assertion(assertion_xml, sp.consume_uri, get_entity_id(sp)),
         :ok <- check_duplicate(assertion, xml, duplicate_fun) do
      {:ok, assertion}
    end
  end

  # -- assertion validation helpers --

  defp check_status_code(xml, ns, success_status) do
    case :xmerl_xpath.string(
           ~c"/samlp:Response/samlp:Status/samlp:StatusCode/@Value",
           xml,
           [{:namespace, ns}]
         ) do
      [status_code] when Record.is_record(status_code, :xmlAttribute) ->
        check_status_value(xmlAttribute(status_code, :value), success_status, xml, ns)

      _ ->
        {:error, :bad_saml}
    end
  end

  defp check_status_value(status, status, _xml, _ns), do: :ok

  defp check_status_value(error_status, _success, xml, ns) do
    error_message =
      case :xmerl_xpath.string(
             ~c"/samlp:Response/samlp:Status/samlp:StatusMessage/text()",
             xml,
             [{:namespace, ns}]
           ) do
        [] -> nil
        [a] -> :lists.flatten(:xmerl_xs.value_of(a))
        _ -> :malformed
      end

    {:error, {:saml_error, error_status, error_message}}
  end

  defp extract_assertion(xml, ns, sp) do
    case :xmerl_xpath.string(
           ~c"/samlp:Response/saml:EncryptedAssertion",
           xml,
           [{:namespace, ns}]
         ) do
      [encrypted] when Record.is_record(encrypted, :xmlElement) ->
        try do
          decrypted = decrypt_assertion(encrypted, sp)
          true = Record.is_record(decrypted, :xmlElement)

          case :xmerl_xpath.string(~c"/saml:Assertion", decrypted, [{:namespace, ns}]) do
            [a] -> {:ok, a}
            _ -> {:error, :bad_assertion}
          end
        rescue
          _ -> {:error, :bad_assertion}
        catch
          _, _ -> {:error, :bad_assertion}
        end

      _ ->
        case :xmerl_xpath.string(
               ~c"/samlp:Response/saml:Assertion",
               xml,
               [{:namespace, ns}]
             ) do
          [a] when Record.is_record(a, :xmlElement) -> {:ok, a}
          _ -> {:error, :bad_assertion}
        end
    end
  end

  defp verify_envelope_signature(xml, sp) do
    if sp.idp_signs_envelopes do
      case Dsig.verify(xml, sp.trusted_fingerprints) do
        :ok -> :ok
        error -> {:error, {:envelope, error}}
      end
    else
      :ok
    end
  end

  defp verify_assertion_signature(assertion_xml, sp) do
    if sp.idp_signs_assertions do
      case Dsig.verify(assertion_xml, sp.trusted_fingerprints) do
        :ok -> :ok
        error -> {:error, {:assertion, error}}
      end
    else
      :ok
    end
  end

  defp check_duplicate(assertion, xml, duplicate_fun) do
    case duplicate_fun.(assertion, Dsig.digest(xml)) do
      :ok -> :ok
      _ -> {:error, :duplicate}
    end
  end

  # ---------------------------------------------------------------------------
  # LogoutRequest validation
  # ---------------------------------------------------------------------------

  @doc """
  Validates and decodes a LogoutRequest XML element.
  """
  @spec validate_logout_request(xml(), SpConfig.t()) ::
          {:ok, LogoutRequest.t()} | {:error, term()}
  def validate_logout_request(xml, %SpConfig{} = sp) do
    ns = @protocol_ns

    with :ok <- require_xpath_element(xml, ~c"/samlp:LogoutRequest", ns),
         :ok <- verify_logout_request_signature(xml, sp) do
      safe_decode_logout_request(xml)
    end
  end

  defp verify_logout_request_signature(xml, sp) do
    if sp.idp_signs_logout_requests do
      case Dsig.verify(xml, sp.trusted_fingerprints) do
        :ok -> :ok
        error -> {:error, error}
      end
    else
      :ok
    end
  end

  defp safe_decode_logout_request(xml) do
    case Saml.decode_logout_request(xml) do
      {:ok, lr} -> {:ok, lr}
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, reason}
  end

  # ---------------------------------------------------------------------------
  # LogoutResponse validation
  # ---------------------------------------------------------------------------

  @doc """
  Validates and decodes a LogoutResponse XML element.
  """
  @spec validate_logout_response(xml(), SpConfig.t()) ::
          {:ok, LogoutResponse.t()} | {:error, term()}
  def validate_logout_response(xml, %SpConfig{} = sp) do
    ns = @protocol_ns ++ @dsig_ns

    with :ok <- require_xpath_element(xml, ~c"/samlp:LogoutResponse", ns),
         :ok <- verify_logout_response_signature(xml, ns, sp),
         {:ok, lr} <- safe_decode_logout_response(xml),
         :ok <- check_logout_response_status(lr) do
      {:ok, lr}
    end
  end

  defp verify_logout_response_signature(xml, ns, sp) do
    case :xmerl_xpath.string(~c"/samlp:LogoutResponse/ds:Signature", xml, [{:namespace, ns}]) do
      [sig] when Record.is_record(sig, :xmlElement) ->
        case Dsig.verify(xml, sp.trusted_fingerprints) do
          :ok -> :ok
          error -> {:error, error}
        end

      _ ->
        :ok
    end
  end

  defp safe_decode_logout_response(xml) do
    case Saml.decode_logout_response(xml) do
      {:ok, lr} -> {:ok, lr}
      {:error, reason} -> {:error, reason}
    end
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, reason}
  end

  defp check_logout_response_status(%LogoutResponse{status: :success} = _lr), do: :ok
  defp check_logout_response_status(%LogoutResponse{status: s}), do: {:error, s}

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp require_xpath_element(xml, path, ns) do
    case :xmerl_xpath.string(path, xml, [{:namespace, ns}]) do
      [elem] when Record.is_record(elem, :xmlElement) -> :ok
      _ -> {:error, :bad_assertion}
    end
  end

  defp add_xml_id(xml) do
    attrs =
      xmlElement(xml, :attributes) ++
        [xmlAttribute(name: :ID, value: to_charlist(Util.unique_id()), namespace: xmlNamespace())]

    xmlElement(xml, attributes: attrs)
  end

  defp get_entity_id(%SpConfig{entity_id: nil, metadata_uri: meta_uri}), do: meta_uri
  defp get_entity_id(%SpConfig{entity_id: entity_id}), do: entity_id

  defp reorder_issuer(elem) do
    content = xmlElement(elem, :content)

    case Enum.split_with(content, fn
           rec when Record.is_record(rec, :xmlElement) ->
             xmlElement(rec, :name) == :"saml:Issuer"

           _ ->
             false
         end) do
      {[issuer], other} -> xmlElement(elem, content: [issuer | other])
      _ -> elem
    end
  end

  defp now_saml_stamp do
    :erlang.localtime()
    |> :erlang.localtime_to_universaltime()
    |> Util.datetime_to_saml()
  end

  # ---------------------------------------------------------------------------
  # Decryption helpers
  # ---------------------------------------------------------------------------

  defp decrypt_assertion(xml, %SpConfig{key: private_key}) do
    xenc_ns = @xenc_ns

    [encrypted_data] =
      :xmerl_xpath.string(~c"./xenc:EncryptedData", xml, [{:namespace, xenc_ns}])

    [cipher_text] =
      :xmerl_xpath.string(
        ~c"xenc:CipherData/xenc:CipherValue/text()",
        encrypted_data,
        [{:namespace, xenc_ns}]
      )

    cipher_value_b64 = xmlText(cipher_text, :value)
    cipher_value = :base64.decode(cipher_value_b64)

    symmetric_key = decrypt_key_info(encrypted_data, private_key)

    [algorithm_attr] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptionMethod/@Algorithm",
        encrypted_data,
        [{:namespace, xenc_ns}]
      )

    algorithm = xmlAttribute(algorithm_attr, :value)

    assertion_xml = block_decrypt(to_string(algorithm), symmetric_key, cipher_value)

    {assertion, _} =
      :xmerl_scan.string(to_charlist(assertion_xml),
        namespace_conformant: true,
        allow_entities: false
      )

    assertion
  end

  defp decrypt_key_info(encrypted_data, key) do
    ds_ns = @dsig_ns
    xenc_ns = @xenc_ns

    [key_info] =
      :xmerl_xpath.string(~c"./ds:KeyInfo", encrypted_data, [{:namespace, ds_ns}])

    [algorithm_attr] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm",
        key_info,
        [{:namespace, xenc_ns}]
      )

    algorithm = xmlAttribute(algorithm_attr, :value)

    [cipher_text] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue/text()",
        key_info,
        [{:namespace, xenc_ns}]
      )

    cipher_value_b64 = xmlText(cipher_text, :value)
    cipher_value = :base64.decode(cipher_value_b64)

    decrypt(cipher_value, to_string(algorithm), key)
  end

  defp decrypt(cipher_value, "http://www.w3.org/2001/04/xmlenc#rsa-1_5", key) do
    opts = [
      {:rsa_padding, :rsa_pkcs1_padding},
      {:rsa_pad, :rsa_pkcs1_padding}
    ]

    :public_key.decrypt_private(cipher_value, key, opts)
  end

  defp decrypt(cipher_value, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", key) do
    opts = [
      {:rsa_padding, :rsa_pkcs1_oaep_padding},
      {:rsa_pad, :rsa_pkcs1_oaep_padding}
    ]

    :public_key.decrypt_private(cipher_value, key, opts)
  end

  defp block_decrypt("http://www.w3.org/2009/xmlenc11#aes128-gcm", symmetric_key, cipher_value) do
    # IV: 12 bytes, Tag: 16 bytes
    encrypted_data_size = byte_size(cipher_value) - 12 - 16

    <<iv::binary-12, encrypted_data::binary-size(encrypted_data_size), tag::binary-16>> =
      cipher_value

    decrypted =
      :crypto.crypto_one_time_aead(
        :aes_128_gcm,
        symmetric_key,
        iv,
        encrypted_data,
        <<>>,
        tag,
        false
      )

    decrypted
  end

  defp block_decrypt("http://www.w3.org/2001/04/xmlenc#aes128-cbc", symmetric_key, cipher_value) do
    <<iv::binary-16, encrypted_data::binary>> = cipher_value
    decrypted = :crypto.crypto_one_time(:aes_128_cbc, symmetric_key, iv, encrypted_data, false)
    strip_pkcs7_padding(decrypted)
  end

  defp block_decrypt("http://www.w3.org/2001/04/xmlenc#aes256-cbc", symmetric_key, cipher_value) do
    <<iv::binary-16, encrypted_data::binary>> = cipher_value
    decrypted = :crypto.crypto_one_time(:aes_256_cbc, symmetric_key, iv, encrypted_data, false)
    strip_pkcs7_padding(decrypted)
  end

  defp strip_pkcs7_padding(data) when is_binary(data) do
    data
    |> :binary.bin_to_list()
    |> Enum.reverse()
    |> Enum.drop_while(fn x -> x < 16 end)
    |> Enum.reverse()
    |> :erlang.list_to_binary()
  end
end
