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
    ValidationContext,
    Xml.Dsig,
    Xml.SafeXml
  }

  @type xml :: record(:xmlElement)
  @type dupe_fun :: (ExSaml.Core.Assertion.t(), binary() -> :ok | term())

  @protocol_ns [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @dsig_ns [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}]

  @xenc_ns [{~c"xenc", :"http://www.w3.org/2001/04/xmlenc#"}]

  @xenc11_ns [{~c"xenc11", :"http://www.w3.org/2009/xmlenc11#"}]

  # XML Encryption block ciphers of an EncryptedData: mode, :crypto cipher
  # and key size in bytes.
  @block_ciphers %{
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => {:cbc, :aes_128_cbc, 16},
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => {:cbc, :aes_192_cbc, 24},
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => {:cbc, :aes_256_cbc, 32},
    "http://www.w3.org/2009/xmlenc11#aes128-gcm" => {:gcm, :aes_128_gcm, 16},
    "http://www.w3.org/2009/xmlenc11#aes192-gcm" => {:gcm, :aes_192_gcm, 24},
    "http://www.w3.org/2009/xmlenc11#aes256-gcm" => {:gcm, :aes_256_gcm, 32}
  }

  # XML Encryption key transports of an EncryptedKey.
  @rsa_oaep_mgf1p "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
  @rsa_oaep "http://www.w3.org/2009/xmlenc11#rsa-oaep"
  @rsa_1_5 "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

  # The OAEP digest (ds:DigestMethod) and mask generation function
  # (xenc11:MGF) URIs; both default to SHA-1.
  @oaep_digests %{
    "http://www.w3.org/2000/09/xmldsig#sha1" => :sha,
    "http://www.w3.org/2001/04/xmlenc#sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384" => :sha384,
    "http://www.w3.org/2001/04/xmlenc#sha512" => :sha512
  }

  @oaep_mgf1_digests %{
    "http://www.w3.org/2009/xmlenc11#mgf1sha1" => :sha,
    "http://www.w3.org/2009/xmlenc11#mgf1sha224" => :sha224,
    "http://www.w3.org/2009/xmlenc11#mgf1sha256" => :sha256,
    "http://www.w3.org/2009/xmlenc11#mgf1sha384" => :sha384,
    "http://www.w3.org/2009/xmlenc11#mgf1sha512" => :sha512
  }

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
    issuer = SpConfig.entity_id(sp)

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
    issuer = SpConfig.entity_id(sp)

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
    issuer = SpConfig.entity_id(sp)

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
    entity_id = SpConfig.entity_id(sp)

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

  Uses a no-op duplicate detection function: the replay check (Profiles
  §4.1.4.5) needs the configured cache, so it is wired by
  `ExSaml.SPHandler`. A direct caller passes
  `ExSaml.AssertionReplayCache.duplicate_fun/1` to `validate_assertion/3`.
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

    ctx = ValidationContext.from_sp_config(sp)

    # The envelope signature is checked before an EncryptedAssertion is
    # decrypted, so an altered ciphertext is rejected without being decrypted.
    with :ok <- check_status_code(xml, ns, success_status),
         :ok <- verify_envelope_signature(xml, sp),
         {:ok, assertion_xml} <- extract_assertion(xml, ns, sp, ctx),
         :ok <- verify_assertion_signature(assertion_xml, sp),
         :ok <- check_response_issuer(xml, ns, ctx),
         :ok <- check_destination(xml, ctx),
         {:ok, assertion} <- Saml.validate_assertion(assertion_xml, ctx),
         :ok <- check_duplicate(assertion, xml, duplicate_fun) do
      {:ok, %{assertion | response_in_response_to: response_in_response_to(xml, ns)}}
    end
  end

  # `Response/@InResponseTo` (Core §3.2.2), `""` when absent. The consumer
  # matches it, like `SubjectConfirmationData/@InResponseTo`, against the
  # AuthnRequest it sent (Profiles §4.1.4.3).
  defp response_in_response_to(xml, ns) do
    case :xmerl_xpath.string(~c"/samlp:Response/@InResponseTo", xml, [{:namespace, ns}]) do
      [attr] when Record.is_record(attr, :xmlAttribute) -> to_string(xmlAttribute(attr, :value))
      _ -> ""
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

  defp extract_assertion(xml, ns, sp, ctx) do
    case :xmerl_xpath.string(
           ~c"/samlp:Response/saml:EncryptedAssertion",
           xml,
           [{:namespace, ns}]
         ) do
      [encrypted] when Record.is_record(encrypted, :xmlElement) ->
        with :ok <- check_unsigned_cbc(encrypted, sp, ctx) do
          decrypt_to_assertion(encrypted, ns, sp)
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

  defp decrypt_to_assertion(encrypted, ns, sp) do
    with {:ok, decrypted} <- decrypt_assertion(encrypted, sp),
         true <- Record.is_record(decrypted, :xmlElement),
         [assertion] <- :xmerl_xpath.string(~c"/saml:Assertion", decrypted, [{:namespace, ns}]) do
      {:ok, assertion}
    else
      _ -> {:error, :bad_assertion}
    end
  end

  # An AES-CBC EncryptedAssertion in a Response whose signature is not
  # required is decrypted before anything about it has been verified: the
  # CBC decryption and its padding check are then an oracle that anyone who
  # can post to the ACS can query. AES-GCM authenticates the ciphertext
  # before anything is decrypted, and a signed Response is verified before
  # decryption, so neither is flagged (`:unsigned_cbc`).
  defp check_unsigned_cbc(encrypted, sp, ctx) do
    algorithm = data_encryption_algorithm(encrypted)

    if match?({:cbc, _, _}, Map.get(@block_ciphers, algorithm)) and
         not sp.idp_signs_envelopes and not sp.allow_unsigned_cbc do
      ValidationContext.verdict(ctx, {:error, :unsigned_cbc},
        expected: "AES-GCM, or signed_envelopes_in_resp: true",
        actual: algorithm
      )
    else
      :ok
    end
  end

  defp data_encryption_algorithm(encrypted) do
    case :xmerl_xpath.string(
           ~c"./xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm",
           encrypted,
           [{:namespace, @xenc_ns}]
         ) do
      [attr] when Record.is_record(attr, :xmlAttribute) -> to_string(xmlAttribute(attr, :value))
      _ -> nil
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

  # Profiles §4.1.4.2. `Issuer` is optional on a `StatusResponseType`, so an
  # absent element is not a failure; a present one that names a different IdP
  # is. Runs after signature verification on purpose — checking it on an
  # unverified document would fill the warn logs with traffic that the
  # signature check rejects anyway.
  defp check_response_issuer(xml, ns, %ValidationContext{} = ctx) do
    expected = ctx.idp_entity_id |> to_string() |> String.trim()

    case {expected, response_issuer(xml, ns)} do
      {"", _} ->
        :ok

      {_, nil} ->
        :ok

      {expected, expected} ->
        :ok

      {expected, actual} ->
        ValidationContext.verdict(ctx, {:error, :bad_issuer}, expected: expected, actual: actual)
    end
  end

  defp response_issuer(xml, ns) do
    case :xmerl_xpath.string(~c"/samlp:Response/saml:Issuer/text()", xml, [{:namespace, ns}]) do
      [text] when Record.is_record(text, :xmlText) ->
        text |> xmlText(:value) |> to_string() |> String.trim()

      _ ->
        nil
    end
  end

  # Core §3.2.2 and Bindings §3.5.5.2: a `Destination` must be the URL the
  # response was delivered to, our ACS URL, compared verbatim like `Recipient`.
  # It is optional on an unsigned response and required on a signed one.
  # Skipped when the ACS URL is unknown.
  defp check_destination(xml, %ValidationContext{} = ctx) do
    expected = to_string(ctx.destination)
    ns = @protocol_ns ++ @dsig_ns

    case {expected, response_destination(xml, ns)} do
      {"", _} ->
        :ok

      {_, nil} ->
        if response_signed?(xml, ns),
          do:
            ValidationContext.verdict(ctx, {:error, :bad_destination},
              reason: :missing,
              expected: expected
            ),
          else: :ok

      {expected, expected} ->
        :ok

      {expected, actual} ->
        ValidationContext.verdict(ctx, {:error, :bad_destination},
          expected: expected,
          actual: actual
        )
    end
  end

  defp response_destination(xml, ns) do
    case :xmerl_xpath.string(~c"/samlp:Response/@Destination", xml, [{:namespace, ns}]) do
      [attr] when Record.is_record(attr, :xmlAttribute) -> to_string(xmlAttribute(attr, :value))
      _ -> nil
    end
  end

  defp response_signed?(xml, ns),
    do: :xmerl_xpath.string(~c"/samlp:Response/ds:Signature", xml, [{:namespace, ns}]) != []

  @doc """
  Returns the `ID` attribute of a generated request element, or `nil`.

  `generate_authn_request/3` mints the id internally — `Dsig.sign/3` prepends it
  when SP signing is on, `add_xml_id/1` appends it otherwise — and the SP needs
  it back to match the `InResponseTo` of the response it will receive.
  """
  @spec xml_id(xml()) :: String.t() | nil
  def xml_id(xml) do
    xml
    |> xmlElement(:attributes)
    |> Enum.find_value(fn attr ->
      Record.is_record(attr, :xmlAttribute) and xmlAttribute(attr, :name) == :ID and
        to_string(xmlAttribute(attr, :value))
    end)
    |> case do
      false -> nil
      value -> value
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
      Dsig.verify(xml, sp.trusted_fingerprints)
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

  # The signature is required when the IdP signs its LogoutResponses
  # (`idp_signs_logout_responses`, the default): without it, stripping the
  # signature off a LogoutResponse would get an unsigned one accepted. With
  # the option off, a signature is verified only when present.
  defp verify_logout_response_signature(xml, ns, sp) do
    signed? =
      match?(
        [_],
        :xmerl_xpath.string(~c"/samlp:LogoutResponse/ds:Signature", xml, [{:namespace, ns}])
      )

    if sp.idp_signs_logout_responses or signed? do
      Dsig.verify(xml, sp.trusted_fingerprints)
    else
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

  defp decrypt_assertion(xml, %SpConfig{} = sp) do
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

    symmetric_key = decrypt_key_info(encrypted_data, sp)

    [algorithm_attr] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptionMethod/@Algorithm",
        encrypted_data,
        [{:namespace, xenc_ns}]
      )

    algorithm = xmlAttribute(algorithm_attr, :value)

    assertion_xml = block_decrypt(to_string(algorithm), symmetric_key, cipher_value)

    SafeXml.scan(assertion_xml)
  rescue
    _ -> {:error, :decrypt_failed}
  catch
    _, _ -> {:error, :decrypt_failed}
  end

  defp decrypt_key_info(encrypted_data, %SpConfig{key: key} = sp) do
    ds_ns = @dsig_ns
    xenc_ns = @xenc_ns

    [key_info] =
      :xmerl_xpath.string(~c"./ds:KeyInfo", encrypted_data, [{:namespace, ds_ns}])

    [encryption_method] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptedKey/xenc:EncryptionMethod",
        key_info,
        [{:namespace, xenc_ns}]
      )

    [cipher_text] =
      :xmerl_xpath.string(
        ~c"./xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue/text()",
        key_info,
        [{:namespace, xenc_ns}]
      )

    cipher_value_b64 = xmlText(cipher_text, :value)
    cipher_value = :base64.decode(cipher_value_b64)

    :public_key.decrypt_private(cipher_value, key, key_transport_opts(encryption_method, sp))
  end

  # The :public_key options of an EncryptedKey's EncryptionMethod.
  defp key_transport_opts(encryption_method, sp) do
    [algorithm_attr] = :xmerl_xpath.string(~c"@Algorithm", encryption_method)

    case to_string(xmlAttribute(algorithm_attr, :value)) do
      @rsa_oaep_mgf1p ->
        oaep_opts(encryption_method, :sha)

      @rsa_oaep ->
        mgf1_digest =
          encryption_method
          |> child_algorithm(~c"xenc11:MGF", @xenc11_ns)
          |> lookup_algorithm(@oaep_mgf1_digests, :sha)

        oaep_opts(encryption_method, mgf1_digest)

      @rsa_1_5 ->
        if sp.allow_rsa_1_5_key_transport do
          [rsa_padding: :rsa_pkcs1_padding]
        else
          require Logger

          Logger.error(
            "[ExSaml.Core] RSA-1_5 key transport rejected (deprecated by XML Encryption 1.1). " <>
              "The IdP must encrypt with RSA-OAEP, or the SP be configured with " <>
              "allow_rsa_1_5_key_transport: true."
          )

          raise ArgumentError, "RSA-1_5 key transport not allowed"
        end
    end
  end

  defp oaep_opts(encryption_method, mgf1_digest) do
    digest =
      encryption_method
      |> child_algorithm(~c"ds:DigestMethod", @dsig_ns)
      |> lookup_algorithm(@oaep_digests, :sha)

    label =
      case :xmerl_xpath.string(~c"xenc:OAEPparams/text()", encryption_method, namespace: @xenc_ns) do
        [text] -> :base64.decode(xmlText(text, :value))
        [] -> <<>>
      end

    [
      rsa_padding: :rsa_pkcs1_oaep_padding,
      rsa_oaep_md: digest,
      rsa_mgf1_md: mgf1_digest,
      rsa_oaep_label: label
    ]
  end

  # The Algorithm of a child element, nil when the element is absent.
  defp child_algorithm(element, path, ns) do
    case :xmerl_xpath.string(path ++ ~c"/@Algorithm", element, namespace: ns) do
      [attr] -> to_string(xmlAttribute(attr, :value))
      [] -> nil
    end
  end

  # An unknown algorithm raises, which rejects the assertion.
  defp lookup_algorithm(nil, _algorithms, default), do: default
  defp lookup_algorithm(uri, algorithms, _default), do: Map.fetch!(algorithms, uri)

  defp block_decrypt(algorithm, symmetric_key, cipher_value) do
    {mode, cipher, key_size} = Map.fetch!(@block_ciphers, algorithm)
    ^key_size = byte_size(symmetric_key)
    block_decrypt(mode, cipher, symmetric_key, cipher_value)
  end

  # GCM: a 12-byte IV, the ciphertext, then a 16-byte tag.
  defp block_decrypt(:gcm, cipher, symmetric_key, cipher_value) do
    encrypted_size = byte_size(cipher_value) - 12 - 16

    <<iv::binary-12, encrypted::binary-size(encrypted_size), tag::binary-16>> = cipher_value

    case :crypto.crypto_one_time_aead(cipher, symmetric_key, iv, encrypted, <<>>, tag, false) do
      plaintext when is_binary(plaintext) -> plaintext
      :error -> raise ArgumentError, "AES-GCM authentication failed"
    end
  end

  # CBC: a 16-byte IV, then the ciphertext of the padded plaintext.
  defp block_decrypt(:cbc, cipher, symmetric_key, cipher_value) do
    <<iv::binary-16, encrypted::binary>> = cipher_value

    cipher
    |> :crypto.crypto_one_time(symmetric_key, iv, encrypted, false)
    |> unpad()
  end

  # XML Encryption padding (XML Encryption 1.1 §5.4.1): the last byte is the
  # padding length, from 1 to the 16-byte block size, and the padding bytes
  # before it are arbitrary.
  defp unpad(padded) do
    pad_len = :binary.last(padded)

    if pad_len in 1..16 and pad_len <= byte_size(padded),
      do: binary_part(padded, 0, byte_size(padded) - pad_len),
      else: raise(ArgumentError, "bad XML Encryption padding")
  end
end
