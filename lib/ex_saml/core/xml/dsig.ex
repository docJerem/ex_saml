defmodule ExSaml.Core.Xml.Dsig do
  @moduledoc """
  XML Digital Signatures (XMLDSig) generation and verification.

  Implements enveloped XML digital signature generation and verification
  as specified at http://www.w3.org/TR/xmldsig-core/

  Currently supports RSA + SHA1|SHA256, ECDSA + SHA256|SHA384|SHA512 and
  ML-DSA-44|65|87 signatures. RSA-SHA1 is rejected on verification. ML-DSA
  needs OTP 28.1 or later linked with OpenSSL 3.5 or later; elsewhere it is
  rejected with `:unsupported_algorithm`.

  This module owns the XML side: canonicalization, the `Reference` digest,
  the `ds:Signature` structure and the certificate. Producing and checking
  the `SignatureValue` bytes is the job of one module per key type,
  `ExSaml.Core.Xml.Dsig.Rsa`, `ExSaml.Core.Xml.Dsig.Ecdsa` and
  `ExSaml.Core.Xml.Dsig.MlDsa`, chosen from the private key when signing and
  from the signature method when verifying.
  """

  alias ExSaml.Core.Util
  alias ExSaml.Core.Xml.C14n
  alias ExSaml.Core.Xml.Dsig.{Ecdsa, MlDsa, Rsa}

  require Logger
  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlDocument,
    Record.extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(
    :xmlNamespace,
    Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(
    :certificate,
    Record.extract(:Certificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecord(
    :tbs_certificate,
    Record.extract(:TBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecord(
    :subject_public_key_info,
    Record.extract(:SubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  # id-ecPublicKey, the SubjectPublicKeyInfo algorithm of an EC certificate.
  @ec_public_key {1, 2, 840, 10_045, 2, 1}
  @ml_dsa_oids MlDsa.oids()

  @type xml :: record(:xmlElement) | record(:xmlDocument)
  @type sig_method ::
          :rsa_sha1
          | :rsa_sha256
          | :ecdsa_sha256
          | :ecdsa_sha384
          | :ecdsa_sha512
          | :ml_dsa_44
          | :ml_dsa_65
          | :ml_dsa_87
  @type fingerprint :: binary() | {:sha | :sha256, binary()}
  @type key_type :: :rsa | :ecdsa | :ml_dsa
  @type method :: %{
          key_type: key_type(),
          algorithm: atom(),
          digest: :sha | :sha256 | :sha384 | :sha512,
          digest_uri: String.t(),
          uri: String.t()
        }

  @sha256_uri "http://www.w3.org/2001/04/xmlenc#sha256"
  @sha384_uri "http://www.w3.org/2001/04/xmldsig-more#sha384"
  @sha512_uri "http://www.w3.org/2001/04/xmlenc#sha512"

  # The signature methods, one row each:
  # - `key_type` names the module producing and checking the SignatureValue;
  # - `algorithm` is what that module signs and verifies with: the hash
  #   function for RSA and ECDSA, the parameter set for ML-DSA;
  # - `digest` and `digest_uri` are the Reference digest used when signing.
  #   RSA and ECDSA verify with it too; ML-DSA reads the DigestMethod instead;
  # - `uri` is the SignatureMethod.
  # `signature_props/1` looks a method up by its atom, or by its URI as a
  # string or charlist. The ML-DSA URIs come from
  # draft-eastlake-rfc9231bis-xmlsec-uris-09 §3.3.15, a draft: they may
  # change before it becomes an RFC.
  @methods [
    rsa_sha1: %{
      key_type: :rsa,
      algorithm: :sha,
      digest: :sha,
      digest_uri: "http://www.w3.org/2000/09/xmldsig#sha1",
      uri: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    },
    rsa_sha256: %{
      key_type: :rsa,
      algorithm: :sha256,
      digest: :sha256,
      digest_uri: @sha256_uri,
      uri: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    },
    ecdsa_sha256: %{
      key_type: :ecdsa,
      algorithm: :sha256,
      digest: :sha256,
      digest_uri: @sha256_uri,
      uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    },
    ecdsa_sha384: %{
      key_type: :ecdsa,
      algorithm: :sha384,
      digest: :sha384,
      digest_uri: @sha384_uri,
      uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    },
    ecdsa_sha512: %{
      key_type: :ecdsa,
      algorithm: :sha512,
      digest: :sha512,
      digest_uri: @sha512_uri,
      uri: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
    },
    ml_dsa_44: %{
      key_type: :ml_dsa,
      algorithm: :mldsa44,
      digest: :sha256,
      digest_uri: @sha256_uri,
      uri: "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44"
    },
    ml_dsa_65: %{
      key_type: :ml_dsa,
      algorithm: :mldsa65,
      digest: :sha384,
      digest_uri: @sha384_uri,
      uri: "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65"
    },
    ml_dsa_87: %{
      key_type: :ml_dsa,
      algorithm: :mldsa87,
      digest: :sha512,
      digest_uri: @sha512_uri,
      uri: "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87"
    }
  ]

  @method_by_name Enum.reduce(@methods, %{}, fn {name, %{uri: uri} = row}, acc ->
                    acc
                    |> Map.put(name, row)
                    |> Map.put(uri, row)
                    |> Map.put(String.to_charlist(uri), row)
                  end)

  # The Reference digests an ML-DSA signature may name, by DigestMethod URI
  # as a string or charlist: the SHA-2 ones.
  @digest_by_uri Enum.reduce(@methods, %{}, fn
                   {_name, %{digest: :sha}}, acc ->
                     acc

                   {_name, %{digest: digest, digest_uri: uri}}, acc ->
                     acc |> Map.put(uri, digest) |> Map.put(String.to_charlist(uri), digest)
                 end)

  @doc """
  Returns an element without any ds:Signature elements inside it.
  """
  @spec strip(xml()) :: xml()
  def strip(rec) when Record.is_record(rec, :xmlDocument) do
    new_kids =
      Enum.map(xmlDocument(rec, :content), fn k ->
        if Record.is_record(k, :xmlElement), do: strip(k), else: k
      end)

    xmlDocument(rec, content: new_kids)
  end

  def strip(rec) when Record.is_record(rec, :xmlElement) do
    new_kids = Enum.filter(xmlElement(rec, :content), &valid_kid?/1)
    xmlElement(rec, content: new_kids)
  end

  defp valid_kid?(kid) when Record.is_record(kid, :xmlElement) do
    C14n.canon_name(kid) != "http://www.w3.org/2000/09/xmldsig#Signature"
  end

  defp valid_kid?(kid) when Record.is_record(kid, :xmlAttribute) do
    C14n.canon_name(kid) != "http://www.w3.org/2000/09/xmldsig#Signature"
  end

  defp valid_kid?(_), do: true

  @doc """
  Signs the given XML element by creating a ds:Signature element within it,
  with the signature method `default_method/1` picks for the key.

  Returns the element with the signature added.
  """
  @spec sign(record(:xmlElement), tuple(), binary()) :: record(:xmlElement)
  def sign(element_in, private_key, cert_bin) when is_binary(cert_bin),
    do: sign(element_in, private_key, cert_bin, default_method(private_key))

  @doc """
  The signature method for a private key: `:rsa_sha256` for an RSA key;
  `:ecdsa_sha256`, `:ecdsa_sha384` or `:ecdsa_sha512` for an EC key on
  P-256, P-384 or P-521; `:ml_dsa_44`, `:ml_dsa_65` or `:ml_dsa_87` for an
  ML-DSA key.
  """
  @spec default_method(tuple()) :: sig_method()
  def default_method(private_key), do: signer(private_key).default_method(private_key)

  @doc """
  Signs the given XML element by creating a ds:Signature element within it,
  with the given signature method.

  The method must be one the key can produce: an RSA key cannot sign
  `:ecdsa_sha256`. Such a mismatch is not checked here but on verification,
  which rejects the signature.
  """
  @spec sign(record(:xmlElement), tuple(), binary(), sig_method() | String.t()) ::
          record(:xmlElement)
  def sign(element_in, private_key, cert_bin, sig_method) when is_binary(cert_bin) do
    element_strip = strip(element_in)

    # Ensure root element has an ID
    {element, id} =
      case find_attr(:ID, element_strip) do
        {:ok, cap_id} ->
          {element_strip, cap_id}

        :error ->
          case find_attr(:id, element_strip) do
            {:ok, low_id} ->
              {element_strip, low_id}

            :error ->
              new_id = Util.unique_id()

              attr =
                xmlAttribute(
                  name: :ID,
                  value: String.to_charlist(new_id),
                  namespace: xmlNamespace()
                )

              new_attrs = [attr | xmlElement(element_strip, :attributes)]
              {xmlElement(element_strip, attributes: new_attrs), String.to_charlist(new_id)}
          end
      end

    %{algorithm: algorithm, digest: digest_hash, digest_uri: digest_method, uri: sig_method_url} =
      signature_props(sig_method)

    # Compute digest of the canonical XML
    canon_xml = C14n.c14n(element)

    digest_value =
      :base64.encode_to_string(
        :crypto.hash(digest_hash, :unicode.characters_to_binary(canon_xml, :unicode, :utf8))
      )

    ns = xmlNamespace(nodes: [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}])

    sig_info =
      Util.build_nsinfo(
        ns,
        xmlElement(
          name: :"ds:SignedInfo",
          content: [
            xmlElement(
              name: :"ds:CanonicalizationMethod",
              attributes: [
                xmlAttribute(
                  name: :Algorithm,
                  value: ~c"http://www.w3.org/2001/10/xml-exc-c14n#"
                )
              ]
            ),
            xmlElement(
              name: :"ds:SignatureMethod",
              attributes: [
                xmlAttribute(name: :Algorithm, value: String.to_charlist(sig_method_url))
              ]
            ),
            xmlElement(
              name: :"ds:Reference",
              attributes: [
                xmlAttribute(name: :URI, value: :lists.flatten([~c"#" | id]))
              ],
              content: [
                xmlElement(
                  name: :"ds:Transforms",
                  content: [
                    xmlElement(
                      name: :"ds:Transform",
                      attributes: [
                        xmlAttribute(
                          name: :Algorithm,
                          value: ~c"http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                        )
                      ]
                    ),
                    xmlElement(
                      name: :"ds:Transform",
                      attributes: [
                        xmlAttribute(
                          name: :Algorithm,
                          value: ~c"http://www.w3.org/2001/10/xml-exc-c14n#"
                        )
                      ]
                    )
                  ]
                ),
                xmlElement(
                  name: :"ds:DigestMethod",
                  attributes: [
                    xmlAttribute(name: :Algorithm, value: String.to_charlist(digest_method))
                  ]
                ),
                xmlElement(
                  name: :"ds:DigestValue",
                  content: [xmlText(value: digest_value)]
                )
              ]
            )
          ]
        )
      )

    # Sign the SignedInfo element
    sig_info_canon = C14n.c14n(sig_info)
    data = :unicode.characters_to_binary(sig_info_canon, :unicode, :utf8)

    signature = signer(private_key).sign(data, algorithm, private_key)
    sig64 = :base64.encode_to_string(signature)
    cert64 = :base64.encode_to_string(cert_bin)

    sig_elem =
      Util.build_nsinfo(
        ns,
        xmlElement(
          name: :"ds:Signature",
          attributes: [
            xmlAttribute(
              name: :"xmlns:ds",
              value: ~c"http://www.w3.org/2000/09/xmldsig#"
            )
          ],
          content: [
            sig_info,
            xmlElement(
              name: :"ds:SignatureValue",
              content: [xmlText(value: sig64)]
            ),
            xmlElement(
              name: :"ds:KeyInfo",
              content: [
                xmlElement(
                  name: :"ds:X509Data",
                  content: [
                    xmlElement(
                      name: :"ds:X509Certificate",
                      content: [xmlText(value: cert64)]
                    )
                  ]
                )
              ]
            )
          ]
        )
      )

    xmlElement(element, content: [sig_elem | xmlElement(element, :content)])
  end

  @doc """
  Returns the canonical digest of an (optionally signed) element.
  """
  @spec digest(record(:xmlElement)) :: binary()
  def digest(element), do: digest(element, :sha256)

  @spec digest(record(:xmlElement), :sha | :sha256) :: binary()
  def digest(element, hash_function) do
    ds_ns = [
      {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"},
      {~c"ec", :"http://www.w3.org/2001/10/xml-exc-c14n#"}
    ]

    txs =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']",
        element,
        namespace: ds_ns
      )

    incl_ns =
      case txs do
        [c14n_tx] when Record.is_record(c14n_tx, :xmlElement) ->
          case :xmerl_xpath.string(~c"ec:InclusiveNamespaces/@PrefixList", c14n_tx,
                 namespace: ds_ns
               ) do
            [] -> []
            [attr] -> String.split(to_string(xmlAttribute(attr, :value)), [" ", ","])
          end

        _ ->
          []
      end

    canon_xml = C14n.c14n(strip(element), false, incl_ns)
    canon_xml_utf8 = :unicode.characters_to_binary(canon_xml, :unicode, :utf8)
    :crypto.hash(hash_function, canon_xml_utf8)
  end

  @doc """
  Verifies an XML digital signature, trusting any valid certificate.
  """
  @spec verify(record(:xmlElement)) ::
          :ok | {:error, :bad_digest | :bad_signature | :cert_not_accepted}
  def verify(element), do: verify(element, :any)

  @doc """
  Verifies an XML digital signature on the given element.

  `fingerprints` is a list of valid cert fingerprints that can be accepted,
  or `:any` to accept any valid certificate.
  """
  @spec verify(record(:xmlElement), [fingerprint()] | :any) ::
          :ok
          | {:error,
             :bad_digest
             | :bad_signature
             | :cert_not_accepted
             | :missing_certificate
             | :no_signature
             | :multiple_signatures
             | :insecure_algorithm
             | :unsupported_algorithm}
  def verify(element, fingerprints) do
    ds_ns = [
      {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"},
      {~c"ec", :"http://www.w3.org/2001/10/xml-exc-c14n#"}
    ]

    case :xmerl_xpath.string(
           ~c"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm",
           element,
           namespace: ds_ns
         ) do
      [] ->
        {:error, :no_signature}

      [algo_attr] when Record.is_record(algo_attr, :xmlAttribute) ->
        algo = xmlAttribute(algo_attr, :value)

        case signature_props(algo) do
          %{algorithm: :sha} ->
            Logger.error(
              "[ExSaml.Core] RSA-SHA1 signature rejected: algorithm is cryptographically broken. " <>
                "The IdP must be configured to use RSA-SHA256 or stronger."
            )

            {:error, :insecure_algorithm}

          %{key_type: :ml_dsa} = method ->
            verify_ml_dsa(element, fingerprints, method, ds_ns)

          %{} = method ->
            do_verify(element, fingerprints, method, ds_ns)

          :unsupported_algorithm ->
            Logger.error("[ExSaml.Core] Unsupported signature algorithm: #{algo}")
            {:error, :unsupported_algorithm}
        end

      _ ->
        {:error, :multiple_signatures}
    end
  end

  # ML-DSA needs OTP 28.1+ on OpenSSL 3.5+. And the draft's optional
  # SignatureContext cannot be passed to `:public_key`, so a Signature
  # carrying one is rejected rather than verified with the empty context.
  defp verify_ml_dsa(element, fingerprints, method, ds_ns) do
    cond do
      not MlDsa.available?() ->
        Logger.error(
          "[ExSaml.Core] ML-DSA signature rejected: this VM cannot verify it. " <>
            "ML-DSA needs OTP 28.1 or later linked with OpenSSL 3.5 or later."
        )

        {:error, :unsupported_algorithm}

      signature_context?(element, ds_ns) ->
        Logger.error("[ExSaml.Core] ML-DSA signature rejected: SignatureContext is not supported")
        {:error, :unsupported_algorithm}

      true ->
        do_verify(element, fingerprints, method, ds_ns)
    end
  end

  defp signature_context?(element, ds_ns) do
    :xmerl_xpath.string(
      ~c"ds:Signature/ds:Object//*[local-name()='SignatureContext']",
      element,
      namespace: ds_ns
    ) != []
  end

  defp do_verify(element, fingerprints, method, ds_ns) do
    incl_ns = extract_inclusive_ns(element, ds_ns)
    expected_digest = extract_expected_digest(element, ds_ns)

    with {:ok, digest_hash} <- reference_hash(element, method, ds_ns),
         :ok <- verify_digest(compute_digest(element, digest_hash, incl_ns), expected_digest) do
      verify_signature(element, method, ds_ns, fingerprints)
    end
  end

  # The hash of the Reference digest. The RSA and ECDSA methods fix it, as
  # they always did here. ML-DSA binds none, so the Reference's DigestMethod
  # says, among SHA-256, SHA-384 and SHA-512.
  defp reference_hash(element, %{key_type: :ml_dsa}, ds_ns) do
    [attr] =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm",
        element,
        namespace: ds_ns
      )

    digest_uri = xmlAttribute(attr, :value)

    case Map.fetch(@digest_by_uri, digest_uri) do
      {:ok, digest_hash} ->
        {:ok, digest_hash}

      :error ->
        Logger.error("[ExSaml.Core] Unsupported digest algorithm: #{digest_uri}")
        {:error, :unsupported_algorithm}
    end
  end

  defp reference_hash(_element, %{digest: digest_hash}, _ds_ns), do: {:ok, digest_hash}

  defp extract_inclusive_ns(element, ds_ns) do
    [c14n_tx] =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']",
        element,
        namespace: ds_ns
      )

    case :xmerl_xpath.string(~c"ec:InclusiveNamespaces/@PrefixList", c14n_tx, namespace: ds_ns) do
      [] -> []
      [attr] -> String.split(to_string(xmlAttribute(attr, :value)), [" ", ","])
    end
  end

  defp compute_digest(element, hash_function, incl_ns) do
    canon_xml = C14n.c14n(strip(element), false, incl_ns)
    canon_xml_utf8 = :unicode.characters_to_binary(canon_xml, :unicode, :utf8)
    :crypto.hash(hash_function, canon_xml_utf8)
  end

  defp extract_expected_digest(element, ds_ns) do
    [sha_text] =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue/text()",
        element,
        namespace: ds_ns
      )

    :base64.decode(xmlText(sha_text, :value))
  end

  defp verify_digest(computed, expected) when computed == expected, do: :ok
  defp verify_digest(_, _), do: {:error, :bad_digest}

  defp verify_signature(element, %{key_type: key_type, algorithm: algorithm}, ds_ns, fingerprints) do
    [sig_info] =
      :xmerl_xpath.string(~c"ds:Signature/ds:SignedInfo", element, namespace: ds_ns)

    data = sig_info |> C14n.c14n() |> String.to_charlist() |> :erlang.list_to_binary()

    [sig_text] =
      :xmerl_xpath.string(~c"ds:Signature//ds:SignatureValue/text()", element, namespace: ds_ns)

    sig = :base64.decode(xmlText(sig_text, :value))

    with {:ok, {key, cert_bin}} <- extract_public_key(element, ds_ns) do
      # A key of another kind than the method names fails here too.
      if verifier(key_type).verify(data, algorithm, sig, key),
        do: check_fingerprints(cert_bin, fingerprints),
        else: {:error, :bad_signature}
    end
  end

  # The module producing the SignatureValue for a private key.
  defp signer({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}), do: Rsa
  defp signer({:ECPrivateKey, _, _, _, _, _}), do: Ecdsa
  defp signer({:"ML-DSAPrivateKey", _, _, _}), do: MlDsa

  # The module checking the SignatureValue for a signature method's key type.
  defp verifier(:rsa), do: Rsa
  defp verifier(:ecdsa), do: Ecdsa
  defp verifier(:ml_dsa), do: MlDsa

  defp extract_public_key(element, ds_ns) do
    case :xmerl_xpath.string(
           ~c"ds:Signature//ds:X509Certificate/text()",
           element,
           namespace: ds_ns
         ) do
      [] ->
        {:error, :missing_certificate}

      # The first certificate is the signing one; the rest is its chain.
      [cert_text | _] ->
        cert_bin = :base64.decode(xmlText(cert_text, :value))
        cert = :public_key.pkix_decode_cert(cert_bin, :plain)
        tbs = certificate(cert, :tbsCertificate)
        spki = tbs_certificate(tbs, :subjectPublicKeyInfo)

        key_bin =
          case subject_public_key_info(spki, :subjectPublicKey) do
            {_, kb} -> kb
            kb -> kb
          end

        key = decode_public_key(subject_public_key_info(spki, :algorithm), key_bin)
        {:ok, {key, cert_bin}}
    end
  end

  defp check_fingerprints(_cert_bin, :any), do: :ok

  defp check_fingerprints(cert_bin, fingerprints) do
    cert_hash = :crypto.hash(:sha, cert_bin)
    cert_hash2 = :crypto.hash(:sha256, cert_bin)

    candidates = [cert_hash, {:sha, cert_hash}, {:sha256, cert_hash2}]

    if Enum.any?(candidates, &(&1 in fingerprints)),
      do: :ok,
      else: {:error, :cert_not_accepted}
  end

  # --- Private helpers ---

  # The public key of a certificate, from the algorithm and subjectPublicKey
  # of its SubjectPublicKeyInfo. Any algorithm but EC and ML-DSA is read as
  # RSA.
  defp decode_public_key({:AlgorithmIdentifier, @ec_public_key, parameters}, point),
    do: Ecdsa.public_key(parameters, point)

  defp decode_public_key({:AlgorithmIdentifier, oid, _parameters}, key_bin)
       when oid in @ml_dsa_oids,
       do: MlDsa.public_key(oid, key_bin)

  defp decode_public_key(_algorithm, key_der), do: Rsa.public_key(key_der)

  defp find_attr(name, element) do
    case :lists.keyfind(name, 2, xmlElement(element, :attributes)) do
      false -> :error
      attr -> {:ok, xmlAttribute(attr, :value)}
    end
  end

  @doc false
  @spec signature_props(sig_method() | String.t() | charlist()) ::
          method() | :unsupported_algorithm
  def signature_props(method), do: Map.get(@method_by_name, method, :unsupported_algorithm)
end
