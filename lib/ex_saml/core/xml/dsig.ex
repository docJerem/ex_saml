defmodule ExSaml.Core.Xml.Dsig do
  @moduledoc """
  XML Digital Signatures (XMLDSig) generation and verification.

  Implements enveloped XML digital signature generation and verification
  as specified at http://www.w3.org/TR/xmldsig-core/

  Currently supports RSA + SHA1|SHA256|SHA384|SHA512 and
  ECDSA + SHA256|SHA384|SHA512 signatures. RSA-SHA1 is rejected on verification.
  The `Reference` is digested with the hash its `DigestMethod` names
  (SHA256|SHA384|SHA512), which need not be the signature method's; a SHA1
  digest is rejected on verification.

  This module owns the XML side: canonicalization, the `Reference` digest,
  the `ds:Signature` structure and the certificate. Producing and checking
  the `SignatureValue` bytes is the job of one module per key type,
  `ExSaml.Core.Xml.Dsig.Rsa` and `ExSaml.Core.Xml.Dsig.Ecdsa`, behind the
  `ExSaml.Core.Xml.Dsig.KeyAlgorithm` behaviour. When signing, the module is
  chosen from the private key, which must be of the type the signature method
  names. When verifying, it is chosen from the signature method, and the
  certificate's key must be of that type: a certificate of any other type is
  rejected with `:bad_signature`.
  """

  alias ExSaml.Core.Util
  alias ExSaml.Core.Xml.C14n
  alias ExSaml.Core.Xml.Dsig.{Ecdsa, KeyAlgorithm, Rsa}

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

  # XML-DSig namespaces and algorithm URIs: xmldsig-core, exc-c14n,
  # RFC 4051 and RFC 6931.
  @xmldsig_ns "http://www.w3.org/2000/09/xmldsig#"
  @exc_c14n "http://www.w3.org/2001/10/xml-exc-c14n#"
  @enveloped_signature "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  @signature_element "http://www.w3.org/2000/09/xmldsig#Signature"

  @digest_sha1 "http://www.w3.org/2000/09/xmldsig#sha1"
  @digest_sha256 "http://www.w3.org/2001/04/xmlenc#sha256"
  @digest_sha384 "http://www.w3.org/2001/04/xmldsig-more#sha384"
  @digest_sha512 "http://www.w3.org/2001/04/xmlenc#sha512"

  @rsa_sha1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @rsa_sha384 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
  @rsa_sha512 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  @ecdsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
  @ecdsa_sha384 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
  @ecdsa_sha512 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

  # The prefixes the XPath queries use.
  @xpath_ns [
    {~c"ds", String.to_atom(@xmldsig_ns)},
    {~c"ec", String.to_atom(@exc_c14n)}
  ]

  @type xml :: record(:xmlElement) | record(:xmlDocument)
  @type sig_method ::
          :rsa_sha1
          | :rsa_sha256
          | :rsa_sha384
          | :rsa_sha512
          | :ecdsa_sha256
          | :ecdsa_sha384
          | :ecdsa_sha512
  @type fingerprint :: binary() | {:sha | :sha256, binary()}
  @type verify_error ::
          :bad_digest
          | :bad_signature
          | :cert_not_accepted
          | :missing_certificate
          | :no_signature
          | :multiple_signatures
          | :insecure_algorithm
          | :unsupported_algorithm

  # The module of each key type.
  @key_algorithms [Rsa, Ecdsa]

  # The signature methods, one row each: hash function, DigestMethod URI,
  # SignatureMethod URI and the module of the key type the method needs.
  # `signature_props/1` looks a method up by its atom, or by its URI as a
  # string or charlist.
  @methods [
    rsa_sha1: {:sha, @digest_sha1, @rsa_sha1, Rsa},
    rsa_sha256: {:sha256, @digest_sha256, @rsa_sha256, Rsa},
    rsa_sha384: {:sha384, @digest_sha384, @rsa_sha384, Rsa},
    rsa_sha512: {:sha512, @digest_sha512, @rsa_sha512, Rsa},
    ecdsa_sha256: {:sha256, @digest_sha256, @ecdsa_sha256, Ecdsa},
    ecdsa_sha384: {:sha384, @digest_sha384, @ecdsa_sha384, Ecdsa},
    ecdsa_sha512: {:sha512, @digest_sha512, @ecdsa_sha512, Ecdsa}
  ]

  # The hash function of each DigestMethod URI. The Reference is digested with
  # the hash its own DigestMethod names, which need not be the SignatureMethod's.
  @digest_by_uri %{
    @digest_sha1 => :sha,
    @digest_sha256 => :sha256,
    @digest_sha384 => :sha384,
    @digest_sha512 => :sha512
  }

  @method_by_name Enum.reduce(@methods, %{}, fn {name, {_, _, uri, _} = row}, acc ->
                    acc
                    |> Map.put(name, row)
                    |> Map.put(uri, row)
                    |> Map.put(String.to_charlist(uri), row)
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
    C14n.canon_name(kid) != @signature_element
  end

  defp valid_kid?(kid) when Record.is_record(kid, :xmlAttribute) do
    C14n.canon_name(kid) != @signature_element
  end

  defp valid_kid?(_), do: true

  @doc """
  Signs the given XML element by creating a ds:Signature element within it.

  Returns the element with the signature added. Default algorithm is RSA-SHA256.
  """
  @spec sign(record(:xmlElement), tuple(), binary()) :: record(:xmlElement)
  def sign(element_in, private_key, cert_bin) when is_binary(cert_bin) do
    sign(element_in, private_key, cert_bin, @rsa_sha256)
  end

  @doc """
  Signs the given XML element with the given signature method, by atom or by
  URI as a string or charlist.

  Raises an `ArgumentError` for an unknown signature method, or a private key
  of another type than the method names.
  """
  @spec sign(record(:xmlElement), tuple(), binary(), sig_method() | String.t() | charlist()) ::
          record(:xmlElement)
  def sign(element_in, private_key, cert_bin, sig_method) when is_binary(cert_bin) do
    {hash_function, digest_method, sig_method_url, key_algorithm} = method!(sig_method)

    unless key_algorithm.private_key?(private_key) do
      raise ArgumentError,
            "#{sig_method_url} needs a private key of #{inspect(key_algorithm)}, " <>
              "got #{key_kind(private_key)}"
    end

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

    # Compute digest of the canonical XML
    canon_xml = C14n.c14n(element)

    digest_value =
      :base64.encode_to_string(
        :crypto.hash(hash_function, :unicode.characters_to_binary(canon_xml, :unicode, :utf8))
      )

    ns = xmlNamespace(nodes: [{~c"ds", String.to_atom(@xmldsig_ns)}])

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
                  value: String.to_charlist(@exc_c14n)
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
                          value: String.to_charlist(@enveloped_signature)
                        )
                      ]
                    ),
                    xmlElement(
                      name: :"ds:Transform",
                      attributes: [
                        xmlAttribute(
                          name: :Algorithm,
                          value: String.to_charlist(@exc_c14n)
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

    signature = key_algorithm.sign(data, hash_function, private_key)
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
              value: String.to_charlist(@xmldsig_ns)
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

  @spec digest(record(:xmlElement), KeyAlgorithm.hash()) :: binary()
  def digest(element, hash_function) do
    ds_ns = @xpath_ns

    txs =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='#{@exc_c14n}']",
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
  @spec verify(record(:xmlElement)) :: :ok | {:error, verify_error()}
  def verify(element), do: verify(element, :any)

  @doc """
  Verifies an XML digital signature on the given element.

  `fingerprints` is a list of valid cert fingerprints that can be accepted,
  or `:any` to accept any valid certificate.
  """
  @spec verify(record(:xmlElement), [fingerprint()] | :any) :: :ok | {:error, verify_error()}
  def verify(element, fingerprints) do
    ds_ns = @xpath_ns

    case :xmerl_xpath.string(
           ~c"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm",
           element,
           namespace: ds_ns
         ) do
      [] ->
        {:error, :no_signature}

      [algo_attr] when Record.is_record(algo_attr, :xmlAttribute) ->
        algo = xmlAttribute(algo_attr, :value)

        case Map.fetch(@method_by_name, algo) do
          {:ok, {:sha, _, _, _}} ->
            require Logger

            Logger.error(
              "[ExSaml.Core] RSA-SHA1 signature rejected: algorithm is cryptographically broken. " <>
                "The IdP must be configured to use RSA-SHA256 or stronger."
            )

            {:error, :insecure_algorithm}

          {:ok, {hash_function, _, _, key_algorithm}} ->
            do_verify(element, fingerprints, {hash_function, key_algorithm}, ds_ns)

          :error ->
            require Logger
            Logger.error("[ExSaml.Core] Unsupported signature algorithm: #{algo}")
            {:error, :unsupported_algorithm}
        end

      _ ->
        {:error, :multiple_signatures}
    end
  end

  defp do_verify(element, fingerprints, method, ds_ns) do
    with {:ok, digest_function} <- extract_digest_function(element, ds_ns),
         incl_ns = extract_inclusive_ns(element, ds_ns),
         computed_digest = compute_digest(element, digest_function, incl_ns),
         expected_digest = extract_expected_digest(element, ds_ns),
         :ok <- verify_digest(computed_digest, expected_digest) do
      verify_signature(element, method, ds_ns, fingerprints)
    end
  end

  defp extract_digest_function(element, ds_ns) do
    case :xmerl_xpath.string(
           ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm",
           element,
           namespace: ds_ns
         ) do
      [algo_attr] when Record.is_record(algo_attr, :xmlAttribute) ->
        algo = algo_attr |> xmlAttribute(:value) |> to_string()

        case Map.fetch(@digest_by_uri, algo) do
          {:ok, :sha} ->
            require Logger

            Logger.error(
              "[ExSaml.Core] SHA1 digest rejected: algorithm is cryptographically broken. " <>
                "The IdP must be configured to use SHA256 or stronger."
            )

            {:error, :insecure_algorithm}

          {:ok, digest_function} ->
            {:ok, digest_function}

          :error ->
            require Logger
            Logger.error("[ExSaml.Core] Unsupported digest algorithm: #{algo}")
            {:error, :unsupported_algorithm}
        end

      _ ->
        {:error, :unsupported_algorithm}
    end
  end

  defp extract_inclusive_ns(element, ds_ns) do
    [c14n_tx] =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='#{@exc_c14n}']",
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

  defp verify_signature(element, {hash_function, key_algorithm}, ds_ns, fingerprints) do
    [sig_info] =
      :xmerl_xpath.string(~c"ds:Signature/ds:SignedInfo", element, namespace: ds_ns)

    data = sig_info |> C14n.c14n() |> String.to_charlist() |> :erlang.list_to_binary()

    [sig_text] =
      :xmerl_xpath.string(~c"ds:Signature//ds:SignatureValue/text()", element, namespace: ds_ns)

    sig = :base64.decode(xmlText(sig_text, :value))

    # The certificate's key must be of the type the signature method names,
    # and one the module supports.
    with {:ok, {spki, cert_bin}} <- extract_public_key_info(element, ds_ns),
         {^key_algorithm, parameters, key_bits} <- spki,
         {:ok, key} <- key_algorithm.public_key(parameters, key_bits),
         true <- key_algorithm.verify(data, hash_function, sig, key) do
      check_fingerprints(cert_bin, fingerprints)
    else
      {:error, :missing_certificate} = error -> error
      _ -> {:error, :bad_signature}
    end
  end

  # The SubjectPublicKeyInfo of the signing certificate, as the module of its
  # algorithm (nil for an unsupported one), the algorithm parameters and the
  # subjectPublicKey bits.
  defp extract_public_key_info(element, ds_ns) do
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

        {:AlgorithmIdentifier, algorithm, parameters} = subject_public_key_info(spki, :algorithm)
        key_algorithm = Enum.find(@key_algorithms, &(&1.spki_algorithm() == algorithm))
        {:ok, {{key_algorithm, parameters, key_bin}, cert_bin}}
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

  defp find_attr(name, element) do
    case :lists.keyfind(name, 2, xmlElement(element, :attributes)) do
      false -> :error
      attr -> {:ok, xmlAttribute(attr, :value)}
    end
  end

  # A signature method's row, by atom or URI, for signing.
  defp method!(method) do
    case Map.fetch(@method_by_name, method) do
      {:ok, row} -> row
      :error -> raise ArgumentError, "unsupported signature method #{inspect(method)}"
    end
  end

  # What a private key is, for an error message, without its material.
  defp key_kind(key) when is_tuple(key) and tuple_size(key) > 0 and is_atom(elem(key, 0)),
    do: inspect(elem(key, 0))

  defp key_kind(_key), do: "an unsupported private key"

  @doc false
  @spec signature_props(sig_method() | String.t() | charlist()) ::
          {hash :: atom(), digest_uri :: String.t(), method_uri :: String.t()}
          | :unsupported_algorithm
  def signature_props(method) do
    case Map.fetch(@method_by_name, method) do
      {:ok, {hash, digest_uri, method_uri, _key_algorithm}} -> {hash, digest_uri, method_uri}
      :error -> :unsupported_algorithm
    end
  end
end
