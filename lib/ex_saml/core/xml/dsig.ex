defmodule ExSaml.Core.Xml.Dsig do
  @moduledoc """
  XML Digital Signatures (XMLDSig) generation and verification.

  Implements enveloped XML digital signature generation and verification
  as specified at http://www.w3.org/TR/xmldsig-core/

  Currently supports RSA + SHA1|SHA256 signatures.
  """

  alias ExSaml.Core.Xml.C14n

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

  @type xml :: record(:xmlElement) | record(:xmlDocument)
  @type sig_method :: :rsa_sha1 | :rsa_sha256
  @type fingerprint :: binary() | {:sha | :sha256, binary()}

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
  Signs the given XML element by creating a ds:Signature element within it.

  Returns the element with the signature added. Default algorithm is RSA-SHA256.
  """
  @spec sign(record(:xmlElement), tuple(), binary()) :: record(:xmlElement)
  def sign(element_in, private_key, cert_bin) when is_binary(cert_bin) do
    sign(element_in, private_key, cert_bin, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
  end

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
              new_id = ExSaml.Core.Util.unique_id()

              attr =
                xmlAttribute(name: :ID, value: String.to_charlist(new_id), namespace: xmlNamespace())

              new_attrs = [attr | xmlElement(element_strip, :attributes)]
              {xmlElement(element_strip, attributes: new_attrs), String.to_charlist(new_id)}
          end
      end

    {hash_function, digest_method, sig_method_url} = signature_props(sig_method)

    # Compute digest of the canonical XML
    canon_xml = C14n.c14n(element)

    digest_value =
      :base64.encode_to_string(
        :crypto.hash(hash_function, :unicode.characters_to_binary(canon_xml, :unicode, :utf8))
      )

    ns = xmlNamespace(nodes: [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}])

    sig_info =
      ExSaml.Core.Util.build_nsinfo(
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
              attributes: [xmlAttribute(name: :Algorithm, value: String.to_charlist(sig_method_url))]
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
                          value:
                            ~c"http://www.w3.org/2000/09/xmldsig#enveloped-signature"
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
                  attributes: [xmlAttribute(name: :Algorithm, value: String.to_charlist(digest_method))]
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

    signature = :public_key.sign(data, hash_function, private_key)
    sig64 = :base64.encode_to_string(signature)
    cert64 = :base64.encode_to_string(cert_bin)

    sig_elem =
      ExSaml.Core.Util.build_nsinfo(
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
             | :no_signature
             | :multiple_signatures
             | :insecure_algorithm}
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
          {:sha, _, _} ->
            require Logger

            Logger.error(
              "[ExSaml.Core] RSA-SHA1 signature rejected: algorithm is cryptographically broken. " <>
                "The IdP must be configured to use RSA-SHA256 or stronger."
            )

            {:error, :insecure_algorithm}

          {hash_function, _, _} ->
            do_verify(element, fingerprints, hash_function, ds_ns)
        end

      _ ->
        {:error, :multiple_signatures}
    end
  end

  defp do_verify(element, fingerprints, hash_function, ds_ns) do
    incl_ns = extract_inclusive_ns(element, ds_ns)
    computed_digest = compute_digest(element, hash_function, incl_ns)
    expected_digest = extract_expected_digest(element, ds_ns)

    with :ok <- verify_digest(computed_digest, expected_digest) do
      verify_signature(element, hash_function, ds_ns, fingerprints)
    end
  end

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

  defp verify_signature(element, hash_function, ds_ns, fingerprints) do
    [sig_info] =
      :xmerl_xpath.string(~c"ds:Signature/ds:SignedInfo", element, namespace: ds_ns)

    data = sig_info |> C14n.c14n() |> String.to_charlist() |> :erlang.list_to_binary()

    [sig_text] =
      :xmerl_xpath.string(~c"ds:Signature//ds:SignatureValue/text()", element, namespace: ds_ns)

    sig = :base64.decode(xmlText(sig_text, :value))

    {key, cert_bin} = extract_public_key(element, ds_ns)

    case :public_key.verify(data, hash_function, sig, key) do
      true -> check_fingerprints(cert_bin, fingerprints)
      false -> {:error, :bad_signature}
    end
  end

  defp extract_public_key(element, ds_ns) do
    [cert_text] =
      :xmerl_xpath.string(~c"ds:Signature//ds:X509Certificate/text()", element, namespace: ds_ns)

    cert_bin = :base64.decode(xmlText(cert_text, :value))
    cert = :public_key.pkix_decode_cert(cert_bin, :plain)
    tbs = certificate(cert, :tbsCertificate)
    spki = tbs_certificate(tbs, :subjectPublicKeyInfo)

    key_bin =
      case subject_public_key_info(spki, :subjectPublicKey) do
        {_, kb} -> kb
        kb -> kb
      end

    key = :public_key.pem_entry_decode({:RSAPublicKey, key_bin, :not_encrypted})
    {key, cert_bin}
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

  @doc false
  def signature_props("http://www.w3.org/2000/09/xmldsig#rsa-sha1"), do: signature_props(:rsa_sha1)

  def signature_props(~c"http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
    do: signature_props(:rsa_sha1)

  def signature_props(:rsa_sha1) do
    {:sha, "http://www.w3.org/2000/09/xmldsig#sha1",
     "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}
  end

  def signature_props("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
    do: signature_props(:rsa_sha256)

  def signature_props(~c"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
    do: signature_props(:rsa_sha256)

  def signature_props(:rsa_sha256) do
    {:sha256, "http://www.w3.org/2001/04/xmlenc#sha256",
     "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
  end
end
