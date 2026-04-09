defmodule ExSaml.Core.Binding do
  @moduledoc """
  SAML HTTP binding handlers.

  Pure Elixir port of the Erlang `esaml_binding` module.
  Provides encoding/decoding of SAML messages for HTTP-Redirect and HTTP-POST bindings.
  """

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlDocument,
    Record.extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl")
  )

  @type uri :: binary() | String.t()
  @type html_doc :: binary()
  @type xml :: record(:xmlElement) | record(:xmlDocument)

  @deflate "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Unpack and parse a SAMLResponse with the given encoding.

  When the encoding is the DEFLATE URI, the response is base64-decoded then
  zlib-unzipped. For any other encoding the response is base64-decoded and an
  unzip is attempted, falling back to the raw decoded data if decompression
  fails. The resulting XML string is then parsed with `:xmerl_scan`.
  """
  @spec decode_response(binary(), binary()) :: xml()
  def decode_response(@deflate, saml_response) do
    xml_data =
      saml_response
      |> :base64.decode()
      |> :zlib.unzip()
      |> to_charlist()

    {xml, _} = :xmerl_scan.string(xml_data, namespace_conformant: true)
    xml
  end

  def decode_response(_encoding, saml_response) do
    data = :base64.decode(saml_response)

    xml_data =
      try do
        :zlib.unzip(data) |> to_charlist()
      rescue
        _e -> to_charlist(data)
      catch
        _kind, _reason -> to_charlist(data)
      end

    {xml, _} = :xmerl_scan.string(xml_data, namespace_conformant: true)
    xml
  end

  @doc """
  Encode a SAMLRequest (or SAMLResponse) as an HTTP-Redirect binding.

  Returns the full redirect URI including query parameters for `SAMLEncoding`,
  the payload (as `SAMLRequest` or `SAMLResponse` depending on the XML root
  element), `RelayState`, and an optional `username`.
  """
  @spec encode_http_redirect(
          idp_target :: uri(),
          signed_xml :: xml(),
          username :: nil | binary(),
          relay_state :: binary()
        ) :: binary()
  def encode_http_redirect(idp_target, signed_xml, username, relay_state) do
    type = xml_payload_type(signed_xml)

    req =
      [signed_xml]
      |> :xmerl.export(:xmerl_xml)
      |> List.flatten()

    encoded = :base64.encode_to_string(:zlib.zip(req))
    normalized_relay = :uri_string.normalize(to_charlist(relay_state))

    query_list = [
      {~c"SAMLEncoding", @deflate},
      {to_charlist(type), encoded},
      {~c"RelayState", normalized_relay}
    ]

    query_param_str = :uri_string.compose_query(query_list)

    first_delimiter =
      if is_binary(idp_target) do
        if String.contains?(idp_target, "?"), do: "&", else: "?"
      else
        if Enum.member?(to_charlist(idp_target), ??), do: "&", else: "?"
      end

    username_part = redirect_username_part(username)

    IO.iodata_to_binary([idp_target, first_delimiter, query_param_str | username_part])
  end

  @doc """
  Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding.

  Returns an HTML document containing a form and JavaScript to auto-submit it.
  """
  @spec encode_http_post(idp_target :: uri(), signed_xml :: xml(), relay_state :: binary()) ::
          html_doc()
  def encode_http_post(idp_target, signed_xml, relay_state) do
    encode_http_post(idp_target, signed_xml, relay_state, <<>>)
  end

  @doc """
  Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding with an
  optional nonce for the inline script tag.

  Returns an HTML document containing a form and JavaScript to auto-submit it.
  """
  @spec encode_http_post(
          idp_target :: uri(),
          signed_xml :: xml(),
          relay_state :: binary(),
          nonce :: binary()
        ) :: html_doc()
  def encode_http_post(idp_target, signed_xml, relay_state, nonce) when is_binary(nonce) do
    type = xml_payload_type(signed_xml)

    req =
      [signed_xml]
      |> :xmerl.export(:xmerl_xml)
      |> List.flatten()

    encoded = :base64.encode(req)

    generate_post_html(type, idp_target, encoded, relay_state, nonce)
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  @spec xml_payload_type(xml()) :: binary()
  defp xml_payload_type(rec) when Record.is_record(rec, :xmlDocument) do
    case xmlDocument(rec, :content) do
      [elem | _] when Record.is_record(elem, :xmlElement) ->
        if String.ends_with?(Atom.to_string(xmlElement(elem, :name)), "Response"),
          do: "SAMLResponse",
          else: "SAMLRequest"

      _ ->
        "SAMLRequest"
    end
  end

  defp xml_payload_type(rec) when Record.is_record(rec, :xmlElement) do
    if String.ends_with?(Atom.to_string(xmlElement(rec, :name)), "Response"),
      do: "SAMLResponse",
      else: "SAMLRequest"
  end

  defp xml_payload_type(_), do: "SAMLRequest"

  defp redirect_username_part(username) when is_binary(username) and byte_size(username) > 0 do
    normalized = :uri_string.normalize(to_charlist(username))
    ["&", :uri_string.compose_query([{~c"username", normalized}])]
  end

  defp redirect_username_part(_), do: []

  defp generate_post_html(type, dest, req, relay_state, nonce) do
    nonce_fragment =
      case nonce do
        <<>> -> <<>>
        _ -> IO.iodata_to_binary(["nonce=\"", nonce, "\""])
      end

    IO.iodata_to_binary([
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n",
      "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n",
      "<head>\n",
      "<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />\n",
      "<title>POST data</title>\n",
      "</head>\n",
      "<body>\n",
      "<script ",
      nonce_fragment,
      ">\n",
      "document.addEventListener('DOMContentLoaded', function () {\n",
      "document.getElementById('saml-req-form').submit();\n",
      "});\n",
      "</script>\n",
      "<noscript>\n",
      "<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>\n",
      "</noscript>\n",
      "<form id=\"saml-req-form\" method=\"post\" action=\"",
      dest,
      "\">\n",
      "<input type=\"hidden\" name=\"",
      type,
      "\" value=\"",
      req,
      "\" />\n",
      "<input type=\"hidden\" name=\"RelayState\" value=\"",
      relay_state,
      "\" />\n",
      "<noscript><input type=\"submit\" value=\"Submit\" /></noscript>\n",
      "</form>\n",
      "</body>\n",
      "</html>"
    ])
  end
end
