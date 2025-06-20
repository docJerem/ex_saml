defmodule ExSaml.RouterUtil do
  @moduledoc false

  alias Plug.Conn
  require Logger
  require ExSaml.Esaml
  alias ExSaml.{Esaml, IdpData, Helper}

  @subdomain_re ~r/^(?<subdomain>([^.]+))?\./

  def check_idp_id(conn, _opts) do
    idp_id_from = Application.get_env(:ex_saml, :idp_id_from)

    idp_id =
      if idp_id_from == :subdomain do
        case Regex.named_captures(@subdomain_re, conn.host) do
          %{"subdomain" => idp_id} -> idp_id
          _ -> nil
        end
      else
        with %{"idp_id_seg" => [idp_id]} <- conn.params do
          idp_id
        else
          %{"idp_id" => idp_id} ->
            idp_id

          _ ->
            nil
        end
      end

    idp = idp_id && Helper.get_idp(idp_id)

    if idp do
      conn |> Conn.put_private(:ex_saml_idp, idp)
    else
      conn |> Conn.send_resp(403, "invalid_request unknown IdP") |> Conn.halt()
    end
  end

  def check_target_url(conn, _opts) do
    try do
      target_url = conn.params["target_url"] && URI.decode_www_form(conn.params["target_url"])
      conn |> Conn.put_private(:ex_saml_target_url, target_url)
    rescue
      ArgumentError ->
        Logger.error(
          "[ExSaml] target_url must be x-www-form-urlencoded: #{inspect(conn.params["target_url"])}"
        )

        conn |> Conn.send_resp(400, "target_url must be x-www-form-urlencoded") |> Conn.halt()
    end
  end

  # generate URIs using the idp_id
  @spec ensure_sp_uris_set(tuple, Conn.t()) :: tuple
  def ensure_sp_uris_set(sp, conn) do
    case Esaml.esaml_sp(sp, :metadata_uri) do
      [?/ | _] ->
        uri = %URI{
          scheme: Atom.to_string(conn.scheme),
          host: conn.host,
          port: conn.port,
          path: "/sso"
        }

        base_url = URI.to_string(uri)
        idp_id_from = Application.get_env(:ex_saml, :idp_id_from)

        path_segment_idp_id =
          if idp_id_from == :subdomain do
            nil
          else
            %IdpData{id: idp_id} = conn.private[:ex_saml_idp]
            idp_id
          end

        Esaml.esaml_sp(
          sp,
          metadata_uri: Helper.get_metadata_uri(base_url, path_segment_idp_id),
          consume_uri: Helper.get_consume_uri(base_url, path_segment_idp_id),
          logout_uri: Helper.get_logout_uri(base_url, path_segment_idp_id)
        )

      _ ->
        sp
    end
  end

  @doc """
  Send a SAML Request.

  remove_saml_encoding flag is curently used only by Lemon LDAP SSOs, we think Lemon has a bug.
  The SAMLEncoding params in the query is returned as invalid by Lemon.
  As it's the default value that is used anyway we simply delete it when Lemon is the Provider.

  use_redirect? flag is used to define if the request should be HTTP Redirect or HTTP POST.
  Most of the time HTTP POST is used and prefered.

  ## Examples

      iex> send_saml_request(%Conn{}, "https://...", false, '<xml>...', "...", true)
      %Conn{}

  """
  # sobelow_skip ["XSS.SendResp"]
  def send_saml_request(
        conn,
        idp_url,
        use_redirect?,
        signed_xml_payload,
        relay_state,
        remove_saml_encoding? \\ false
      ) do
    if use_redirect? do
      standard_url =
        :esaml_binding.encode_http_redirect(idp_url, signed_xml_payload, :undefined, relay_state)

      # SAML Encoding query param is currentlty not accepted by LemonLDAP (bug? and perhaps other IDP(s) ?)
      maybe_url_without_saml_encoding =
        if remove_saml_encoding?, do: remove_saml_encoding(standard_url), else: standard_url

      redirect(conn, 302, maybe_url_without_saml_encoding)
    else
      nonce = conn.private[:ex_saml_nonce]
      resp_body = :esaml_binding.encode_http_post(idp_url, signed_xml_payload, relay_state, nonce)

      conn
      |> Conn.put_resp_header("content-type", "text/html")
      |> Conn.send_resp(200, resp_body)
    end
  end

  def redirect(conn, status_code, dest) do
    conn
    |> Conn.put_resp_header("location", dest)
    |> Conn.send_resp(status_code, "")
    |> Conn.halt()
  end

  defp remove_saml_encoding(url) do
    encoded_param = URI.encode_query(%{"SAMLEncoding" => IdpData.oasis_redirect_flow_uri()})

    String.replace(url, encoded_param <> "&", "")
  end
end
