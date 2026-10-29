defmodule ExSaml.SPHandler do
  @moduledoc """
  Handles Service Provider SAML responses: metadata generation, assertion consumption,
  and logout handling.

  ## Functions

    * `send_metadata/1` - Returns SP metadata XML for the given IdP
    * `consume_signin_response/2` - Processes the IdP sign-in response and returns the assertion
    * `handle_logout_response/1` - Processes the IdP logout response
    * `handle_logout_request/1` - Processes an IdP-initiated logout request
  """

  require Logger
  import Plug.Conn

  alias ExSaml.{
    Assertion,
    AuthorizationCodeCache,
    Helper,
    IdpData,
    RelayStateCache,
    State,
    Subject
  }

  alias ExSaml.Core.ValidationContext

  import ExSaml.Helper, only: [get_idp: 1]
  import ExSaml.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, redirect: 3]

  @doc "Returns the SP metadata XML for the IdP in `conn.private[:ex_saml_idp]`."
  # metadata is generated from SP config by Helper.sp_metadata/1, not from user input.
  # sobelow_skip ["XSS.SendResp"]
  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:ex_saml_idp]
    %IdpData{sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # NOTE: We should avoid this, as you can not decorate the
    # behaviour.
    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")

    # PROPOSAL:
    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     {:error, saml: :request_metadata_failed}
  end

  @doc """
  Processes the IdP sign-in response and extracts the SAML assertion.

  On success returns
  `{:ok, %{flow: flow, assertion: assertion, nonce: nonce, user_token: token, redirect_uri: uri}}`
  where:

    * `flow` is `:idp_initiated` or `:sp_initiated` and reflects which SAML flow
      produced the response (deduced from the assertion's `SubjectConfirmationData`
      `InResponseTo` — empty means IdP-initiated).
    * `nonce` is the AuthnRequest-bound SAML nonce for SP-initiated flows, and
      `nil` for IdP-initiated flows (no AuthnRequest exists in that case, so no
      nonce is generated; downstream consumers must accept `nil` for the
      IdP-initiated case).

  On failure returns `{:error, reason}`. Possible reasons include
  `:idp_initiated_not_allowed`, `:invalid_target_url`, `:invalid_relay_state`,
  `:invalid_idp_id`, `:bad_in_response_to`, and `:access_denied`, as well as
  the response validation reasons (`:bad_issuer`, `:bad_destination`,
  `:bad_audience`, `:bad_subject_confirmation`, `:session_expired`,
  `:too_early`, `:duplicate`, …). The router clause also returns
  `:bad_name_id` when neither the `user_key_attribute` nor the NameID gives
  the signed-in user a key.
  """
  # Router-facing clause: matches when the SP router dispatched here with
  # `idp_id` in path params. Performs the full SAML flow AND handles the
  # connection: persists the assertion, generates an authorization code,
  # and redirects to the target URL. Always returns a `%Plug.Conn{}`.
  def consume_signin_response(%{params: %{"idp_id" => idp_id}} = conn)
      when is_bitstring(idp_id) do
    idp_data = get_idp(idp_id)
    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with {:ok, %{assertion: assertion, nonce: nonce}} <-
           consume_signin_response(conn, idp_data),
         {:ok, user_key} <- user_key(assertion, idp_data) do
      assertion_key = {idp_data.id, user_key}
      conn = State.put_assertion(conn, assertion_key, assertion)
      target_url = auth_target_url(conn, idp_data, assertion, relay_state)

      RelayStateCache.delete(relay_state)

      redirect_with_authorization_code(conn, target_url, assertion_key, nonce)
    else
      {:error, error} ->
        redirect_with_error(conn, relay_state, error)

      # Defensive fallback: unreachable today (Dialyzer flags it as such), but
      # kept so that any future change introducing a new return shape from the
      # `with` chain fails closed with a 403 instead of crashing the request
      # with a `WithClauseError`. Auth endpoints should fail closed.
      _ ->
        conn |> send_resp(403, "access_denied")
    end
  end

  # Library-facing clause: pure decode+validate. Returns the assertion data
  # as a tuple — caller is responsible for any conn handling. Useful when
  # an app wants to drive the post-consume flow itself.
  def consume_signin_response(conn, %IdpData{id: idp_id, sp_config: sp_cfg} = idp_data) do
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]

    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)
    user_token = RelayStateCache.get(relay_state)[:user_token]
    redirect_uri = RelayStateCache.get(relay_state)[:redirect_uri]

    with {:ok, assertion} <- Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
         {:ok, flow, nonce} <- validate_authresp(conn, idp_data, assertion, relay_state) do
      {:ok,
       %{
         flow: flow,
         assertion: %Assertion{assertion | idp_id: idp_id},
         nonce: nonce,
         user_token: user_token,
         redirect_uri: redirect_uri
       }}
    else
      {:error, error} -> {:error, error}
    end
  end

  # The user part of the assertion key: the `user_key_attribute` value, else the
  # NameID. The NameID is optional (Core §2.4.1), but an empty key would key
  # every user of the IdP the same, so such a sign-in is rejected.
  defp user_key(assertion, idp_data) do
    case present(user_key_attribute(assertion, idp_data)) || present(assertion.subject.name) do
      nil -> {:error, :bad_name_id}
      key -> {:ok, key}
    end
  end

  defp present(value) when is_binary(value), do: if(String.trim(value) != "", do: value)
  defp present([_ | _] = values), do: values
  defp present(_), do: nil

  # The value of the IdP's `user_key_attribute`, which keys the assertion
  # instead of the NameID when the assertion carries it.
  defp user_key_attribute(_assertion, %IdpData{user_key_attribute: nil}), do: nil

  defp user_key_attribute(%{attributes: attributes}, %IdpData{user_key_attribute: attr}),
    do: Map.get(attributes, attr)

  defp redirect_with_authorization_code(conn, target_url, assertion_key, nonce) do
    code = State.gen_id()

    AuthorizationCodeCache.put_new!(code, %{
      ex_saml_assertion_key: assertion_key,
      saml_nonce_candidate: nonce
    })

    redirect(conn, 302, "#{target_url}?code=#{code}")
  end

  defp redirect_with_error(conn, _, :invalid_target_url) do
    conn
    |> put_session("ex_saml_error", {:error, :invalid_target_url})
    |> redirect(302, target_url())
  end

  defp redirect_with_error(conn, relay_state, error) do
    conn
    |> put_session("ex_saml_error", {:error, error})
    |> redirect(302, target_url(conn, relay_state))
  end

  # IdP-initiated flow: the RelayState is the target. `validate_authresp/4`
  # has already checked it against `allowed_target_urls` when the list is set;
  # without a list, only a relative path is followed, anything else falls back
  # to the default target.
  defp auth_target_url(conn, idp_data, assertion, relay_state) do
    if unsolicited?(assertion) do
      idp_initiated_target_url(idp_data, relay_state)
    else
      get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url] || "/"
    end
  end

  defp idp_initiated_target_url(_idp_data, ""), do: "/"

  defp idp_initiated_target_url(%IdpData{id: idp_id, allowed_target_urls: nil}, url) do
    if relative_path?(url) do
      url
    else
      Logger.warning(
        "[ExSaml] IdP-initiated RelayState #{inspect(url)} for #{inspect(idp_id)} is not a " <>
          "relative path and allowed_target_urls is not set: redirecting to \"/\""
      )

      "/"
    end
  end

  defp idp_initiated_target_url(_idp_data, url), do: url

  # An unsolicited response (Profiles §4.1.5) answers no AuthnRequest: neither
  # the `Response` nor the `SubjectConfirmationData` carries an `InResponseTo`
  # (Core §3.2.2 forbids the attribute on a response to no request).
  defp unsolicited?(assertion), do: in_response_to_values(assertion) == []

  # The `InResponseTo` values of the response, `Response/@InResponseTo` and
  # `SubjectConfirmationData/@InResponseTo`, without the absent ones.
  defp in_response_to_values(%{subject: %{in_response_to: subject_value}} = assertion) do
    [subject_value, Map.get(assertion, :response_in_response_to, "")]
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
  end

  # A path on this host: a single leading `/`, no scheme or authority, and
  # nothing a browser could read as one (backslashes, control characters).
  defp relative_path?(url) do
    String.starts_with?(url, "/") and not String.starts_with?(url, "//") and
      not String.contains?(url, "\\") and not String.match?(url, ~r/[\x00-\x1F\x7F]/) and
      match?(%URI{scheme: nil, host: nil}, URI.parse(url))
  end

  @doc false
  def validate_authresp(conn, idp_data, assertion, relay_state) do
    if unsolicited?(assertion) do
      validate_idp_initiated(idp_data, relay_state)
    else
      validate_sp_initiated(conn, idp_data, assertion, relay_state)
    end
  end

  # IdP-initiated flow auth response. Tagged as `:idp_initiated` with a `nil`
  # nonce since there is no AuthnRequest to bind a nonce to in this flow.
  defp validate_idp_initiated(idp_data, relay_state) do
    cond do
      !idp_data.allow_idp_initiated_flow ->
        {:error, :idp_initiated_not_allowed}

      idp_data.allowed_target_urls && relay_state not in idp_data.allowed_target_urls ->
        {:error, :invalid_target_url}

      true ->
        {:ok, :idp_initiated, nil}
    end
  end

  # SP-initiated flow auth response.
  defp validate_sp_initiated(conn, %IdpData{id: idp_id}, assertion, relay_state) do
    cached = RelayStateCache.get(relay_state)
    rs_in_session = session_or_cached(conn, cached, :relay_state)
    idp_id_in_session = session_or_cached(conn, cached, :idp_id)
    saml_nonce_in_session = session_or_cached(conn, cached, :saml_nonce)
    authn_request_id = session_or_cached(conn, cached, :authn_request_id)

    cond do
      rs_in_session == nil || rs_in_session != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      not in_response_to_ok?(authn_request_id, assertion, idp_id) ->
        {:error, :bad_in_response_to}

      true ->
        {:ok, :sp_initiated, saml_nonce_in_session}
    end
  end

  # The session value when set, else the one stored with the relay state.
  defp session_or_cached(conn, cached, key),
    do: get_session(conn, Atom.to_string(key)) || cached[key]

  # Profiles §4.1.4.3: every `InResponseTo` the response carries, on the
  # `Response` and on the `SubjectConfirmationData`, must name the AuthnRequest
  # we sent. A stored `nil` means the relay-state entry predates
  # AuthnRequest-id tracking — a rolling deploy, or a consumer driving
  # `validate_authresp/4` without going through `ExSaml.AuthHandler` — so it
  # skips rather than rejects. The enforce / warn policy applies like for the
  # other checks.
  defp in_response_to_ok?(nil, _assertion, _idp_id), do: true

  defp in_response_to_ok?(expected, assertion, idp_id) do
    expected = to_string(expected)

    Enum.all?(in_response_to_values(assertion), fn actual ->
      actual == expected or
        ValidationContext.verdict(
          %ValidationContext{idp_id: idp_id},
          {:error, :bad_in_response_to},
          expected: expected,
          actual: actual
        ) == :ok
    end)
  end

  @doc "Processes the IdP logout response and redirects to the target URL."
  # Error details are logged server-side only; the response body is a static string, not user input.
  # sobelow_skip ["XSS.SendResp"]
  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    # Handle both POST and Redirect
    saml_response = conn.body_params["SAMLResponse"] || Map.get(conn.params, "SAMLResponse")
    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      conn
      |> configure_session(drop: true)
      |> redirect(302, target_url)
    else
      error ->
        Logger.error("[ExSaml] Logout response validation failed: #{inspect(error)}")
        conn |> send_resp(403, "invalid_request")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  @doc "Handles an IdP-initiated logout request."
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{idp_metadata: idp_meta, sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    rls = conn.body_params["RelayState"]
    relay_state = safe_decode_www_form(rls)

    case Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      {:ok, %ExSaml.Core.LogoutRequest{name: nameid}} ->
        assertion_key = {idp_id, nameid}

        {conn, return_status} =
          case State.get_assertion(conn, assertion_key) do
            %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
              conn = State.delete_assertion(conn, assertion_key)
              {conn, :success}

            _ ->
              {conn, :denied}
          end

        {idp_signout_url, resp_xml_frag} =
          Helper.gen_idp_signout_resp(sp, idp_meta, return_status)

        conn
        |> configure_session(drop: true)
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )

      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_meta, :denied)

        conn
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  @doc """
  Returns the target URL from session or relay state cache, falling back
  to `target_url/0` (`Application.get_env(:ex_saml, :fallback_target_url, "/")`)
  when neither is set. Never returns `nil` — callers can safely pass the
  result to `Plug.Conn.put_resp_header/3`.
  """
  def target_url(conn, relay_state) do
    get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url] ||
      target_url()
  end

  @doc "Returns the fallback target URL from application config (defaults to `\"/\"`)."
  def target_url, do: Application.get_env(:ex_saml, :fallback_target_url, "/")

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
