defmodule ExSaml.SsoFlowTest do
  @moduledoc """
  In-process end-to-end test of the SP-initiated flow: AuthnRequest → ACS →
  authorization code → exchange, under one `trace_id`, with and without debug.
  This is the chain the debug mode promises to correlate; every other test
  exercises it piecewise.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias ExSaml.{
    Assertion,
    AuthHandler,
    AuthorizationCodeCache,
    Debug,
    Error,
    IdpData,
    RelayStateCache,
    SPHandler,
    StubCache
  }

  alias ExSaml.Core.{IdpMetadata, SpConfig}

  @idp_id "acme"
  @consume_uri "https://sp.example.com/sso/consume/acme"
  @metadata_uri "https://sp.example.com/sso/metadata/acme"
  @target_url "https://app.example.com/cb?x=1"
  @ns ~s(xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")

  setup do
    StubCache.install()
    previous_idps = Application.get_env(:ex_saml, :identity_providers)
    previous_store = Application.get_env(:ex_saml, :state_store)
    Application.put_env(:ex_saml, :identity_providers, %{@idp_id => idp()})
    ExSaml.State.init(ExSaml.State.Cache)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_trace_id: nil, ex_saml_saml_sub_status: nil)

    on_exit(fn ->
      if previous_idps,
        do: Application.put_env(:ex_saml, :identity_providers, previous_idps),
        else: Application.delete_env(:ex_saml, :identity_providers)

      if previous_store,
        do: Application.put_env(:ex_saml, :state_store, previous_store),
        else: Application.delete_env(:ex_saml, :state_store)
    end)

    :ok
  end

  defp idp do
    %IdpData{
      id: @idp_id,
      use_redirect_for_req: true,
      allow_idp_initiated_flow: false,
      idp_metadata: %IdpMetadata{
        entity_id: "https://idp.example.com",
        login_location: "https://idp.example.com/sso"
      },
      sp_config: %SpConfig{
        metadata_uri: @metadata_uri,
        consume_uri: @consume_uri,
        idp_signs_assertions: false,
        idp_signs_envelopes: false
      }
    }
  end

  defp session_conn(method, path, body, session) do
    opts =
      Plug.Session.init(
        store: :cookie,
        key: "_sso_flow_session",
        signing_salt: "salt",
        encryption_salt: "esalt"
      )

    method
    |> conn(path, body)
    |> Map.put(:secret_key_base, String.duplicate("a", 64))
    |> Plug.Session.call(opts)
    |> fetch_session()
    |> then(fn c -> Enum.reduce(session, c, fn {k, v}, acc -> put_session(acc, k, v) end) end)
  end

  defp acs_conn(body, session) do
    :post
    |> session_conn("/sso/consume/#{@idp_id}", body, session)
    |> Map.update!(:params, &Map.put(&1, "idp_id", @idp_id))
  end

  # An unsigned but otherwise valid Response for our SP: recipient, audience
  # and time conditions all pass, `InResponseTo` marks the SP-initiated flow.
  defp saml_response(in_response_to) do
    Base.encode64("""
    <samlp:Response #{@ns} ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
          <saml:NameID>jane@corp.com</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z"
              Recipient="#{@consume_uri}" InResponseTo="#{in_response_to}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
          <saml:AudienceRestriction>
            <saml:Audience>#{@metadata_uri}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"/>
        <saml:AttributeStatement>
          <saml:Attribute Name="email">
            <saml:AttributeValue>jane@corp.com</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
    """)
  end

  defp start_sso do
    conn =
      :get
      |> session_conn("/sso/auth/#{@idp_id}", %{}, %{})
      |> put_private(:ex_saml_target_url, @target_url)
      |> AuthHandler.request_idp(@idp_id)

    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, "https://idp.example.com/sso?")
    assert location =~ "SAMLRequest="

    relay_state = get_session(conn, "relay_state")
    assert is_binary(relay_state)
    assert get_session(conn, "idp_id") == @idp_id
    assert get_session(conn, "target_url") == @target_url
    assert RelayStateCache.get(relay_state)[:idp_id] == @idp_id
    assert location =~ URI.encode_query(%{"RelayState" => relay_state})

    {conn, relay_state}
  end

  defp post_response(relay_state) do
    body = %{"SAMLResponse" => saml_response("_req-1"), "RelayState" => relay_state}

    session = %{
      "relay_state" => relay_state,
      "idp_id" => @idp_id,
      "target_url" => @target_url
    }

    conn = SPHandler.consume_signin_response(acs_conn(body, session))
    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, "https://app.example.com/cb?x=1&code=")
    %URI{query: query} = URI.parse(location)
    %{"x" => "1", "code" => code} = URI.decode_query(query)
    {conn, code}
  end

  test "full SP-initiated flow with debug off: one trace_id end to end, nothing recorded" do
    {_conn, relay_state} = start_sso()
    {_conn, code} = post_response(relay_state)

    # The relay state is consumed, the code carries the trace_id even without debug.
    assert RelayStateCache.get(relay_state) == nil
    assert AuthorizationCodeCache.get(code)[:trace_id] == relay_state

    assert {:ok, {@idp_id, %{"email" => "jane@corp.com"}}} = Assertion.get_from_code(code)

    assert {:error, %Error{reason: :authorization_code_not_found, step: :code_exchange}} =
             Assertion.get_from_code(code)

    assert Debug.trace(relay_state) == nil
    assert Debug.capture(relay_state) == nil
    assert Debug.failures(@idp_id) == []
  end

  test "full SP-initiated flow with per-IdP debug: one trace, a provisional capture, redacted logs, a promoted capture on replay" do
    Debug.enable(idp_id: @idp_id)
    payload = saml_response("_req-1")

    log =
      capture_log(fn ->
        {_conn, relay_state} = start_sso()

        assert [{:authn_request, authn}] = Debug.trace(relay_state)

        assert %{binding: :http_redirect, nonce_source: :generated, target_url: @target_url} =
                 authn

        {_conn, code} = post_response(relay_state)

        # Success: the capture stays provisional and is not listed as a failure.
        assert %{captured_on: :pending, error: nil, saml_response: ^payload} =
                 Debug.capture(relay_state)

        assert Debug.failures(@idp_id) == []

        assert {:ok, {@idp_id, %{"email" => "jane@corp.com"}}} = Assertion.get_from_code(code)

        trace = Debug.trace(relay_state)

        assert Enum.map(trace, &elem(&1, 0)) == [
                 :authn_request,
                 :response_received,
                 :decode_result,
                 :validate_authresp_result,
                 :relay_state_deleted,
                 :code_stored,
                 :code_issued,
                 :code_taken,
                 :code_exchanged
               ]

        assert {:decode_result, %{result: :ok}} = List.keyfind(trace, :decode_result, 0)

        assert {:validate_authresp_result,
                %{result: {:ok, :sp_initiated, _nonce}, relay_state_source: :session}} =
                 List.keyfind(trace, :validate_authresp_result, 0)

        assert {:code_issued, %{code: ^code, target_url: @target_url, target_source: :session}} =
                 List.keyfind(trace, :code_issued, 0)

        assert {:code_exchanged, %{assertion_found: true}} =
                 List.keyfind(trace, :code_exchanged, 0)

        # Replayed callback: the code is gone, the capture is promoted and listed.
        assert {:error, %Error{reason: :authorization_code_not_found, trace_id: ^relay_state}} =
                 Assertion.get_from_code(code)

        assert %{captured_on: :authorization_code_not_found, saml_response: ^payload} =
                 Debug.failure(relay_state)

        assert [%{trace_id: ^relay_state}] = Debug.failures(@idp_id)
        assert [_, _] = for({:code_taken, m} <- Debug.trace(relay_state), do: m)

        Process.put(:sso_flow_code, code)
      end)

    code = Process.get(:sso_flow_code)

    # :steps mode: the payload, the code and the full NameID never reach the logs.
    assert log =~ "[ExSaml.Debug] code_issued"
    refute log =~ payload
    refute log =~ code
    refute log =~ "jane@corp.com"
    assert log =~ "j***@corp.com"
  end
end
