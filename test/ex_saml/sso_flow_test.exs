defmodule ExSaml.SsoFlowTest do
  @moduledoc """
  In-process end-to-end test of the SP-initiated flow, AuthnRequest → ACS, for
  the response checks that span both legs: `InResponseTo` against the
  AuthnRequest the SP sent, assertion replay through the configured cache, and
  `Response/@Destination`.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias ExSaml.{
    AuthHandler,
    AuthorizationCodeCache,
    IdpData,
    RelayStateCache,
    SPHandler,
    StubCache
  }

  alias ExSaml.Core.{IdpMetadata, SpConfig}

  @idp_id "acme"
  @idp_entity_id "https://idp.example.com"
  @consume_uri "https://sp.example.com/sso/consume/acme"
  @metadata_uri "https://sp.example.com/sso/metadata/acme"
  @target_url "https://app.example.com/cb"
  @ns ~s(xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")

  setup do
    StubCache.install()
    previous_idps = Application.get_env(:ex_saml, :identity_providers)
    previous_store = Application.get_env(:ex_saml, :state_store)
    previous_checks = Application.get_env(:ex_saml, :enforced_response_checks)
    Application.put_env(:ex_saml, :identity_providers, %{@idp_id => idp()})
    ExSaml.State.init(ExSaml.State.Cache)

    on_exit(fn ->
      restore(:identity_providers, previous_idps)
      restore(:state_store, previous_store)
      restore(:enforced_response_checks, previous_checks)
    end)

    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:ex_saml, key)
  defp restore(key, value), do: Application.put_env(:ex_saml, key, value)

  defp idp do
    %IdpData{
      id: @idp_id,
      use_redirect_for_req: true,
      allow_idp_initiated_flow: false,
      idp_metadata: %IdpMetadata{
        entity_id: @idp_entity_id,
        login_location: "https://idp.example.com/sso"
      },
      sp_config: %SpConfig{
        metadata_uri: @metadata_uri,
        consume_uri: @consume_uri,
        idp_signs_assertions: false,
        idp_signs_envelopes: false,
        idp_entity_id: @idp_entity_id,
        idp_id: @idp_id
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
  # Options: `:destination` adds `Response/@Destination`, `:issuer` replaces
  # the `Response/Issuer`, `:name_id` replaces the NameID (`nil` drops it),
  # `:attributes` adds attributes, as `{name, value}` pairs.
  defp saml_response(in_response_to, opts \\ []) do
    dest_attr =
      if dest = Keyword.get(opts, :destination), do: ~s( Destination="#{dest}"), else: ""

    issuer = Keyword.get(opts, :issuer, @idp_entity_id)

    name_id_el =
      if name_id = Keyword.get(opts, :name_id, "jane@corp.com"),
        do: "<saml:NameID>#{name_id}</saml:NameID>",
        else: ""

    attributes_el =
      for {name, value} <- Keyword.get(opts, :attributes, []),
          into: "",
          do:
            ~s(<saml:Attribute Name="#{name}"><saml:AttributeValue>#{value}</saml:AttributeValue></saml:Attribute>)

    Base.encode64("""
    <samlp:Response #{@ns} ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"#{dest_attr}>
      <saml:Issuer>#{issuer}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
        <saml:Subject>
          #{name_id_el}
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
          #{attributes_el}
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
    relay_state = get_session(conn, "relay_state")
    assert is_binary(relay_state)

    {conn, relay_state}
  end

  defp authn_request_id(relay_state), do: RelayStateCache.get(relay_state)[:authn_request_id]

  # The response answers the AuthnRequest we actually sent (InResponseTo check).
  defp response_payload(relay_state), do: saml_response(authn_request_id(relay_state))

  # Posts `payload` to the ACS with the session the browser holds for
  # `relay_state`, and returns the conn after the redirect.
  defp post_payload(relay_state, payload, authn_request_id) do
    body = %{"SAMLResponse" => payload, "RelayState" => relay_state}

    session = %{
      "relay_state" => relay_state,
      "idp_id" => @idp_id,
      "target_url" => @target_url,
      "authn_request_id" => authn_request_id
    }

    conn = SPHandler.consume_signin_response(acs_conn(body, session))
    assert conn.status == 302
    conn
  end

  defp location(conn) do
    [location] = get_resp_header(conn, "location")
    location
  end

  defp signed_in?(conn), do: location(conn) =~ "#{@target_url}?code="

  defp rejected_with(conn), do: get_session(conn, "ex_saml_error")

  describe "InResponseTo check end to end" do
    test "the AuthnRequest id is minted, stored and matched" do
      {conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      assert is_binary(id) and id != ""
      assert get_session(conn, "authn_request_id") == id

      assert relay_state |> post_payload(saml_response(id), id) |> signed_in?()
    end

    test "a response to a request we never sent is rejected (enforced by default)" do
      {_conn, relay_state} = start_sso()

      conn =
        post_payload(
          relay_state,
          saml_response("_not-our-request"),
          authn_request_id(relay_state)
        )

      refute signed_in?(conn)
      assert rejected_with(conn) == {:error, :bad_in_response_to}
    end

    test "with the check in warn mode the sign-in succeeds and the warning is logged" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)

      log =
        capture_log(fn ->
          assert relay_state
                 |> post_payload(saml_response("_not-our-request"), id)
                 |> signed_in?()
        end)

      assert log =~ "saml_validation check=:bad_in_response_to enforced=false"
      assert log =~ ~s(actual="_not-our-request")
    end
  end

  describe "replay, Destination and Issuer checks end to end" do
    test "a re-posted response is rejected as :duplicate (enforced by default)" do
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = response_payload(relay_state)

      assert relay_state |> post_payload(payload, id) |> signed_in?()

      conn = post_payload(relay_state, payload, id)
      refute signed_in?(conn)
      assert rejected_with(conn) == {:error, :duplicate}
    end

    test "with the check in warn mode a re-post signs in again and the warning is logged" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = response_payload(relay_state)

      assert relay_state |> post_payload(payload, id) |> signed_in?()

      log = capture_log(fn -> assert relay_state |> post_payload(payload, id) |> signed_in?() end)

      assert log =~ "saml_validation check=:duplicate enforced=false"
      assert log =~ ~s(assertion_id="_a1")
    end

    test "a Destination equal to the ACS URL signs in" do
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = saml_response(id, destination: @consume_uri)

      assert relay_state |> post_payload(payload, id) |> signed_in?()
    end

    test "a Destination other than the ACS URL is rejected (enforced by default)" do
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = saml_response(id, destination: "https://other.example.com/sso/consume/acme")

      conn = post_payload(relay_state, payload, id)
      refute signed_in?(conn)
      assert rejected_with(conn) == {:error, :bad_destination}
    end

    test "with the check in warn mode a wrong Destination signs in and is logged" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = saml_response(id, destination: "https://other.example.com/sso/consume/acme")

      log = capture_log(fn -> assert relay_state |> post_payload(payload, id) |> signed_in?() end)

      assert log =~ "saml_validation check=:bad_destination enforced=false"
      assert log =~ ~s(expected="#{@consume_uri}")
    end

    test "a Response/Issuer other than the IdP entityID is rejected" do
      {_conn, relay_state} = start_sso()
      id = authn_request_id(relay_state)
      payload = saml_response(id, issuer: "https://other-idp.example.com")

      conn = post_payload(relay_state, payload, id)
      refute signed_in?(conn)
      assert rejected_with(conn) == {:error, :bad_issuer}
    end
  end

  # IdP-initiated flow: the RelayState is the redirect target. Without
  # `allowed_target_urls`, only a relative path is followed.
  describe "IdP-initiated RelayState target" do
    defp use_idp(overrides) do
      idp = struct!(idp(), [allow_idp_initiated_flow: true] ++ overrides)
      Application.put_env(:ex_saml, :identity_providers, %{@idp_id => idp})
    end

    defp post_unsolicited(relay_state) do
      body = %{"SAMLResponse" => saml_response(""), "RelayState" => relay_state}
      conn = SPHandler.consume_signin_response(acs_conn(body, %{}))
      assert conn.status == 302
      conn
    end

    defp redirected_with_code_to(conn) do
      [target, query] = conn |> location() |> String.split("?code=", parts: 2)
      assert query != ""
      target
    end

    test "without a list, a relative path is kept" do
      use_idp(allowed_target_urls: nil)
      assert "/dashboard" |> post_unsolicited() |> redirected_with_code_to() == "/dashboard"
    end

    for relay_state <- [
          "https://elsewhere.example.com/landing",
          "//elsewhere.example.com/landing",
          "/\\elsewhere.example.com/landing",
          "/\telsewhere.example.com",
          "ftp://elsewhere.example.com/landing",
          "elsewhere.example.com"
        ] do
      test "without a list, #{inspect(relay_state)} falls back to the default target" do
        use_idp(allowed_target_urls: nil)

        log =
          capture_log(fn ->
            assert unquote(relay_state) |> post_unsolicited() |> redirected_with_code_to() == "/"
          end)

        assert log =~ "is not a relative path and allowed_target_urls is not set"
      end
    end

    test "without a list, an empty RelayState goes to the default target" do
      use_idp(allowed_target_urls: nil)
      assert "" |> post_unsolicited() |> redirected_with_code_to() == "/"
    end

    test "with a list, a listed absolute URL is kept" do
      use_idp(allowed_target_urls: ["https://app.example.com/dashboard"])

      assert "https://app.example.com/dashboard"
             |> post_unsolicited()
             |> redirected_with_code_to() == "https://app.example.com/dashboard"
    end

    test "with a list, a URL outside it is rejected" do
      use_idp(allowed_target_urls: ["https://app.example.com/dashboard"])
      conn = post_unsolicited("https://elsewhere.example.com/landing")

      refute location(conn) =~ "code="
      assert rejected_with(conn) == {:error, :invalid_target_url}
    end
  end

  # The RelayState is never followed before the SAMLResponse is validated: a
  # `https://start-from:` RelayState used to be redirected to as-is, before any
  # check of the response.
  describe "RelayState before validation" do
    test "an invalid response is not redirected to a start-from RelayState" do
      relay_state = "https://start-from:evil.example/phish"
      body = %{"SAMLResponse" => "not a response", "RelayState" => relay_state}

      conn = SPHandler.consume_signin_response(acs_conn(body, %{}))

      assert conn.status == 302
      assert location(conn) == "/"
      assert {:error, {:invalid_response, _}} = rejected_with(conn)
    end
  end

  # The assertion is keyed on the value of the IdP's `user_key_attribute` when
  # the assertion carries it, on the NameID otherwise.
  describe "user key" do
    defp sign_in_key(idp_overrides, response_opts) do
      idp =
        struct!(
          idp(),
          [allow_idp_initiated_flow: true, allowed_target_urls: nil] ++ idp_overrides
        )

      Application.put_env(:ex_saml, :identity_providers, %{@idp_id => idp})

      body = %{"SAMLResponse" => saml_response("", response_opts), "RelayState" => "/home"}
      conn = SPHandler.consume_signin_response(acs_conn(body, %{}))

      case conn |> location() |> String.split("?code=", parts: 2) do
        [_target, code] -> AuthorizationCodeCache.get(code)[:ex_saml_assertion_key]
        _ -> rejected_with(conn)
      end
    end

    test "is the idp_user_id attribute by default" do
      assert sign_in_key([], attributes: [{"idp_user_id", "u-42"}]) == {@idp_id, "u-42"}
    end

    test "is the attribute the IdP names" do
      assert sign_in_key([user_key_attribute: "uid"], attributes: [{"uid", "jdoe"}]) ==
               {@idp_id, "jdoe"}
    end

    test "is the NameID when the assertion does not carry the attribute" do
      assert sign_in_key([], []) == {@idp_id, "jane@corp.com"}
    end

    test "is the NameID when the IdP names no attribute" do
      assert sign_in_key([user_key_attribute: nil], attributes: [{"idp_user_id", "u-42"}]) ==
               {@idp_id, "jane@corp.com"}
    end

    test "is the attribute when the assertion has no NameID" do
      assert sign_in_key([], name_id: nil, attributes: [{"idp_user_id", "u-42"}]) ==
               {@idp_id, "u-42"}
    end

    test "is the NameID when the attribute is blank" do
      assert sign_in_key([], attributes: [{"idp_user_id", " "}]) == {@idp_id, "jane@corp.com"}
    end

    # An empty key would key every user of the IdP the same. One sign-in per
    # test: the replay check consumes the assertion ID.
    for {label, idp_overrides, response_opts} <- [
          {"no NameID", [], [name_id: nil]},
          {"a blank NameID", [], [name_id: "  "]},
          {"no NameID and no attribute named", [user_key_attribute: nil], [name_id: nil]},
          {"no NameID and the attribute not named", [user_key_attribute: nil],
           [name_id: nil, attributes: [{"idp_user_id", "u-42"}]]}
        ] do
      test "rejects the sign-in with :bad_name_id on #{label}" do
        assert sign_in_key(unquote(idp_overrides), unquote(response_opts)) ==
                 {:error, :bad_name_id}
      end
    end
  end
end
