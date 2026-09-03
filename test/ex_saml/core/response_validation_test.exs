defmodule ExSaml.Core.ResponseValidationTest do
  @moduledoc """
  The checks required by SAML 2.0 Core / Profiles that #55 adds, driven through
  the public `Core.Saml.validate_assertion/2` and `Core.Sp.validate_assertion/2`.

  Fixtures are XML strings rather than xmerl records: negative cases stay
  readable, and nothing here needs a signature because the SpConfig used below
  has both `idp_signs_*` flags off.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.Core.{Saml, Sp, SpConfig, Util, ValidationContext}
  alias ExSaml.{Debug, StubCache}

  @idp_entity_id "https://idp.example.com/entity"
  @recipient "https://sp.example.com/consume"
  @audience "https://sp.example.com/sp"

  setup do
    StubCache.install()
    previous = Application.get_env(:ex_saml, :enforced_response_checks)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_trace_id: nil, ex_saml_saml_sub_status: nil)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ex_saml, :enforced_response_checks, previous),
        else: Application.delete_env(:ex_saml, :enforced_response_checks)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Fixtures
  # ---------------------------------------------------------------------------

  defp parse(xml),
    do:
      xml
      |> :binary.bin_to_list()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)
      |> elem(0)

  defp in_secs(offset) do
    :erlang.localtime()
    |> :erlang.localtime_to_universaltime()
    |> :calendar.datetime_to_gregorian_seconds()
    |> Kernel.+(offset)
    |> :calendar.gregorian_seconds_to_datetime()
    |> Util.datetime_to_saml()
  end

  defp assertion_xml(opts \\ []) do
    issuer = Keyword.get(opts, :issuer, @idp_entity_id)
    method = Keyword.get(opts, :method, "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    session = Keyword.get(opts, :session_not_on_or_after)

    session_attr = if session, do: ~s( SessionNotOnOrAfter="#{session}"), else: ""

    """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="#{in_secs(-10)}">
      <saml:Issuer>#{issuer}</saml:Issuer>
      <saml:Subject>
        <saml:NameID>user@example.com</saml:NameID>
        <saml:SubjectConfirmation Method="#{method}">
          <saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotOnOrAfter="#{in_secs(300)}">
        <saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="#{in_secs(-10)}"#{session_attr}/>
    </saml:Assertion>
    """
    |> parse()
  end

  defp ctx(overrides \\ []) do
    struct!(
      %ValidationContext{
        audience: @audience,
        destination: @recipient,
        idp_entity_id: @idp_entity_id,
        idp_id: "idp-1",
        recipient: @recipient
      },
      overrides
    )
  end

  # ---------------------------------------------------------------------------
  # :bad_issuer — Assertion/Issuer
  # ---------------------------------------------------------------------------

  describe ":bad_issuer on the assertion" do
    test "a matching issuer passes" do
      assert {:ok, _} = Saml.validate_assertion(assertion_xml(), ctx())
    end

    test "a different issuer is rejected" do
      assert {:error, :bad_issuer} =
               Saml.validate_assertion(assertion_xml(issuer: "https://evil.example.com"), ctx())
    end

    test "surrounding whitespace does not cause a false rejection" do
      assert {:ok, _} =
               Saml.validate_assertion(
                 assertion_xml(issuer: "  #{@idp_entity_id}  "),
                 ctx()
               )
    end

    test "an unset idp_entity_id skips the check silently" do
      log =
        capture_log(fn ->
          assert {:ok, _} =
                   Saml.validate_assertion(
                     assertion_xml(issuer: "https://anyone.example.com"),
                     ctx(idp_entity_id: nil)
                   )
        end)

      refute log =~ "saml_validation"
    end
  end

  # ---------------------------------------------------------------------------
  # :bad_subject_confirmation
  # ---------------------------------------------------------------------------

  describe ":bad_subject_confirmation" do
    test "bearer passes" do
      assert {:ok, _} = Saml.validate_assertion(assertion_xml(), ctx())
    end

    test "an explicitly non-bearer method is rejected" do
      xml = assertion_xml(method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
      assert {:error, :bad_subject_confirmation} = Saml.validate_assertion(xml, ctx())
    end

    # Documents a known limitation rather than asserting desired behaviour: the
    # decoder defaults a missing @Method to :bearer, so this check cannot see
    # the difference between "absent" and "bearer". Tracked separately.
    test "a missing method is treated as bearer" do
      xml =
        """
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="#{in_secs(-10)}">
          <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
          <saml:Subject>
            <saml:SubjectConfirmation>
              <saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
        </saml:Assertion>
        """
        |> parse()

      assert {:ok, _} = Saml.validate_assertion(xml, ctx())
    end
  end

  # ---------------------------------------------------------------------------
  # :session_expired
  # ---------------------------------------------------------------------------

  describe ":session_expired" do
    test "a future SessionNotOnOrAfter passes" do
      xml = assertion_xml(session_not_on_or_after: in_secs(600))
      assert {:ok, _} = Saml.validate_assertion(xml, ctx())
    end

    test "a past SessionNotOnOrAfter is rejected" do
      xml = assertion_xml(session_not_on_or_after: in_secs(-600))
      assert {:error, :session_expired} = Saml.validate_assertion(xml, ctx())
    end

    test "an absent SessionNotOnOrAfter passes silently" do
      log =
        capture_log(fn -> assert {:ok, _} = Saml.validate_assertion(assertion_xml(), ctx()) end)

      refute log =~ "saml_validation"
    end

    test "a value within the clock skew still passes" do
      xml = assertion_xml(session_not_on_or_after: in_secs(-2))
      assert {:ok, _} = Saml.validate_assertion(xml, ctx())
    end

    # The context's clock drives this check too: a replay evaluated as of the
    # instant of receipt does not see a session that expired since.
    test "is evaluated at ctx.now" do
      xml = assertion_xml(session_not_on_or_after: in_secs(-600))
      past = DateTime.add(DateTime.utc_now(), -1200, :second)
      assert {:ok, _} = Saml.validate_assertion(xml, ctx(now: past))
    end

    # Fails open whatever the policy says: an IdP formatting bug must not become
    # a rejected login the day this check ships.
    test "an unparsable value warns and passes, even when enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [:session_expired])
      xml = assertion_xml(session_not_on_or_after: "not-a-timestamp")

      log =
        capture_log(fn -> assert {:ok, _} = Saml.validate_assertion(xml, ctx(enforce: nil)) end)

      assert log =~ "check=:session_expired"
      assert log =~ "reason=:unparsable"
    end
  end

  # ---------------------------------------------------------------------------
  # Enforce / warn policy
  # ---------------------------------------------------------------------------

  describe "enforce policy" do
    test "a check absent from the enforced list warns and passes" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = assertion_xml(issuer: "https://evil.example.com")

      log =
        capture_log(fn -> assert {:ok, _} = Saml.validate_assertion(xml, ctx(enforce: nil)) end)

      assert log =~ "[ExSaml] saml_validation check=:bad_issuer enforced=false"
      assert log =~ ~s(idp_id="idp-1")
      assert log =~ ~s(actual="https://evil.example.com")
    end

    test "the default enforces the four safe checks and leaves the risky ones off" do
      Application.delete_env(:ex_saml, :enforced_response_checks)
      enforced = ValidationContext.enforced_checks()

      for check <- [:bad_issuer, :bad_in_response_to, :bad_subject_confirmation, :session_expired] do
        assert check in enforced
      end

      for check <- [:bad_destination, :duplicate] do
        refute check in enforced
      end
    end

    test ":all enforces every known check, and a garbage value falls back to the default" do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)
      assert ValidationContext.enforced_checks() == ValidationContext.all_checks()

      Application.put_env(:ex_saml, :enforced_response_checks, "nonsense")
      assert :bad_issuer in ValidationContext.enforced_checks()
      refute :bad_destination in ValidationContext.enforced_checks()
    end

    test "from_sp_config/2 maps the SP configuration and the clock onto the context" do
      sp = %SpConfig{
        consume_uri: ~c"https://sp.example.com/consume",
        entity_id: ~c"https://sp.example.com/sp",
        idp_entity_id: "https://idp.example.com/entity",
        idp_id: "idp-1"
      }

      built = ValidationContext.from_sp_config(sp, now: ~U[2026-01-01 00:00:00Z])

      assert built.recipient == ~c"https://sp.example.com/consume"
      assert built.destination == ~c"https://sp.example.com/consume"
      assert built.audience == ~c"https://sp.example.com/sp"
      assert built.idp_entity_id == "https://idp.example.com/entity"
      assert built.idp_id == "idp-1"
      assert built.now == ~U[2026-01-01 00:00:00Z]
      assert ValidationContext.from_sp_config(sp).now == nil
    end

    test "an SP with no entity_id falls back to its metadata URI as the audience" do
      sp = %SpConfig{metadata_uri: ~c"https://sp.example.com/metadata"}
      assert ValidationContext.from_sp_config(sp).audience == ~c"https://sp.example.com/metadata"
    end

    # Every verdict is recorded in the debug trace, enforced or not, so a check
    # observed in warn mode shows up next to whatever did reject the response.
    test "verdicts are recorded as :validation_check events in the trace" do
      Debug.enable(idp_id: "idp-1", log: :silent)
      Debug.put_context("idp-1", "t-1")
      Application.put_env(:ex_saml, :enforced_response_checks, [])

      assert {:ok, _} =
               Saml.validate_assertion(
                 assertion_xml(issuer: "https://evil.example.com"),
                 ctx(enforce: nil)
               )

      Application.put_env(:ex_saml, :enforced_response_checks, [:bad_issuer])

      assert {:error, :bad_issuer} =
               Saml.validate_assertion(
                 assertion_xml(issuer: "https://evil.example.com"),
                 ctx(enforce: nil)
               )

      assert [
               {:validation_check,
                %{check: :bad_issuer, enforced: false, actual: "https://evil.example.com"}},
               {:validation_check, %{check: :bad_issuer, enforced: true}}
             ] = Debug.trace("t-1")

      Debug.clear_context()
    end
  end

  # ---------------------------------------------------------------------------
  # Backward compatibility of the 3-arity entry point
  # ---------------------------------------------------------------------------

  test "validate_assertion/3 still works and skips the checks that need a context" do
    xml = assertion_xml(issuer: "https://someone-else.example.com")
    assert {:ok, _} = Saml.validate_assertion(xml, @recipient, @audience)
    assert {:error, :bad_recipient} = Saml.validate_assertion(xml, "https://wrong", @audience)
  end

  # ---------------------------------------------------------------------------
  # :bad_issuer — Response/Issuer, via Core.Sp
  # ---------------------------------------------------------------------------

  describe ":bad_issuer on the response envelope" do
    defp response_xml(issuer) do
      issuer_el = if issuer, do: "<saml:Issuer>#{issuer}</saml:Issuer>", else: ""

      """
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
        #{issuer_el}
        <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        <saml:Assertion Version="2.0" IssueInstant="#{in_secs(-10)}">
          <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
          <saml:Subject>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"/>
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions NotOnOrAfter="#{in_secs(300)}">
            <saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction>
          </saml:Conditions>
        </saml:Assertion>
      </samlp:Response>
      """
      |> parse()
    end

    defp unsigned_sp do
      %SpConfig{
        consume_uri: @recipient,
        entity_id: @audience,
        idp_entity_id: @idp_entity_id,
        idp_id: "idp-1",
        idp_signs_assertions: false,
        idp_signs_envelopes: false
      }
    end

    test "a matching response issuer passes" do
      assert {:ok, _} = Sp.validate_assertion(response_xml(@idp_entity_id), unsigned_sp())
    end

    test "a mismatching response issuer is rejected" do
      assert {:error, :bad_issuer} =
               Sp.validate_assertion(response_xml("https://evil.example.com"), unsigned_sp())
    end

    # Issuer is optional on a StatusResponseType (Core §3.2.2), so its absence
    # must not warn either — that noise would swamp the real signal.
    test "an absent response issuer passes silently" do
      log =
        capture_log(fn ->
          assert {:ok, _} = Sp.validate_assertion(response_xml(nil), unsigned_sp())
        end)

      refute log =~ "saml_validation"
    end
  end
end
