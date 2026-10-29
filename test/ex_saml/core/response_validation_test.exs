defmodule ExSaml.Core.ResponseValidationTest do
  @moduledoc """
  The response checks required by SAML 2.0 Core / Profiles, driven through the
  public `Core.Saml.validate_assertion/2` and `Core.Sp.validate_assertion/2,3`.

  Fixtures are XML strings rather than xmerl records: negative cases stay
  readable, and nothing here needs a signature because the SpConfig used below
  has both `idp_signs_*` flags off.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{AssertionReplayCache, Helper, StubCache}
  alias ExSaml.Core.{Saml, Sp, SpConfig, Util, ValidationContext}

  @idp_entity_id "https://idp.example.com/entity"
  @recipient "https://sp.example.com/consume"
  @audience "https://sp.example.com/sp"

  setup do
    StubCache.install()
    previous = Application.get_env(:ex_saml, :enforced_response_checks)

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

  @default_conditions "<saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction>"

  defp assertion_xml(opts \\ []) do
    issuer = Keyword.get(opts, :issuer, @idp_entity_id)
    method = Keyword.get(opts, :method, "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    session = Keyword.get(opts, :session_not_on_or_after)
    conditions = Keyword.get(opts, :conditions, @default_conditions)
    scd_not_before = Keyword.get(opts, :scd_not_before)

    session_attr = if session, do: ~s( SessionNotOnOrAfter="#{session}"), else: ""
    method_attr = if method, do: ~s( Method="#{method}"), else: ""
    scd_nb_attr = if scd_not_before, do: ~s( NotBefore="#{scd_not_before}"), else: ""

    """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{Keyword.get(opts, :id, "_a1")}" Version="2.0" IssueInstant="#{in_secs(-10)}">
      <saml:Issuer>#{issuer}</saml:Issuer>
      <saml:Subject>
        <saml:NameID>user@example.com</saml:NameID>
        <saml:SubjectConfirmation#{method_attr}>
          <saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"#{scd_nb_attr}/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotOnOrAfter="#{in_secs(300)}">#{conditions}</saml:Conditions>
      <saml:AuthnStatement AuthnInstant="#{in_secs(-10)}"#{session_attr}/>
    </saml:Assertion>
    """
    |> parse()
  end

  defp restriction(audiences) do
    "<saml:AudienceRestriction>" <>
      Enum.map_join(audiences, &"<saml:Audience>#{&1}</saml:Audience>") <>
      "</saml:AudienceRestriction>"
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
               Saml.validate_assertion(
                 assertion_xml(issuer: "https://other-idp.example.com"),
                 ctx()
               )
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

    # `Method` is required on SubjectConfirmation (Core §2.4.1.1): an absent
    # one is not bearer.
    test "a missing method decodes as :unknown and is rejected" do
      xml = assertion_xml(method: nil)

      assert {:ok, %{subject: %{confirmation_method: :unknown}}} = Saml.decode_assertion(xml)
      assert {:error, :bad_subject_confirmation} = Saml.validate_assertion(xml, ctx())
    end

    test "a missing method only warns when the check is not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])

      log =
        capture_log(fn ->
          assert {:ok, _} = Saml.validate_assertion(assertion_xml(method: nil), ctx(enforce: nil))
        end)

      assert log =~ "check=:bad_subject_confirmation enforced=false"
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

    # The context's clock drives this check too: an evaluation as of an earlier
    # instant does not see a session that expired since.
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
      xml = assertion_xml(issuer: "https://other-idp.example.com")

      log =
        capture_log(fn -> assert {:ok, _} = Saml.validate_assertion(xml, ctx(enforce: nil)) end)

      assert log =~ "[ExSaml] saml_validation check=:bad_issuer enforced=false"
      assert log =~ ~s(idp_id="idp-1")
      assert log =~ ~s(actual="https://other-idp.example.com")
    end

    test "the default enforces every check but :unsigned_cbc" do
      Application.delete_env(:ex_saml, :enforced_response_checks)
      enforced = ValidationContext.enforced_checks()
      refute :unsigned_cbc in enforced

      for check <- [
            :bad_audience,
            :bad_destination,
            :bad_in_response_to,
            :bad_issuer,
            :bad_subject_confirmation,
            :duplicate,
            :session_expired,
            :too_early
          ] do
        assert check in enforced
      end

      assert Enum.sort(enforced) == Enum.sort(ValidationContext.all_checks() -- [:unsigned_cbc])
    end

    test ":all enforces every known check, and a garbage value falls back to the default" do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)
      assert ValidationContext.enforced_checks() == ValidationContext.all_checks()

      Application.put_env(:ex_saml, :enforced_response_checks, "nonsense")
      assert :bad_issuer in ValidationContext.enforced_checks()
      assert :duplicate in ValidationContext.enforced_checks()
    end

    test "[] and an explicit list keep :duplicate enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      assert ValidationContext.enforced_checks() == [:duplicate]

      Application.put_env(:ex_saml, :enforced_response_checks, [:bad_issuer])
      assert Enum.sort(ValidationContext.enforced_checks()) == [:bad_issuer, :duplicate]

      Application.put_env(:ex_saml, :enforced_response_checks, [:duplicate, :bad_issuer])
      assert Enum.sort(ValidationContext.enforced_checks()) == [:bad_issuer, :duplicate]
    end

    test "always_enforce/2 enforces one check on top of a log-only policy" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      forced = ValidationContext.always_enforce(ctx(enforce: nil), :duplicate)
      assert forced.enforce == [:duplicate]
    end

    test "from_sp_config/1 maps the SP configuration onto the context" do
      sp = %SpConfig{
        consume_uri: ~c"https://sp.example.com/consume",
        entity_id: ~c"https://sp.example.com/sp",
        idp_entity_id: "https://idp.example.com/entity",
        idp_id: "idp-1"
      }

      built = ValidationContext.from_sp_config(sp)

      assert built.recipient == ~c"https://sp.example.com/consume"
      assert built.destination == ~c"https://sp.example.com/consume"
      assert built.audience == ~c"https://sp.example.com/sp"
      assert built.idp_entity_id == "https://idp.example.com/entity"
      assert built.idp_id == "idp-1"
      assert built.now == nil
    end

    test "an SP with no entity_id falls back to its metadata URI as the audience" do
      sp = %SpConfig{metadata_uri: ~c"https://sp.example.com/metadata"}
      assert ValidationContext.from_sp_config(sp).audience == ~c"https://sp.example.com/metadata"
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

  # Options: `:destination` (attribute value, absent by default), `:signed`
  # (adds an unverified `ds:Signature` child: `unsigned_sp/0` does not check
  # it, but its presence makes `Destination` mandatory), `:id` and
  # `:one_time_use` for the assertion.
  defp response_xml(issuer, opts \\ []) do
    issuer_el = if issuer, do: "<saml:Issuer>#{issuer}</saml:Issuer>", else: ""
    dest = Keyword.get(opts, :destination)
    dest_attr = if dest, do: ~s( Destination="#{dest}"), else: ""

    signature =
      if Keyword.get(opts, :signed),
        do: ~s(<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>),
        else: ""

    id_attr =
      case Keyword.get(opts, :id, "_a1") do
        nil -> ""
        id -> ~s( ID="#{id}")
      end

    one_time_use = if Keyword.get(opts, :one_time_use), do: "<saml:OneTimeUse/>", else: ""

    """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"#{dest_attr}>
      #{issuer_el}
      #{signature}
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion#{id_attr} Version="2.0" IssueInstant="#{in_secs(-10)}">
        <saml:Issuer>#{@idp_entity_id}</saml:Issuer>
        <saml:Subject>
          <saml:NameID>user@example.com</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotOnOrAfter="#{in_secs(300)}">
          <saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction>
          #{one_time_use}
        </saml:Conditions>
      </saml:Assertion>
    </samlp:Response>
    """
    |> parse()
  end

  defp unsigned_sp(overrides \\ []) do
    struct!(
      %SpConfig{
        consume_uri: @recipient,
        entity_id: @audience,
        idp_entity_id: @idp_entity_id,
        idp_id: "idp-1",
        idp_signs_assertions: false,
        idp_signs_envelopes: false
      },
      overrides
    )
  end

  describe ":bad_issuer on the response envelope" do
    test "a matching response issuer passes" do
      assert {:ok, _} = Sp.validate_assertion(response_xml(@idp_entity_id), unsigned_sp())
    end

    test "a mismatching response issuer is rejected" do
      assert {:error, :bad_issuer} =
               Sp.validate_assertion(response_xml("https://other-idp.example.com"), unsigned_sp())
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

  # ---------------------------------------------------------------------------
  # :bad_destination — Response/@Destination, via Core.Sp
  # ---------------------------------------------------------------------------

  describe ":bad_destination" do
    test "a Destination equal to the ACS URL passes" do
      xml = response_xml(@idp_entity_id, destination: @recipient, signed: true)
      assert {:ok, _} = Sp.validate_assertion(xml, unsigned_sp())
    end

    test "a different Destination is rejected" do
      xml = response_xml(@idp_entity_id, destination: "https://other.example.com/consume")
      assert {:error, :bad_destination} = Sp.validate_assertion(xml, unsigned_sp())
    end

    test "the comparison is verbatim, like Recipient" do
      xml = response_xml(@idp_entity_id, destination: @recipient <> "/")
      assert {:error, :bad_destination} = Sp.validate_assertion(xml, unsigned_sp())
    end

    test "a different Destination only warns when the check is not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = response_xml(@idp_entity_id, destination: "https://other.example.com/consume")

      log = capture_log(fn -> assert {:ok, _} = Sp.validate_assertion(xml, unsigned_sp()) end)

      assert log =~ "[ExSaml] saml_validation check=:bad_destination enforced=false"
      assert log =~ ~s(expected="#{@recipient}")
      assert log =~ ~s(actual="https://other.example.com/consume")
    end

    # Bindings §3.5.5.2: optional on an unsigned response.
    test "an absent Destination on an unsigned response passes silently" do
      log =
        capture_log(fn ->
          assert {:ok, _} = Sp.validate_assertion(response_xml(@idp_entity_id), unsigned_sp())
        end)

      refute log =~ "saml_validation"
    end

    # Bindings §3.5.5.2: required on a signed response.
    test "an absent Destination on a signed response is rejected" do
      xml = response_xml(@idp_entity_id, signed: true)
      assert {:error, :bad_destination} = Sp.validate_assertion(xml, unsigned_sp())
    end

    test "an absent Destination on a signed response only warns when not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = response_xml(@idp_entity_id, signed: true)

      log = capture_log(fn -> assert {:ok, _} = Sp.validate_assertion(xml, unsigned_sp()) end)

      assert log =~ "check=:bad_destination enforced=false"
      assert log =~ "reason=:missing"
    end

    test "an SP with no ACS URL skips the check" do
      xml = response_xml(@idp_entity_id, destination: "https://other.example.com/consume")
      sp = unsigned_sp(consume_uri: "")
      # The Recipient check still applies; only Destination is skipped.
      assert {:error, :bad_recipient} = Sp.validate_assertion(xml, sp)
    end
  end

  # ---------------------------------------------------------------------------
  # :bad_audience — every AudienceRestriction must name the SP
  # ---------------------------------------------------------------------------

  describe ":bad_audience" do
    test "the SP among several Audience values passes" do
      xml = assertion_xml(conditions: restriction(["https://a.example.com", @audience]))
      assert {:ok, _} = Saml.validate_assertion(xml, ctx())
    end

    test "several Audience values none of which is the SP are rejected" do
      xml =
        assertion_xml(conditions: restriction(["https://a.example.com", "https://b.example.com"]))

      assert {:error, :bad_audience} = Saml.validate_assertion(xml, ctx())
    end

    test "a mismatched Audience is rejected even when the policy is log-only" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = assertion_xml(conditions: restriction(["https://a.example.com"]))
      assert {:error, :bad_audience} = Saml.validate_assertion(xml, ctx(enforce: nil))
    end

    # Core §2.5.1.4: the SP must be in every AudienceRestriction.
    test "the SP missing from one of two AudienceRestriction elements is rejected" do
      xml =
        assertion_xml(
          conditions: restriction([@audience]) <> restriction(["https://a.example.com"])
        )

      assert {:error, :bad_audience} = Saml.validate_assertion(xml, ctx())
    end

    test "the SP named in every AudienceRestriction passes" do
      xml =
        assertion_xml(
          conditions:
            restriction([@audience]) <> restriction(["https://a.example.com", @audience])
        )

      assert {:ok, _} = Saml.validate_assertion(xml, ctx())
    end

    test "an Audience split by an XML comment is read whole" do
      [head, tail] = String.split(@audience, "example", parts: 2)
      split = head <> "<!-- c -->example" <> tail

      assert {:ok, assertion} =
               Saml.validate_assertion(assertion_xml(conditions: restriction([split])), ctx())

      assert assertion.audience_restrictions == [[@audience]]
      assert {:audience, @audience} in assertion.conditions

      other = "https://other.<!-- c -->example.com/sp"

      assert {:error, :bad_audience} =
               Saml.validate_assertion(assertion_xml(conditions: restriction([other])), ctx())
    end

    test "conditions[:audience] keeps the first Audience value" do
      xml = assertion_xml(conditions: restriction(["https://a.example.com", @audience]))
      assert {:ok, assertion} = Saml.validate_assertion(xml, ctx())
      assert {:audience, "https://a.example.com"} in assertion.conditions
    end

    # Profiles §4.1.4.2: a bearer assertion MUST carry an AudienceRestriction
    # naming the SP.
    test "an assertion with no Audience is rejected" do
      xml = assertion_xml(conditions: "")
      assert {:error, :bad_audience} = Saml.validate_assertion(xml, ctx())
    end

    test "an assertion with no Audience only warns when the check is not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])

      log =
        capture_log(fn ->
          assert {:ok, _} =
                   Saml.validate_assertion(assertion_xml(conditions: ""), ctx(enforce: nil))
        end)

      assert log =~ "check=:bad_audience enforced=false"
      assert log =~ "reason=:missing"
    end

    test "an unknown SP entity id does not report a missing Audience" do
      log =
        capture_log(fn ->
          assert {:ok, _} =
                   Saml.validate_assertion(assertion_xml(conditions: ""), ctx(audience: ""))
        end)

      refute log =~ "saml_validation"
    end
  end

  # ---------------------------------------------------------------------------
  # :too_early — SubjectConfirmationData/@NotBefore
  # ---------------------------------------------------------------------------

  describe ":too_early on SubjectConfirmationData" do
    test "a past NotBefore passes" do
      assert {:ok, _} =
               Saml.validate_assertion(assertion_xml(scd_not_before: in_secs(-60)), ctx())
    end

    test "a future NotBefore is rejected" do
      xml = assertion_xml(scd_not_before: in_secs(120))
      assert {:error, :too_early} = Saml.validate_assertion(xml, ctx())
    end

    test "the clock skew of Conditions/@NotBefore applies" do
      assert {:ok, _} = Saml.validate_assertion(assertion_xml(scd_not_before: in_secs(3)), ctx())
    end

    test "is evaluated at ctx.now" do
      xml = assertion_xml(scd_not_before: in_secs(120))
      later = DateTime.add(DateTime.utc_now(), 200, :second)
      assert {:ok, _} = Saml.validate_assertion(xml, ctx(now: later))
    end

    test "a future NotBefore only warns when the check is not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])

      log =
        capture_log(fn ->
          assert {:ok, _} =
                   Saml.validate_assertion(
                     assertion_xml(scd_not_before: in_secs(120)),
                     ctx(enforce: nil)
                   )
        end)

      assert log =~ "check=:too_early enforced=false"
      assert log =~ "element=:subject_confirmation_data"
    end

    test "an unparsable NotBefore warns and passes, even when enforced" do
      log =
        capture_log(fn ->
          assert {:ok, _} =
                   Saml.validate_assertion(assertion_xml(scd_not_before: "not-a-time"), ctx())
        end)

      assert log =~ "check=:too_early"
      assert log =~ "reason=:unparsable"
    end
  end

  # ---------------------------------------------------------------------------
  # :duplicate — assertion replay, via ExSaml.AssertionReplayCache
  # ---------------------------------------------------------------------------

  describe ":duplicate" do
    defp consume(xml, sp \\ unsigned_sp()),
      do: Sp.validate_assertion(xml, AssertionReplayCache.duplicate_fun(sp), sp)

    test "an assertion ID is accepted once, then rejected" do
      xml = response_xml(@idp_entity_id)
      assert {:ok, _} = consume(xml)
      assert {:error, :duplicate} = consume(xml)
    end

    test "different assertion IDs do not collide" do
      assert {:ok, _} = consume(response_xml(@idp_entity_id, id: "_a1"))
      assert {:ok, _} = consume(response_xml(@idp_entity_id, id: "_a2"))
    end

    test "a replay is rejected whatever the policy" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = response_xml(@idp_entity_id)
      assert {:ok, _} = consume(xml)
      assert {:error, :duplicate} = consume(xml)
    end

    # Core §2.5.1.5.
    test "OneTimeUse makes the check enforced whatever the policy" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      xml = response_xml(@idp_entity_id, one_time_use: true)

      assert {:ok, %{one_time_use: true}} = consume(xml)
      assert {:error, :duplicate} = consume(xml)
    end

    test "the ID is kept until the assertion would be stale, plus the skew" do
      xml = response_xml(@idp_entity_id)
      assert {:ok, assertion} = consume(xml)

      key = {AssertionReplayCache, AssertionReplayCache.key(assertion, "")}
      ttl = StubCache.ttl(key)

      # NotOnOrAfter is 300 s ahead; the skew is 5 s.
      assert ttl in (300_000 - 5_000)..((300 + 5) * 1000)
    end

    test "an assertion without an ID is keyed by the response digest" do
      xml = response_xml(@idp_entity_id, id: nil)
      assert {:ok, %{id: ""}} = consume(xml)
      assert {:error, :duplicate} = consume(xml)
    end

    test "the default duplicate function of Core.Sp is still a no-op" do
      xml = response_xml(@idp_entity_id)
      assert {:ok, _} = Sp.validate_assertion(xml, unsigned_sp())
      assert {:ok, _} = Sp.validate_assertion(xml, unsigned_sp())
    end

    test "the handler path records the ID and rejects a second use" do
      payload =
        response_xml(@idp_entity_id)
        |> List.wrap()
        |> :xmerl.export_simple(:xmerl_xml)
        |> :unicode.characters_to_binary()
        |> Base.encode64()

      assert {:ok, _} = Helper.decode_idp_auth_resp(unsigned_sp(), nil, payload)
      assert {:error, :duplicate} = Helper.decode_idp_auth_resp(unsigned_sp(), nil, payload)
    end
  end
end
