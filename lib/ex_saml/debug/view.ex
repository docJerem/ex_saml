defmodule ExSaml.Debug.View do
  @moduledoc false

  # Turns what `ExSaml.Debug` returns into the maps the API sends.
  #
  # Free of `Plug.Conn`, so the shapes can be tested without HTTP — which is
  # where the sharp edges are: scope-term keys, captures whose keys may be
  # absent rather than nil, and traces as `{event, meta}` tuples.

  alias ExSaml.Assertion
  alias ExSaml.Core.ValidationContext
  alias ExSaml.Debug
  alias ExSaml.Debug.JSON
  alias ExSaml.Error
  alias ExSaml.ErrorMessages

  @doc """
  `GET /debug` for a caller that may see everything.

  Takes `ExSaml.Debug.status/0` verbatim, including its rescue shape — a cache
  that is failing is exactly what an operator needs to see, so that answers 200
  with `degraded: true` rather than an error.
  """
  def debug_all(status) do
    settings = Map.get(status, :settings, %{})
    ttls = Map.get(status, :expires_in_ms, %{})

    %{
      "global" => %{
        "enabled" => Map.get(status, :global, false),
        "settings" => settings_json(Map.get(settings, :global)),
        "expires_in_ms" => Map.get(ttls, :global)
      },
      "static" => Map.get(status, :static, false),
      "idps" =>
        status
        |> Map.get(:idps, [])
        |> Enum.map(fn id ->
          # Note the tuple keys: `settings["acme"]` is always nil.
          idp_json(id, Map.get(settings, {:idp, id}), Map.get(ttls, {:idp, id}))
        end),
      "config" => config_json(),
      "cache" => cache_json(),
      "degraded" => Map.has_key?(status, :error)
    }
  end

  @doc """
  `GET /debug` for a caller restricted to a set of IdPs.

  Reports only their scopes, and reduces the global block to whether it is on:
  an operator needs to know global debug is running to explain traces they did
  not enable, but its settings and TTL are not theirs to see.
  """
  def debug_scoped(global_enabled?, scope_statuses) do
    %{
      "global" => %{"enabled" => global_enabled?},
      "static" => Enum.any?(scope_statuses, fn {_id, s} -> Map.get(s, :static, false) end),
      "idps" =>
        Enum.map(scope_statuses, fn {id, status} ->
          idp_json(id, status[:settings], status[:expires_in_ms], status[:enabled])
        end),
      "config" => config_json(),
      "cache" => cache_json(),
      "degraded" => false
    }
  end

  @doc "The body of a successful `PUT /debug` or `PUT /debug/idps/:idp_id`."
  def enabled(%{scope: scope, expires_at: expires_at, settings: settings}, ttl_ms) do
    {scope_name, idp_id} =
      case scope do
        {:idp, id} -> {"idp", id}
        :global -> {"global", nil}
      end

    %{
      "scope" => scope_name,
      "idp_id" => idp_id,
      "enabled" => true,
      "settings" => settings_json(settings),
      "expires_at" => DateTime.to_iso8601(expires_at),
      "expires_in_ms" => ttl_ms
    }
  end

  @doc "`GET /idps/:idp_id/failures`."
  def failures(idp_id, failures) do
    %{
      "idp_id" => idp_id,
      "count" => length(failures),
      "max_failures_per_idp" => Debug.config().max_failures_per_idp,
      "failures" => Enum.map(failures, &failure_summary/1)
    }
  end

  @doc """
  `GET /failures/:trace_id`.

  The payload is summarised, never inlined: it is the one thing here that is
  the end user's own data, and it has its own route so that handing it over is
  a deliberate request.
  """
  def failure(capture, locale, payload_href) do
    payload = capture[:saml_response]

    %{
      "trace_id" => capture[:trace_id],
      "idp_id" => capture[:idp_id],
      "received_at" => JSON.normalize(capture[:received_at]),
      "captured_on" => JSON.normalize(capture[:captured_on]),
      "error" => JSON.normalize(capture[:error]),
      "relay_state" => capture[:relay_state],
      "saml_encoding" => capture[:saml_encoding],
      "consume_uri" => capture[:consume_uri],
      "entity_id" => capture[:entity_id],
      "saml_response" => %{
        "present" => is_binary(payload),
        "bytes" => if(is_binary(payload), do: byte_size(payload)),
        "href" => if(is_binary(payload), do: payload_href)
      },
      "locale" => locale,
      "message" => message(capture[:error], locale)
    }
  end

  @doc "`GET /failures/:trace_id/saml_response` in its JSON form."
  def saml_response(capture, base64) do
    %{
      "trace_id" => capture[:trace_id],
      "idp_id" => capture[:idp_id],
      "saml_encoding" => capture[:saml_encoding],
      "bytes" => byte_size(base64),
      "base64" => base64
    }
  end

  @doc "`POST /failures/:trace_id/replay`, when the response now validates."
  def replay_ok(trace_id, evaluated_at, %Assertion{} = assertion) do
    %{
      "trace_id" => trace_id,
      "evaluated_at" => JSON.normalize(evaluated_at),
      "result" => "ok",
      "assertion" => assertion_summary(assertion)
    }
  end

  @doc """
  `POST /failures/:trace_id/replay`, when it still fails.

  A response that does not validate is the expected outcome of a replay, not an
  error of the call: the point of replaying is to find out.
  """
  def replay_error(trace_id, evaluated_at, %Error{} = error) do
    %{
      "trace_id" => trace_id,
      "evaluated_at" => JSON.normalize(evaluated_at),
      "result" => "error",
      "error" => %{
        "reason" => JSON.normalize(error.reason),
        "scope" => JSON.normalize(error.scope),
        "step" => JSON.normalize(error.step),
        "idp_id" => error.idp_id,
        "detail" => error.detail
      }
    }
  end

  @doc "`GET /traces/:trace_id`."
  def trace(trace_id, events, redacted?) do
    %{
      "trace_id" => trace_id,
      "redacted" => redacted?,
      "count" => length(events),
      "events" => Enum.map(events, &event/1)
    }
  end

  @doc "`GET /validation`."
  def validation do
    %{
      "enforced" => Enum.map(ValidationContext.enforced_checks(), &JSON.normalize/1),
      "available" => Enum.map(ValidationContext.all_checks(), &JSON.normalize/1),
      "mutable" => false
    }
  end

  @doc "The one error envelope."
  def error(code, message, extras \\ %{}) do
    %{"error" => Map.merge(%{"code" => to_string(code), "message" => message}, extras)}
  end

  # ---------------------------------------------------------------------------

  defp idp_json(id, settings, ttl, enabled? \\ true) do
    %{
      "idp_id" => id,
      "enabled" => enabled?,
      # `Debug.settings/1` falls back to the global flag, so this is what applies
      # to the IdP, not necessarily a flag of its own — hence the name.
      "effective_settings" => settings_json(settings),
      "expires_in_ms" => ttl
    }
  end

  defp settings_json(nil), do: nil

  defp settings_json(%{capture: capture, log: log}),
    do: %{"capture" => JSON.normalize(capture), "log" => JSON.normalize(log)}

  defp settings_json(other), do: JSON.normalize(other)

  defp failure_summary(failure) do
    %{
      "trace_id" => failure[:trace_id],
      "received_at" => JSON.normalize(failure[:received_at]),
      "captured_on" => JSON.normalize(failure[:captured_on]),
      "error" => JSON.normalize(failure[:error])
    }
  end

  # A capture holds an error summary map, not an `%ExSaml.Error{}`.
  defp message(%{reason: reason}, locale) when is_atom(reason),
    do: ErrorMessages.get(reason, locale)

  defp message(_error, _locale), do: nil

  defp event({name, meta}) do
    # `Debug.log/3` stamps these on every event; they describe the event rather
    # than the step. `:trace_id` is dropped, being the one in the URL.
    {lifted, data} = Map.split(meta, [:at, :node, :trace_id, :idp_id])

    %{
      "event" => JSON.normalize(name),
      "at" => JSON.normalize(Map.get(lifted, :at)),
      "node" => JSON.normalize(Map.get(lifted, :node)),
      "idp_id" => Map.get(lifted, :idp_id),
      "data" => JSON.normalize(data)
    }
  end

  # Summarised, never whole: masked subject, attribute names only.
  defp assertion_summary(%Assertion{} = assertion) do
    %{
      "issuer" => JSON.normalize(assertion.issuer),
      "recipient" => JSON.normalize(assertion.recipient),
      "subject" => masked_subject(assertion.subject),
      "attributes" => attribute_names(assertion.attributes)
    }
  end

  defp masked_subject(%{name: name}) when is_binary(name) or is_list(name) do
    %{name_id: JSON.normalize(name)} |> Debug.redact() |> Map.get(:name_id)
  end

  defp masked_subject(_subject), do: nil

  defp attribute_names(attributes) when is_list(attributes),
    do: Enum.map(attributes, fn {name, _value} -> to_string(name) end)

  defp attribute_names(attributes) when is_map(attributes),
    do: attributes |> Map.keys() |> Enum.map(&to_string/1)

  defp attribute_names(_attributes), do: []

  defp config_json do
    config = Debug.config()

    %{
      "trace_ttl_ms" => config.trace_ttl,
      "payload_ttl_ms" => config.payload_ttl,
      "provisional_ttl_ms" => config.provisional_ttl,
      "error_ttl_ms" => config.error_ttl,
      "max_failures_per_idp" => config.max_failures_per_idp,
      "debug_log_level" => JSON.normalize(config.debug_log_level),
      "enforced_response_checks" =>
        Enum.map(ValidationContext.enforced_checks(), &JSON.normalize/1)
    }
  end

  defp cache_json, do: %{"configured" => not is_nil(Debug.config().cache)}
end
