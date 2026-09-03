defmodule ExSaml.Debug.JSON do
  @moduledoc false

  # JSON for the debug API, with no mandatory dependency.
  #
  # The encoder is hand-rolled because neither candidate is available
  # everywhere: `:json` starts at OTP 27, `Jason` is optional, and they disagree
  # on `nil` (`:json` emits the string "nil"). Only the decoder is detected.

  alias ExSaml.Error

  @max_depth 32
  @inspect_limit 1024

  @type json ::
          nil | boolean() | number() | binary() | [json()] | %{optional(binary()) => json()}

  # ---------------------------------------------------------------------------
  # Normalising
  # ---------------------------------------------------------------------------

  @doc "Maps an arbitrary term onto the JSON data model."
  @spec normalize(term()) :: json()
  def normalize(term), do: norm(term, 0)

  defp norm(_term, depth) when depth > @max_depth, do: "…"

  defp norm(nil, _depth), do: nil
  defp norm(true, _depth), do: true
  defp norm(false, _depth), do: false
  defp norm(atom, _depth) when is_atom(atom), do: atom_to_string(atom)
  defp norm(number, _depth) when is_number(number), do: number

  defp norm(%DateTime{} = dt, _depth), do: DateTime.to_iso8601(dt)
  defp norm(%NaiveDateTime{} = dt, _depth), do: NaiveDateTime.to_iso8601(dt)
  defp norm(%Date{} = d, _depth), do: Date.to_iso8601(d)
  defp norm(%Time{} = t, _depth), do: Time.to_iso8601(t)

  # An error carries a whole trace; traces have their own route.
  defp norm(%Error{} = error, depth),
    do: error |> Map.from_struct() |> Map.delete(:trace) |> norm(depth)

  defp norm(%_{} = struct, _depth), do: %{"inspect" => inspected(struct)}

  defp norm(%{} = map, depth),
    do: Map.new(map, fn {k, v} -> {key(k), norm(v, depth + 1)} end)

  # `[]` is both the empty list and the empty charlist. It stays a list.
  defp norm([], _depth), do: []

  defp norm(list, depth) when is_list(list) do
    cond do
      keyword?(list) -> Map.new(list, fn {k, v} -> {key(k), norm(v, depth + 1)} end)
      List.ascii_printable?(list) -> List.to_string(list)
      true -> Enum.map(list, &norm(&1, depth + 1))
    end
  end

  defp norm(binary, _depth) when is_binary(binary) do
    if String.valid?(binary), do: binary, else: %{"base64" => Base.encode64(binary)}
  end

  # xmerl records are tuples, and large enough to bury the event holding them.
  defp norm(tuple, depth) when is_tuple(tuple) do
    if xmerl_record?(tuple),
      do: %{"inspect" => inspected(tuple)},
      else: tuple |> Tuple.to_list() |> Enum.map(&norm(&1, depth + 1))
  end

  defp norm(other, _depth), do: %{"inspect" => inspected(other)}

  defp xmerl_record?(tuple) when tuple_size(tuple) > 1 do
    case elem(tuple, 0) do
      atom when is_atom(atom) -> String.starts_with?(Atom.to_string(atom), "xml")
      _ -> false
    end
  end

  defp xmerl_record?(_tuple), do: false

  defp keyword?([{k, _} | rest]) when is_atom(k), do: keyword?(rest)
  defp keyword?([]), do: true
  defp keyword?(_), do: false

  defp key(k) when is_binary(k), do: k
  defp key(k) when is_atom(k), do: atom_to_string(k)
  defp key(k), do: inspect(k)

  defp atom_to_string(atom) do
    case Atom.to_string(atom) do
      "Elixir." <> rest -> rest
      other -> other
    end
  end

  defp inspected(term) do
    term
    |> inspect(limit: 20, printable_limit: 256)
    |> String.slice(0, @inspect_limit)
  end

  # ---------------------------------------------------------------------------
  # Encoding
  # ---------------------------------------------------------------------------

  @doc "Normalises and encodes a term. Never raises on a term `normalize/1` accepts."
  @spec encode_to_iodata!(term()) :: iodata()
  def encode_to_iodata!(term), do: term |> normalize() |> enc()

  defp enc(nil), do: "null"
  defp enc(true), do: "true"
  defp enc(false), do: "false"
  defp enc(int) when is_integer(int), do: Integer.to_string(int)
  defp enc(float) when is_float(float), do: Float.to_string(float)
  defp enc(bin) when is_binary(bin), do: [?", escape(bin), ?"]

  defp enc(list) when is_list(list),
    do: [?[, list |> Enum.map(&enc/1) |> Enum.intersperse(?,), ?]]

  defp enc(%{} = map),
    do: [?{, map |> Enum.map(&pair/1) |> Enum.intersperse(?,), ?}]

  defp pair({k, v}), do: [?", escape(k), ?", ?:, enc(v)]

  @escape_targets ["\"", "\\"] ++ for(c <- 0..0x1F, do: <<c>>)

  # A captured SAMLResponse is kilobytes of base64 with nothing escapable in it,
  # so one NIF pass beats walking every codepoint.
  defp escape(bin) do
    case :binary.match(bin, @escape_targets) do
      :nomatch -> bin
      _ -> escape_all(bin)
    end
  end

  defp escape_all(bin), do: for(<<c::utf8 <- bin>>, into: "", do: escape_char(c))

  defp escape_char(?"), do: "\\\""
  defp escape_char(?\\), do: "\\\\"
  defp escape_char(?\n), do: "\\n"
  defp escape_char(?\r), do: "\\r"
  defp escape_char(?\t), do: "\\t"
  defp escape_char(?\b), do: "\\b"
  defp escape_char(?\f), do: "\\f"

  defp escape_char(c) when c < 0x20,
    do: "\\u" <> (c |> Integer.to_string(16) |> String.pad_leading(4, "0"))

  defp escape_char(c), do: <<c::utf8>>

  # ---------------------------------------------------------------------------
  # Decoding
  # ---------------------------------------------------------------------------

  # `Code.ensure_loaded?/1` first: `function_exported?/3` is false for a module
  # that is on disk but not yet loaded.
  @decoder (cond do
              Code.ensure_loaded?(Jason) and function_exported?(Jason, :decode, 1) -> :jason
              Code.ensure_loaded?(:json) and function_exported?(:json, :decode, 1) -> :otp
              true -> :none
            end)

  @doc false
  def decoder, do: @decoder

  @doc """
  Decodes a JSON request body.

  Detection is sticky: a consumer that adds `:jason` after `ex_saml` was
  compiled does not trigger a recompile, so
  `config :ex_saml, debug_api: [json_decoder: {Mod, :fun}]` overrides it.
  """
  @spec decode(binary()) :: {:ok, term()} | {:error, :invalid_json | :no_json_decoder}
  def decode(body) when is_binary(body) do
    case Application.get_env(:ex_saml, :debug_api, [])[:json_decoder] do
      {mod, fun} -> apply(mod, fun, [body])
      _ -> default_decode(body)
    end
  end

  case @decoder do
    :jason ->
      defp default_decode(body) do
        case Jason.decode(body) do
          {:ok, term} -> {:ok, term}
          {:error, _} -> {:error, :invalid_json}
        end
      end

    :otp ->
      defp default_decode(body) do
        {:ok, body |> :json.decode() |> denull()}
      rescue
        _ -> {:error, :invalid_json}
      catch
        _, _ -> {:error, :invalid_json}
      end

      # OTP decodes JSON null to the atom `null`, which is not Elixir's nil.
      defp denull(:null), do: nil
      defp denull(list) when is_list(list), do: Enum.map(list, &denull/1)
      defp denull(%{} = map), do: Map.new(map, fn {k, v} -> {k, denull(v)} end)
      defp denull(other), do: other

    :none ->
      defp default_decode(_body), do: {:error, :no_json_decoder}
  end
end
