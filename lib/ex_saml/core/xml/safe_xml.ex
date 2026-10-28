defmodule ExSaml.Core.Xml.SafeXml do
  @moduledoc """
  Single entry point for parsing untrusted SAML/XML payloads with `:xmerl_scan`.

  Every XML document `ex_saml` parses — SAML messages received from an IdP,
  decrypted assertions and IdP metadata — goes through `scan/1`, and every
  DEFLATE-compressed message through `inflate/1` or `inflate_if_deflated/1`,
  so that the hardening below is applied once, in one place. Callers do not
  pass scan options: they cannot weaken the defaults.

  ## What `scan/1` enforces

  Before the parser runs, a lexical pass over the raw document:

    * rejects documents larger than `:max_document_size` bytes;
    * rejects any DOCTYPE declaration (and any other `<!` declaration than a
      comment or a CDATA section). SAML messages and metadata never carry
      one;
    * rejects entity references other than the five predefined ones and
      character references;
    * rejects declared encodings other than UTF-8, US-ASCII and ISO-8859-1,
      and UTF-16 / UTF-32 byte order marks;
    * bounds atom creation: `:xmerl_scan` turns element names, attribute
      names, namespace prefixes and namespace URIs into atoms, which are never
      garbage collected. Names that are already atoms, or that belong to the
      SAML, XML-DSig, XML-Enc and metadata vocabularies `ex_saml` knows, are
      always accepted. Any other name draws from a node-wide budget of
      `:max_new_atoms`; a document whose new names do not fit in what remains
      of it is rejected.

  The parser then runs with `allow_entities: false`,
  `namespace_conformant: true`, `quiet: true`, and a `fetch_fun` that refuses
  every external resource. Its rules table is released whatever the outcome.
  Any exception, exit or throw from the parser becomes
  `{:error, :invalid_xml}`.

  ## Configuration

      config :ex_saml, :safe_xml,
        max_document_size: 1_048_576,
        max_new_atoms: 10_000,
        extra_prefixes: ["ns2"],
        extra_names: ["urn:example:vendor", "xmlns:vnd", "vnd:Extension", "Extension"],
        on_error: &MyApp.SIEM.report_xml_error/1

    * `:max_document_size` — maximum size, in bytes, of a document passed to
      `scan/1` and of the output of `inflate/1` and `inflate_if_deflated/1`.
      Default: `1_048_576` (1 MiB).
    * `:max_new_atoms` — number of names outside the known vocabulary that
      documents may introduce over the node's lifetime. A name counts once:
      after it has been parsed, it is an atom and free from then on. Default:
      `10_000`.
    * `:extra_prefixes` — namespace prefixes an IdP uses instead of the usual
      ones (for example `ns2` for `ns2:Assertion`). `<prefix>:<name>` is then
      known for every name of the built-in vocabulary, and so is
      `xmlns:<prefix>`. Default: `[]`.
    * `:extra_names` — further names to treat as known: qualified element or
      attribute names, their local names, `xmlns:<prefix>` declarations and
      namespace URIs, for example those of a vendor extension. Default: `[]`.
    * `:on_error` — see below.

  The configuration is read on every call.

  ## Error reporting hook

  An arity-1 function may be configured to receive parse-failure context.
  Typical use: forward to a SIEM / OCSF pipeline.

      config :ex_saml, :safe_xml,
        on_error: &MyApp.SIEM.report_xml_error/1

  The handler is invoked **after** the `{:error, :invalid_xml}` tuple is
  produced and receives a map:

      %{
        reason: :invalid_xml,
        kind: :error | :exit | :throw | :rejected,
        payload: Exception.t() | term()
      }

  `kind: :rejected` means the document was refused before reaching the
  parser; `payload` is then one of `:too_large`, `:doctype`,
  `:entity_reference`, `:unsupported_encoding`, `:invalid_name`,
  `:malformed`, `:atom_budget_exhausted` or `:invalid_deflate`.

  Any exception raised by the handler is silently caught — the handler must
  never be able to mask the original parse failure or alter the caller's
  control flow.
  """

  alias __MODULE__.{AtomBudget, Prescan}

  @scan_opts [namespace_conformant: true, allow_entities: false, quiet: true]
  @default_max_document_size 1_048_576

  @type xml :: term()

  @type rejection ::
          :too_large
          | :doctype
          | :entity_reference
          | :unsupported_encoding
          | :invalid_name
          | :malformed
          | :atom_budget_exhausted
          | :invalid_deflate

  @type error_context :: %{
          required(:reason) => :invalid_xml,
          required(:kind) => :error | :exit | :throw | :rejected,
          required(:payload) => Exception.t() | rejection() | term()
        }

  @doc """
  Parse `xml` with `:xmerl_scan` using the hardened option set.

  Accepts either a binary or a charlist. Returns the parsed root on success
  or `{:error, :invalid_xml}` when the document is rejected or fails to
  parse.

  Invokes the configured `:on_error` hook (if any) before returning the
  error tuple.
  """
  @spec scan(binary() | charlist()) :: {:ok, xml()} | {:error, :invalid_xml}
  def scan(xml) when is_binary(xml) do
    config = config()

    with :ok <- check_size(xml, config),
         {:ok, names} <- prescan(xml),
         :ok <- AtomBudget.admit(names, config) do
      parse(xml)
    else
      {:error, reason} -> reject(reason)
    end
  end

  def scan(xml) when is_list(xml) do
    case list_to_binary(xml) do
      {:ok, binary} -> scan(binary)
      :error -> reject(:malformed)
    end
  end

  @doc """
  Inflate a raw DEFLATE stream (RFC 1951), as carried by the SAML
  HTTP-Redirect binding, without producing more than `:max_document_size`
  bytes.

  Returns `{:error, :invalid_xml}` when the data is not a complete DEFLATE
  stream or inflates beyond the limit, after invoking the `:on_error` hook.
  """
  @spec inflate(binary()) :: {:ok, binary()} | {:error, :invalid_xml}
  def inflate(data) when is_binary(data) do
    case bounded_inflate(data, max_document_size(config())) do
      {:ok, inflated} -> {:ok, inflated}
      {:error, reason} -> reject(reason)
    end
  end

  @doc """
  Like `inflate/1`, but returns `data` unchanged when it is not a DEFLATE
  stream.

  Used on the HTTP-POST binding, whose messages are only base64-encoded
  (SAML Bindings §3.5), to keep accepting IdPs that compress them anyway. A
  payload that is a DEFLATE stream is still bounded: if it inflates beyond
  `:max_document_size` bytes, it is rejected with `{:error, :invalid_xml}`.
  """
  @spec inflate_if_deflated(binary()) :: {:ok, binary()} | {:error, :invalid_xml}
  def inflate_if_deflated(data) when is_binary(data) do
    case bounded_inflate(data, max_document_size(config())) do
      {:ok, inflated} -> {:ok, inflated}
      {:error, :invalid_deflate} -> {:ok, data}
      {:error, reason} -> reject(reason)
    end
  end

  # ---------------------------------------------------------------------------
  # Parsing
  # ---------------------------------------------------------------------------

  defp parse(xml) do
    # xmerl keeps DTD rules in an ETS table it only deletes on success; owning
    # it here releases it on every outcome.
    rules = :ets.new(:ex_saml_safe_xml_rules, [:set, :private])

    try do
      {root, _rest} = :xmerl_scan.string(:binary.bin_to_list(xml), scan_opts(rules))
      {:ok, root}
    rescue
      e ->
        notify(%{reason: :invalid_xml, kind: :error, payload: e})
        {:error, :invalid_xml}
    catch
      :exit, reason ->
        notify(%{reason: :invalid_xml, kind: :exit, payload: reason})
        {:error, :invalid_xml}

      :throw, value ->
        notify(%{reason: :invalid_xml, kind: :throw, payload: value})
        {:error, :invalid_xml}
    after
      :ets.delete(rules)
    end
  end

  defp scan_opts(rules) do
    [{:rules, rules}, {:fetch_fun, &refuse_fetch/2} | @scan_opts]
  end

  # External resources (DTDs, external entities) are never fetched. The
  # lexical pass already rejects every construct that could name one; this is
  # a second, independent barrier.
  defp refuse_fetch(_uri, _state), do: {:error, :external_resources_disabled}

  # The lexical pass returns errors as values; this only guards the
  # guarantee that `scan/1` never raises.
  defp prescan(xml) do
    Prescan.names(xml)
  rescue
    _ -> {:error, :malformed}
  end

  defp check_size(xml, config) do
    if byte_size(xml) > max_document_size(config), do: {:error, :too_large}, else: :ok
  end

  defp list_to_binary(list) do
    {:ok, :erlang.list_to_binary(list)}
  rescue
    ArgumentError ->
      case :unicode.characters_to_binary(list) do
        binary when is_binary(binary) -> {:ok, binary}
        _ -> :error
      end
  end

  # ---------------------------------------------------------------------------
  # Bounded inflate
  # ---------------------------------------------------------------------------

  defp bounded_inflate(data, max) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, -15)
      inflate_chunks(z, :zlib.safeInflate(z, data), max, 0, [])
    rescue
      _ -> {:error, :invalid_deflate}
    catch
      _, _ -> {:error, :invalid_deflate}
    after
      :zlib.close(z)
    end
  end

  defp inflate_chunks(z, {status, output}, max, size, acc)
       when status in [:continue, :finished] do
    size = size + IO.iodata_length(output)
    acc = [output | acc]

    cond do
      size > max ->
        {:error, :too_large}

      status == :finished ->
        # Raises when the stream ended before its final block.
        :ok = :zlib.inflateEnd(z)
        {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

      true ->
        inflate_chunks(z, :zlib.safeInflate(z, []), max, size, acc)
    end
  end

  defp inflate_chunks(_z, _other, _max, _size, _acc), do: {:error, :invalid_deflate}

  # ---------------------------------------------------------------------------
  # Configuration
  # ---------------------------------------------------------------------------

  defp config do
    case Application.get_env(:ex_saml, :safe_xml, []) do
      config when is_list(config) -> config
      _ -> []
    end
  end

  defp max_document_size(config) do
    case Keyword.get(config, :max_document_size, @default_max_document_size) do
      size when is_integer(size) and size > 0 -> size
      _ -> @default_max_document_size
    end
  end

  # ---------------------------------------------------------------------------
  # Error reporting hook
  # ---------------------------------------------------------------------------

  defp reject(reason) do
    notify(%{reason: :invalid_xml, kind: :rejected, payload: reason})
    {:error, :invalid_xml}
  end

  defp notify(context) do
    case Keyword.get(config(), :on_error) do
      fun when is_function(fun, 1) ->
        safe_invoke(fun, context)

      _ ->
        :ok
    end
  end

  defp safe_invoke(fun, context) do
    fun.(context)
    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end
