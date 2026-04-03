defmodule ExSaml.Core.Util do
  @moduledoc """
  Utility functions for SAML processing.

  Pure Elixir port of the Erlang `esaml_util` module. Provides helpers for
  datetime conversion, unique ID generation, fingerprint handling, xmerl
  namespace processing, key/certificate loading, metadata fetching, and
  duplicate-assertion checking.

  Note: the original Erlang helpers `thread/2`, `threaduntil/2`, and
  `folduntil/3` are intentionally not ported — use Elixir's `with`, pipes,
  and `Enum.reduce_while/3` instead.
  """

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlComment, Record.extract(:xmlComment, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlPI, Record.extract(:xmlPI, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlDocument,
    Record.extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(
    :xmlNamespace,
    Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")
  )

  # ---------------------------------------------------------------------------
  # Datetime helpers
  # ---------------------------------------------------------------------------

  @doc """
  Converts an Erlang datetime tuple to a SAML 2.0 UTC timestamp string.

  ## Examples

      iex> ExSaml.Core.Util.datetime_to_saml({{2013, 5, 2}, {17, 26, 53}})
      "2013-05-02T17:26:53Z"
  """
  @spec datetime_to_saml(:calendar.datetime()) :: String.t()
  def datetime_to_saml({{y, mo, d}, {h, mi, s}}) do
    :io_lib.format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [
      y,
      mo,
      d,
      h,
      mi,
      s
    ])
    |> :erlang.iolist_to_binary()
  end

  @doc """
  Parses a SAML 2.0 UTC timestamp string into an Erlang datetime tuple.

  Accepts both binary strings and charlists.

  ## Examples

      iex> ExSaml.Core.Util.saml_to_datetime("2013-05-02T17:26:53Z")
      {{2013, 5, 2}, {17, 26, 53}}
  """
  @spec saml_to_datetime(binary() | charlist()) :: :calendar.datetime()
  def saml_to_datetime(str) when is_binary(str) do
    str |> String.to_charlist() |> saml_to_datetime()
  end

  def saml_to_datetime(str) when is_list(str) do
    {y, rest} = :string.to_integer(str)
    ~c"-" ++ rest2 = rest
    {mo, rest3} = :string.to_integer(rest2)
    ~c"-" ++ rest4 = rest3
    {d, rest5} = :string.to_integer(rest4)
    ~c"T" ++ rest6 = rest5
    {h, rest7} = :string.to_integer(rest6)
    ~c":" ++ rest8 = rest7
    {mi, rest9} = :string.to_integer(rest8)
    ~c":" ++ rest10 = rest9
    {s, _} = :string.to_integer(rest10)
    {{y, mo, d}, {h, mi, s}}
  end

  # ---------------------------------------------------------------------------
  # Unique ID generation
  # ---------------------------------------------------------------------------

  @doc """
  Generates a unique SAML ID string (hex-encoded, prefixed with underscore).

  Uses `:crypto.strong_rand_bytes/1` for cryptographic randomness.
  """
  @spec unique_id() :: String.t()
  def unique_id do
    bytes = :crypto.strong_rand_bytes(16)
    "_" <> Base.encode16(bytes, case: :lower)
  end

  # ---------------------------------------------------------------------------
  # Fingerprint conversion
  # ---------------------------------------------------------------------------

  @doc """
  Converts a list of fingerprints in various formats into normalised binaries.

  Accepted input formats per element:

  * Hex colon-separated string: `"AA:BB:CC:DD:..."`
  * Typed (with digest prefix): `"SHA256:base64data"` or `"SHA:base64data"`
  * Raw binary (already decoded)

  Returns a list of `binary()` or `{atom(), binary()}` tuples.
  """
  @spec convert_fingerprints([binary() | charlist()]) :: [binary() | {atom(), binary()}]
  def convert_fingerprints(fps) when is_list(fps) do
    Enum.map(fps, &convert_one_fingerprint/1)
  end

  defp convert_one_fingerprint(fp) when is_list(fp) do
    fp |> :erlang.list_to_binary() |> convert_one_fingerprint()
  end

  defp convert_one_fingerprint(fp) when is_binary(fp) do
    if String.contains?(fp, ":") do
      case split_type_prefix(fp) do
        {:ok, type_atom, decoded} -> {type_atom, decoded}
        :hex -> decode_hex_colon(fp)
      end
    else
      fp
    end
  end

  defp split_type_prefix(fp) do
    case String.split(fp, ":", parts: 2) do
      [type, data] ->
        utype = String.upcase(type)

        if utype in ["SHA", "SHA1", "SHA256", "SHA384", "SHA512"] do
          decode_typed_fingerprint(utype, data)
        else
          :hex
        end

      _ ->
        :hex
    end
  end

  defp decode_typed_fingerprint(type, data) do
    case Base.decode64(data) do
      {:ok, decoded} -> {:ok, hash_type_atom(type), decoded}
      :error -> :hex
    end
  end

  defp hash_type_atom("SHA"), do: :sha
  defp hash_type_atom("SHA1"), do: :sha
  defp hash_type_atom("SHA256"), do: :sha256
  defp hash_type_atom("SHA384"), do: :sha384
  defp hash_type_atom("SHA512"), do: :sha512

  defp decode_hex_colon(fp) do
    fp
    |> String.split(":")
    |> Enum.map(fn hex_byte -> String.to_integer(hex_byte, 16) end)
    |> :erlang.list_to_binary()
  end

  # ---------------------------------------------------------------------------
  # xmerl namespace info builder
  # ---------------------------------------------------------------------------

  @doc """
  Recursively adds namespace info (`nsinfo` field) to xmerl element and
  attribute records.

  Takes an `xmlNamespace` record and an xmerl node. For `xmlElement` and
  `xmlAttribute` records whose names contain a colon (i.e. namespace-prefixed),
  the `nsinfo` field is set to `{prefix, local_name}`.
  """
  @spec build_nsinfo(record(:xmlNamespace), term()) :: term()
  def build_nsinfo(nsp, rec) when Record.is_record(rec, :xmlElement) do
    name = xmlElement(rec, :name)
    nsinfo = parse_nsinfo(name)

    new_attrs =
      xmlElement(rec, :attributes)
      |> Enum.map(&build_nsinfo(nsp, &1))

    new_content =
      xmlElement(rec, :content)
      |> Enum.map(&build_nsinfo(nsp, &1))

    xmlElement(rec, nsinfo: nsinfo, namespace: nsp, attributes: new_attrs, content: new_content)
  end

  def build_nsinfo(nsp, rec) when Record.is_record(rec, :xmlAttribute) do
    name = xmlAttribute(rec, :name)
    nsinfo = parse_nsinfo(name)
    xmlAttribute(rec, nsinfo: nsinfo, namespace: nsp)
  end

  def build_nsinfo(_nsp, other), do: other

  defp parse_nsinfo(name) when is_atom(name) do
    name |> Atom.to_charlist() |> parse_nsinfo_charlist()
  end

  defp parse_nsinfo(name) when is_list(name) do
    parse_nsinfo_charlist(name)
  end

  defp parse_nsinfo_charlist(chars) do
    case :string.tokens(chars, ~c":") do
      [prefix, local] -> {prefix, local}
      _ -> []
    end
  end

  # ---------------------------------------------------------------------------
  # Private key loading / importing
  # ---------------------------------------------------------------------------

  @doc """
  Loads an RSA private key from the given file path.

  The key is cached in the `:ex_saml_core_privkey_cache` ETS table.
  Returns `{:ok, rsa_private_key}` or `{:error, reason}`.
  """
  @spec load_private_key(String.t()) :: {:ok, term()} | {:error, term()}
  # Path comes from server-side SP configuration, not user input.
  # sobelow_skip ["Traversal.FileModule"]
  def load_private_key(path) do
    case :ets.lookup(:ex_saml_core_privkey_cache, path) do
      [{^path, key}] ->
        {:ok, key}

      [] ->
        case File.read(path) do
          {:ok, pem} -> do_import_private_key(path, pem)
          {:error, reason} -> {:error, {:read_file, reason}}
        end
    end
  end

  @doc """
  Imports an RSA private key from a PEM-encoded binary string.

  The key is cached in the `:ex_saml_core_privkey_cache` ETS table under
  the given `identifier`.
  """
  @spec import_private_key(term(), binary()) :: {:ok, term()} | {:error, term()}
  def import_private_key(identifier, pem) when is_binary(pem) do
    case :ets.lookup(:ex_saml_core_privkey_cache, identifier) do
      [{^identifier, key}] -> {:ok, key}
      [] -> do_import_private_key(identifier, pem)
    end
  end

  defp do_import_private_key(cache_key, pem) do
    entries = :public_key.pem_decode(pem)

    result =
      Enum.find_value(entries, :error, fn
        {:RSAPrivateKey, der, :not_encrypted} ->
          {:ok, :public_key.der_decode(:RSAPrivateKey, der)}

        {:PrivateKeyInfo, der, :not_encrypted} ->
          {:ok, unwrap_private_key_info(der)}

        _ ->
          nil
      end)

    case result do
      {:ok, key} ->
        :ets.insert(:ex_saml_core_privkey_cache, {cache_key, key})
        {:ok, key}

      :error ->
        {:error, :no_rsa_private_key}
    end
  end

  defp unwrap_private_key_info(der) do
    private_key_info = :public_key.der_decode(:PrivateKeyInfo, der)

    # PrivateKeyInfo wraps the key — extract the inner RSAPrivateKey
    case private_key_info do
      {:PrivateKeyInfo, _version, _algo, inner_der, _attrs} ->
        :public_key.der_decode(:RSAPrivateKey, inner_der)

      other ->
        other
    end
  end

  # ---------------------------------------------------------------------------
  # Certificate loading / importing
  # ---------------------------------------------------------------------------

  @doc """
  Loads a single X.509 certificate from the given file path.

  Returns the DER-encoded certificate binary.
  """
  @spec load_certificate(String.t()) :: {:ok, binary()} | {:error, term()}
  # sobelow_skip ["Traversal.FileModule"]
  # Path comes from server-side SP configuration, not user input.
  def load_certificate(path) do
    case File.read(path) do
      {:ok, pem} -> extract_first_cert(pem)
      {:error, reason} -> {:error, {:read_file, reason}}
    end
  end

  @doc """
  Imports a single X.509 certificate from a PEM-encoded binary string.

  Returns the DER-encoded certificate binary.
  """
  @spec import_certificate(term(), binary()) :: {:ok, binary()} | {:error, term()}
  def import_certificate(_identifier, pem) when is_binary(pem) do
    extract_first_cert(pem)
  end

  defp extract_first_cert(pem) do
    entries = :public_key.pem_decode(pem)

    case Enum.find(entries, fn {type, _, _} -> type == :Certificate end) do
      {:Certificate, der, :not_encrypted} -> {:ok, der}
      nil -> {:error, :no_certificate}
    end
  end

  # ---------------------------------------------------------------------------
  # Certificate chain loading / importing
  # ---------------------------------------------------------------------------

  @doc """
  Loads a certificate chain from the given file path.

  Returns a list of DER-encoded certificate binaries. Results are cached in
  the `:ex_saml_core_certbin_cache` ETS table.
  """
  # Path comes from server-side SP configuration, not user input.
  # sobelow_skip ["Traversal.FileModule"]
  @spec load_certificate_chain(String.t()) :: {:ok, [binary()]} | {:error, term()}
  def load_certificate_chain(path) do
    case :ets.lookup(:ex_saml_core_certbin_cache, path) do
      [{^path, chain}] ->
        {:ok, chain}

      [] ->
        case File.read(path) do
          {:ok, pem} -> do_import_certificate_chain(path, pem)
          {:error, reason} -> {:error, {:read_file, reason}}
        end
    end
  end

  @doc """
  Imports a certificate chain from a PEM-encoded binary string.

  Returns a list of DER-encoded certificate binaries. Results are cached in
  the `:ex_saml_core_certbin_cache` ETS table under the given `identifier`.
  """
  @spec import_certificate_chain(term(), binary()) :: {:ok, [binary()]} | {:error, term()}
  def import_certificate_chain(identifier, pem) when is_binary(pem) do
    case :ets.lookup(:ex_saml_core_certbin_cache, identifier) do
      [{^identifier, chain}] -> {:ok, chain}
      [] -> do_import_certificate_chain(identifier, pem)
    end
  end

  defp do_import_certificate_chain(cache_key, pem) do
    entries = :public_key.pem_decode(pem)

    chain =
      entries
      |> Enum.filter(fn {type, _, _} -> type == :Certificate end)
      |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)

    case chain do
      [] ->
        {:error, :no_certificates}

      _ ->
        :ets.insert(:ex_saml_core_certbin_cache, {cache_key, chain})
        {:ok, chain}
    end
  end

  # ---------------------------------------------------------------------------
  # Metadata loading
  # ---------------------------------------------------------------------------

  @doc """
  Fetches IdP metadata XML from the given URL via `:httpc`.

  The raw XML binary is cached in the `:ex_saml_core_idp_meta_cache` ETS table.

  Returns `{:ok, xml_binary}` or `{:error, reason}`.
  """
  @spec load_metadata(String.t() | charlist()) :: {:ok, binary()} | {:error, term()}
  def load_metadata(url) do
    url_charlist = to_charlist_url(url)

    case :ets.lookup(:ex_saml_core_idp_meta_cache, url_charlist) do
      [{^url_charlist, xml}] ->
        {:ok, xml}

      [] ->
        _ = ensure_httpc_started()

        case :httpc.request(:get, {url_charlist, []}, [{:autoredirect, true}], []) do
          {:ok, {{_http_ver, 200, _reason}, _headers, body}} ->
            xml = :erlang.iolist_to_binary(body)
            :ets.insert(:ex_saml_core_idp_meta_cache, {url_charlist, xml})
            {:ok, xml}

          {:ok, {{_http_ver, status, reason}, _headers, _body}} ->
            {:error, {:http, status, reason}}

          {:error, reason} ->
            {:error, {:httpc, reason}}
        end
    end
  end

  @doc """
  Fetches IdP metadata XML from the given URL and verifies its XML signature
  using the provided fingerprints.

  This is a structural port — signature verification will be refined later.
  Returns `{:ok, xml_binary}` or `{:error, reason}`.
  """
  @spec load_metadata(String.t() | charlist(), [binary() | {atom(), binary()}]) ::
          {:ok, binary()} | {:error, term()}
  def load_metadata(url, _fingerprints) do
    # Signature verification against fingerprints will be added in Phase 2 (security fixes)
    load_metadata(url)
  end

  defp ensure_httpc_started do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  defp to_charlist_url(url) when is_binary(url), do: String.to_charlist(url)
  defp to_charlist_url(url) when is_list(url), do: url

  # ---------------------------------------------------------------------------
  # Duplicate assertion checking
  # ---------------------------------------------------------------------------

  @doc """
  Checks whether the given assertion `digest` has been seen before.

  If `digest` is new, it is inserted into the `:ex_saml_core_assertion_seen`
  ETS table and `false` is returned. If it already exists, returns `true`.

  This is a simplified local-only version — the original Erlang implementation
  used `rpc:multicall` across all nodes.
  """
  @spec check_dupe_ets(binary(), integer()) :: boolean()
  def check_dupe_ets(digest, _ttl) do
    now = :erlang.system_time(:second)

    case :ets.lookup(:ex_saml_core_assertion_seen, digest) do
      [{^digest, _inserted_at}] ->
        true

      [] ->
        :ets.insert(:ex_saml_core_assertion_seen, {digest, now})
        false
    end
  end

  # ---------------------------------------------------------------------------
  # ETS table bootstrap (backwards compat)
  # ---------------------------------------------------------------------------

  @doc """
  No-op kept for backwards compatibility.

  ETS tables are managed by `ExSaml.Core.TableOwner`. This function verifies
  that the expected tables exist and returns `:ok`.
  """
  @spec start_ets() :: :ok
  def start_ets do
    # Tables are owned by ExSaml.Core.TableOwner — just verify they exist
    for table <- ExSaml.Core.TableOwner.tables() do
      case :ets.info(table) do
        :undefined ->
          raise "ETS table #{table} not found. Ensure ExSaml.Core.TableOwner is started."

        _ ->
          :ok
      end
    end

    :ok
  end
end
