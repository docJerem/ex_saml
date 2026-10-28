defmodule ExSaml.Core.Xml.SafeXml.Prescan do
  @moduledoc false

  # Lexical pass over a raw document, run before `:xmerl_scan` sees it.
  #
  # It does not build a tree. It walks the markup the way `:xmerl_scan` does,
  # and:
  #
  #   * rejects any `<!` declaration other than a comment or a CDATA section,
  #     so a DOCTYPE (internal subset or external identifier) never reaches the
  #     parser;
  #   * rejects any entity reference other than the five predefined ones and
  #     character references;
  #   * rejects a declared encoding other than UTF-8, US-ASCII or ISO-8859-1,
  #     and UTF-16 / UTF-32 byte order marks;
  #   * collects every string `:xmerl_scan` turns into an atom: element names
  #     (start and end tags), attribute names, the local part of prefixed
  #     names, namespace URIs, and processing-instruction targets.
  #
  # Names are read with `:xmerl_lib.is_letter/1` and `:xmerl_lib.is_namechar/1`,
  # the predicates `:xmerl_scan` itself uses, so a name ends where the parser
  # ends it. Anything this pass cannot read unambiguously is rejected rather
  # than passed on: the parser never sees a document this pass did not fully
  # account for.

  @type reason ::
          :doctype | :entity_reference | :unsupported_encoding | :invalid_name | :malformed

  # Longest name the parser can turn into an atom.
  @max_name_length 255

  @spec names(binary()) :: {:ok, [String.t()]} | {:error, reason()}
  def names(doc) when is_binary(doc) do
    if utf16_or_utf32_bom?(doc) do
      {:error, :unsupported_encoding}
    else
      content(doc, %{mode: :utf8, names: MapSet.new()})
    end
  end

  defp utf16_or_utf32_bom?(<<0xFE, 0xFF, _::binary>>), do: true
  defp utf16_or_utf32_bom?(<<0xFF, 0xFE, _::binary>>), do: true
  defp utf16_or_utf32_bom?(<<0x00, 0x00, 0xFE, 0xFF, _::binary>>), do: true
  defp utf16_or_utf32_bom?(_), do: false

  # ---------------------------------------------------------------------------
  # Character data and markup dispatch
  # ---------------------------------------------------------------------------

  defp content(bin, st) do
    case :binary.match(bin, ["<", "&"]) do
      :nomatch ->
        {:ok, MapSet.to_list(st.names)}

      {pos, 1} ->
        markup(binary_part(bin, pos, byte_size(bin) - pos), st)
    end
  end

  defp markup("<!--" <> rest, st), do: skip_past(rest, "-->", st)
  defp markup("<![CDATA[" <> rest, st), do: skip_past(rest, "]]>", st)
  defp markup("<!" <> _, _st), do: {:error, :doctype}
  defp markup("<?" <> rest, st), do: processing_instruction(rest, st)
  defp markup("</" <> rest, st), do: end_tag(rest, st)
  defp markup("<" <> rest, st), do: start_tag(rest, st)

  defp markup("&" <> rest, st) do
    with {:ok, rest} <- reference(rest), do: content(rest, st)
  end

  defp skip_past(bin, delimiter, st) do
    case :binary.match(bin, delimiter) do
      :nomatch -> {:error, :malformed}
      {pos, len} -> content(binary_part(bin, pos + len, byte_size(bin) - pos - len), st)
    end
  end

  # Character references expand to character data; the five predefined
  # entities are matched literally by the parser. Any other name would be
  # resolved as a general entity, which a document without a DTD cannot
  # declare.
  defp reference("#" <> _ = rest), do: {:ok, rest}
  defp reference("lt;" <> rest), do: {:ok, rest}
  defp reference("gt;" <> rest), do: {:ok, rest}
  defp reference("amp;" <> rest), do: {:ok, rest}
  defp reference("apos;" <> rest), do: {:ok, rest}
  defp reference("quot;" <> rest), do: {:ok, rest}
  defp reference(_), do: {:error, :entity_reference}

  # ---------------------------------------------------------------------------
  # Processing instructions and the XML declaration
  # ---------------------------------------------------------------------------

  defp processing_instruction(bin, st) do
    with {:ok, target, rest} <- read_name(bin, st.mode),
         {pos, 2} <- :binary.match(rest, "?>"),
         body = binary_part(rest, 0, pos),
         {:ok, st} <- pi_target(target, body, st) do
      content(binary_part(rest, pos + 2, byte_size(rest) - pos - 2), st)
    else
      :nomatch -> {:error, :malformed}
      {:error, _} = error -> error
    end
  end

  # The XML declaration (`<?xml …?>`) is read by the parser without creating
  # an atom for its target, but a declared encoding other than UTF-8 is.
  defp pi_target("xml", body, st) do
    with {:ok, mode} <- declared_encoding(body), do: {:ok, %{st | mode: mode}}
  end

  defp pi_target(target, _body, st), do: {:ok, add(st, target)}

  defp declared_encoding(body) do
    case Regex.run(~r/encoding\s*=\s*(?:"([^"]*)"|'([^']*)')/, body, capture: :all_but_first) do
      nil -> {:ok, :utf8}
      captures -> captures |> Enum.join() |> String.downcase() |> encoding_mode()
    end
  end

  defp encoding_mode("utf-8"), do: {:ok, :utf8}
  defp encoding_mode("us-ascii"), do: {:ok, :latin1}
  defp encoding_mode("iso-8859-1"), do: {:ok, :latin1}
  defp encoding_mode(_), do: {:error, :unsupported_encoding}

  # ---------------------------------------------------------------------------
  # Tags and attributes
  # ---------------------------------------------------------------------------

  defp end_tag(bin, st) do
    with {:ok, name, rest} <- read_name(bin, st.mode),
         ">" <> rest <- skip_whitespace(rest) do
      content(rest, add_qname(st, name))
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed}
    end
  end

  defp start_tag(bin, st) do
    with {:ok, name, rest} <- read_name(bin, st.mode) do
      attributes(rest, add_qname(st, name))
    end
  end

  defp attributes(bin, st) do
    case skip_whitespace(bin) do
      "/>" <> rest -> content(rest, st)
      ">" <> rest -> content(rest, st)
      rest -> attribute(rest, st)
    end
  end

  defp attribute(bin, st) do
    with {:ok, name, rest} <- read_name(bin, st.mode),
         "=" <> rest <- skip_whitespace(rest),
         <<quote, rest::binary>> when quote in [?", ?'] <- skip_whitespace(rest),
         {pos, 1} <- :binary.match(rest, <<quote>>),
         value = binary_part(rest, 0, pos),
         {:ok, st} <- attribute_value(name, value, add_qname(st, name)) do
      attributes(binary_part(rest, pos + 1, byte_size(rest) - pos - 1), st)
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed}
    end
  end

  defp attribute_value(name, value, st) do
    cond do
      String.contains?(value, "<") -> {:error, :malformed}
      namespace_declaration?(name) -> namespace_uri(value, st)
      true -> check_references(value, st)
    end
  end

  defp namespace_declaration?("xmlns"), do: true
  defp namespace_declaration?("xmlns:" <> _), do: true
  defp namespace_declaration?(_), do: false

  # The parser turns a namespace URI into an atom after normalising the
  # attribute value. URIs that normalisation would alter (references,
  # whitespace other than spaces) are rejected, so the string checked here is
  # exactly the atom the parser would create.
  defp namespace_uri(value, st) do
    cond do
      String.contains?(value, ["&", "\t", "\n", "\r"]) -> {:error, :malformed}
      st.mode == :latin1 -> {:ok, add(st, :unicode.characters_to_binary(value, :latin1))}
      String.valid?(value) -> {:ok, add(st, value)}
      true -> {:error, :malformed}
    end
  end

  defp check_references(value, st) do
    case :binary.match(value, "&") do
      :nomatch ->
        {:ok, st}

      {pos, 1} ->
        rest = binary_part(value, pos + 1, byte_size(value) - pos - 1)
        with {:ok, rest} <- reference(rest), do: check_references(rest, st)
    end
  end

  # ---------------------------------------------------------------------------
  # Names
  # ---------------------------------------------------------------------------

  # A qualified name contributes its own atom and, when prefixed, the atom of
  # its local part (the parser's expanded name). Namespace declarations
  # (`xmlns:p`) keep their local part as a string.
  defp add_qname(st, name) do
    case String.split(name, ":") do
      [_unprefixed] -> add(st, name)
      ["xmlns", _prefix] -> add(st, name)
      [_prefix, local] -> st |> add(name) |> add(local)
    end
  end

  defp add(st, name), do: %{st | names: MapSet.put(st.names, name)}

  defp read_name(bin, mode) do
    case next_char(bin, mode) do
      {char, rest} when char == ?_ ->
        read_name_chars(rest, mode, [char])

      {char, rest} ->
        if :xmerl_lib.is_letter(char),
          do: read_name_chars(rest, mode, [char]),
          else: {:error, :invalid_name}

      :error ->
        {:error, :invalid_name}
    end
  end

  defp read_name_chars(bin, mode, acc) do
    with {char, rest} <- next_char(bin, mode),
         true <- :xmerl_lib.is_namechar(char) do
      read_name_chars(rest, mode, [char | acc])
    else
      _ -> finish_name(acc, bin)
    end
  end

  defp finish_name(acc, rest) do
    chars = Enum.reverse(acc)
    name = :unicode.characters_to_binary(chars)

    cond do
      length(chars) > @max_name_length -> {:error, :invalid_name}
      length(String.split(name, ":")) > 2 -> {:error, :invalid_name}
      String.starts_with?(name, ":") or String.ends_with?(name, ":") -> {:error, :invalid_name}
      true -> {:ok, name, rest}
    end
  end

  defp next_char(<<char::utf8, rest::binary>>, :utf8), do: {char, rest}
  defp next_char(<<char, rest::binary>>, :latin1), do: {char, rest}
  defp next_char(_, _), do: :error

  defp skip_whitespace(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r],
    do: skip_whitespace(rest)

  defp skip_whitespace(bin), do: bin
end
