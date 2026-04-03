defmodule ExSaml.Core.Xml.C14n do
  @moduledoc """
  XML Canonicalization (C14N) for xmerl data structures.

  Implements the W3C Exclusive XML Canonicalization specification:
  http://www.w3.org/TR/xml-c14n

  Operates on xmerl records (`xmlElement`, `xmlAttribute`, etc.).
  """

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlAttribute, Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlComment, Record.extract(:xmlComment, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlPI, Record.extract(:xmlPI, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlDocument, Record.extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlNamespace, Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl"))

  @type xml_thing ::
          record(:xmlDocument)
          | record(:xmlElement)
          | record(:xmlAttribute)
          | record(:xmlPI)
          | record(:xmlText)
          | record(:xmlComment)

  @doc """
  Returns the canonical namespace-URI-prefix-resolved version of an XML name.
  """
  @spec canon_name(record(:xmlElement) | record(:xmlAttribute)) :: String.t()
  def canon_name(rec) when Record.is_record(rec, :xmlAttribute) do
    case xmlAttribute(rec, :nsinfo) do
      {ns, name} -> canon_name_resolve(ns, name, xmlAttribute(rec, :namespace))
      _ -> canon_name_resolve([], xmlAttribute(rec, :name), xmlAttribute(rec, :namespace))
    end
  end

  def canon_name(rec) when Record.is_record(rec, :xmlElement) do
    case xmlElement(rec, :nsinfo) do
      {ns, name} -> canon_name_resolve(ns, name, xmlElement(rec, :namespace))
      _ -> canon_name_resolve([], xmlElement(rec, :name), xmlElement(rec, :namespace))
    end
  end

  @doc false
  def canon_name_resolve(ns, name, nsp) do
    ns_part_raw =
      case ns do
        :empty ->
          xmlNamespace(nsp, :default)

        [] ->
          if nsp == [] do
            :"urn:oasis:names:tc:SAML:2.0:assertion"
          else
            xmlNamespace(nsp, :default)
          end

        _ ->
          nodes = xmlNamespace(nsp, :nodes)

          case :proplists.get_value(ns, nodes) do
            :undefined -> :erlang.error({:ns_not_found, ns, nsp})
            uri -> Atom.to_charlist(uri)
          end
      end

    ns_part = to_charlist_safe(ns_part_raw)
    name_part = to_charlist_safe(name)
    List.to_string(ns_part ++ name_part)
  end

  defp collect_needed_ns(attr, needed, incl_ns) do
    case xmlAttribute(attr, :nsinfo) do
      {prefix, value} when prefix in ["xmlns", ~c"xmlns"] ->
        maybe_add_inclusive_ns(value, needed, incl_ns)

      {ns, _name} ->
        if ns in needed, do: needed, else: [ns | needed]

      _ ->
        needed
    end
  end

  defp maybe_add_inclusive_ns(value, needed, incl_ns) do
    str_value = to_string(value)
    incl_strs = Enum.map(incl_ns, &to_string/1)

    if str_value in incl_strs and value not in needed,
      do: [value | needed],
      else: needed
  end

  defp to_charlist_safe(val) when is_atom(val), do: Atom.to_charlist(val)
  defp to_charlist_safe(val) when is_binary(val), do: String.to_charlist(val)
  defp to_charlist_safe(val) when is_list(val), do: val

  @doc """
  Puts an XML document or element into canonical form, as a string.
  """
  @spec c14n(xml_thing()) :: String.t()
  def c14n(elem), do: c14n(elem, true)

  @doc """
  Puts an XML document or element into canonical form, as a string.

  If `comments` is true, preserves comments in the output.
  """
  @spec c14n(xml_thing(), boolean()) :: String.t()
  def c14n(elem, comments), do: c14n(elem, comments, [])

  @doc """
  Puts an XML document or element into canonical form, as a string.

  If `comments` is true, preserves comments in the output. Any namespace
  prefixes listed in `inclusive_ns` will be left as they are and not
  modified during canonicalization.
  """
  @spec c14n(xml_thing(), boolean(), [String.t()]) :: String.t()
  def c14n(elem, comments, inclusive_ns) do
    do_c14n(elem, [], [], comments, inclusive_ns, [])
    |> Enum.reverse()
    |> :lists.flatten()
    |> List.to_string()
  end

  # --- XML safe string escaping ---

  @doc """
  Make XML content safe (non-quoted context).
  """
  @spec xml_safe_string(term()) :: charlist()
  def xml_safe_string(term), do: xml_safe_string(term, false)

  @doc """
  Make XML content safe. If `quotes` is true, also escapes double quotes.
  """
  @spec xml_safe_string(term(), boolean()) :: charlist()
  def xml_safe_string(atom, quotes) when is_atom(atom),
    do: xml_safe_string(Atom.to_charlist(atom), quotes)

  def xml_safe_string(bin, quotes) when is_binary(bin),
    do: xml_safe_string(:erlang.binary_to_list(bin), quotes)

  def xml_safe_string([], _quotes), do: []

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  def xml_safe_string([next | rest], quotes) when is_list([next | rest]) do
    cond do
      not quotes and next == ?\n ->
        [next | xml_safe_string(rest, quotes)]

      next < 32 ->
        :lists.flatten([
          ~c"&#x" ++ :erlang.integer_to_list(next, 16) ++ ~c";" | xml_safe_string(rest, quotes)
        ])

      quotes and next == ?" ->
        :lists.flatten([~c"&quot;" | xml_safe_string(rest, quotes)])

      next == ?& ->
        :lists.flatten([~c"&amp;" | xml_safe_string(rest, quotes)])

      next == ?< ->
        :lists.flatten([~c"&lt;" | xml_safe_string(rest, quotes)])

      not quotes and next == ?> ->
        :lists.flatten([~c"&gt;" | xml_safe_string(rest, quotes)])

      true ->
        [next | xml_safe_string(rest, quotes)]
    end
  end

  def xml_safe_string(term, quotes) do
    xml_safe_string(:io_lib.format(~c"~p", [term]), quotes)
  end

  # --- Private canonicalization worker ---

  defp do_c14n(rec, _known_ns, _active_ns, _comments, _incl_ns, acc)
       when Record.is_record(rec, :xmlText) do
    [xml_safe_string(xmlText(rec, :value)) | acc]
  end

  defp do_c14n(rec, _known_ns, _active_ns, true, _incl_ns, acc)
       when Record.is_record(rec, :xmlComment) do
    [~c"-->", xml_safe_string(xmlComment(rec, :value)), ~c"<!--" | acc]
  end

  defp do_c14n(rec, _known_ns, _active_ns, _comments, _incl_ns, acc)
       when Record.is_record(rec, :xmlPI) do
    name = xmlPI(rec, :name)
    name_string = if is_atom(name), do: Atom.to_charlist(name), else: :string.trim(name)

    value = xmlPI(rec, :value)
    trimmed = :string.trim(value)

    case trimmed do
      [] -> [~c"?>", name_string, ~c"<?" | acc]
      _ -> [~c"?>", value, ~c" ", name_string, ~c"<?" | acc]
    end
  end

  defp do_c14n(rec, known_ns, active_ns, comments, incl_ns, acc)
       when Record.is_record(rec, :xmlDocument) do
    kids = xmlDocument(rec, :content)

    result =
      Enum.reduce(kids, acc, fn kid, acc_in ->
        case do_c14n(kid, known_ns, active_ns, comments, incl_ns, acc_in) do
          ^acc_in -> acc_in
          other -> [~c"\n" | other]
        end
      end)

    case result do
      [~c"\n" | rest] -> rest
      other -> other
    end
  end

  defp do_c14n(rec, _known_ns, active_ns, _comments, _incl_ns, acc)
       when Record.is_record(rec, :xmlAttribute) do
    case xmlAttribute(rec, :nsinfo) do
      {ns, nname} ->
        if ns in active_ns do
          [
            ~c"\"",
            xml_safe_string(xmlAttribute(rec, :value), true),
            ~c"=\"",
            nname,
            ~c":",
            ns,
            ~c" " | acc
          ]
        else
          :erlang.error("attribute namespace is not active")
        end

      _ ->
        [
          ~c"\"",
          xml_safe_string(xmlAttribute(rec, :value), true),
          ~c"=\"",
          Atom.to_charlist(xmlAttribute(rec, :name)),
          ~c" " | acc
        ]
    end
  end

  # credo:disable-for-next-line Credo.Check.Refactor.CyclomaticComplexity
  defp do_c14n(elem, known_ns_in, active_ns_in, comments, incl_ns, acc)
       when Record.is_record(elem, :xmlElement) do
    namespace = xmlElement(elem, :namespace)

    default =
      case xmlElement(elem, :nsinfo) do
        [] -> xmlNamespace(namespace, :default)
        _ -> []
      end

    {active_ns, parent_default} =
      case active_ns_in do
        [{:default, p} | rest] -> {rest, p}
        other -> {other, :""}
      end

    # Add any new namespaces this element has that we haven't seen before
    known_ns =
      Enum.reduce(xmlNamespace(namespace, :nodes), known_ns_in, fn {ns, uri}, nss ->
        if :proplists.is_defined(ns, nss) do
          nss
        else
          [{ns, Atom.to_charlist(uri)} | nss]
        end
      end)

    # Minimum set of namespaces we need at this level
    needed_ns = needed_ns(elem, incl_ns)
    # All attributes that aren't xmlns
    attrs = clean_sort_attrs(xmlElement(elem, :attributes))

    # Append xmlns: that our parent didn't have but that we need
    new_ns = needed_ns -- active_ns
    new_active_ns = active_ns ++ new_ns

    # Opening tag
    acc1 =
      case xmlElement(elem, :nsinfo) do
        {e_ns, e_name} ->
          [e_name, ~c":", e_ns, ~c"<" | acc]

        _ ->
          [Atom.to_charlist(xmlElement(elem, :name)), ~c"<" | acc]
      end

    # xmlns definitions
    {acc2, final_active_ns} =
      cond do
        default != [] and default != parent_default ->
          {[
             ~c"\"",
             xml_safe_string(default, true),
             ~c" xmlns=\"" | acc1
           ], [{:default, default} | new_active_ns]}

        default != [] ->
          {acc1, [{:default, default} | new_active_ns]}

        true ->
          {acc1, new_active_ns}
      end

    acc3 =
      Enum.reduce(Enum.sort(new_ns), acc2, fn ns, acc_in ->
        [
          ~c"\"",
          xml_safe_string(:proplists.get_value(ns, known_ns, ~c""), true),
          ~c"=\"",
          ns,
          ~c":",
          ~c" xmlns" | acc_in
        ]
      end)

    # Other attributes
    acc4 =
      Enum.reduce(attrs, acc3, fn attr, acc_in ->
        do_c14n(attr, known_ns, final_active_ns, comments, incl_ns, acc_in)
      end)

    # Close the opening tag
    acc5 = [~c">" | acc4]

    # Accumulate all children
    acc6 =
      Enum.reduce(xmlElement(elem, :content), acc5, fn kid, acc_in ->
        do_c14n(kid, known_ns, final_active_ns, comments, incl_ns, acc_in)
      end)

    # Close tag
    case xmlElement(elem, :nsinfo) do
      {ns, name} ->
        [~c">", name, ~c":", ns, ~c"</" | acc6]

      _ ->
        [~c">", Atom.to_charlist(xmlElement(elem, :name)), ~c"</" | acc6]
    end
  end

  # Catch-all: ignore unknown node types
  defp do_c14n(_other, _known_ns, _active_ns, _comments, _incl_ns, acc), do: acc

  # --- Helpers ---

  defp attr_lte(attr_a, attr_b) do
    a = canon_name(attr_a)
    b = canon_name(attr_b)

    prefixed_a = match?({_, _}, xmlAttribute(attr_a, :nsinfo))
    prefixed_b = match?({_, _}, xmlAttribute(attr_b, :nsinfo))

    cond do
      prefixed_a and not prefixed_b -> false
      not prefixed_a and prefixed_b -> true
      true -> a <= b
    end
  end

  defp clean_sort_attrs(attrs) do
    attrs
    |> Enum.filter(fn attr ->
      not xmlns_attr?(attr)
    end)
    |> Enum.sort(&attr_lte/2)
  end

  defp xmlns_attr?(attr) do
    case xmlAttribute(attr, :nsinfo) do
      {prefix, _} when prefix in ["xmlns", ~c"xmlns"] -> true
      _ -> xmlAttribute(attr, :name) == :xmlns
    end
  end

  @doc false
  def needed_ns(elem, incl_ns) when Record.is_record(elem, :xmlElement) do
    needed_ns1 =
      case xmlElement(elem, :nsinfo) do
        {nas, _} -> [nas]
        _ -> []
      end

    Enum.reduce(xmlElement(elem, :attributes), needed_ns1, fn attr, needed ->
      collect_needed_ns(attr, needed, incl_ns)
    end)
  end
end
