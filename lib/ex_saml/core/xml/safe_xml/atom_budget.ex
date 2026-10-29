defmodule ExSaml.Core.Xml.SafeXml.AtomBudget do
  @moduledoc false

  # Node-wide bound on the atoms the XML parser may create.
  #
  # `:xmerl_scan` creates an atom for every element name, attribute name,
  # local name, namespace URI and processing-instruction target it reads, and
  # atoms are never garbage collected. A per-document limit does not bound the
  # total across documents, so the bound is kept for the whole node:
  #
  #   * a name that is already an atom, or that belongs to the built-in SAML
  #     vocabulary (`KnownNames`) or to the configured `:extra_names` /
  #     `:extra_prefixes`, is free: it creates no atom, or one of a finite,
  #     fixed set;
  #   * every other name draws one unit from a budget of `:max_new_atoms`
  #     (default 10_000) shared by every document the node parses, for the
  #     node's lifetime. Once a name has been parsed it is an atom, so it is
  #     free from then on;
  #   * a document whose new names do not fit in what remains of the budget is
  #     rejected before the parser runs.
  #
  # The counter is an `:atomics` reference held in `:persistent_term`. The
  # reservation is a single `add_get`, rolled back when it overshoots, so
  # concurrent documents cannot together exceed the budget. A name reserved
  # by a document the parser then rejects is still counted: the counter can
  # only overestimate the atoms actually created.

  require Logger

  alias ExSaml.Core.Xml.SafeXml.KnownNames

  @key {__MODULE__, :counter}
  @used 1
  @warned 2
  @default_max_new_atoms 10_000

  @doc "Creates the node-wide counter, if it does not exist yet."
  @spec init() :: :atomics.atomics_ref()
  def init do
    case :persistent_term.get(@key, nil) do
      nil ->
        ref = :atomics.new(2, signed: false)
        :persistent_term.put(@key, ref)
        ref

      ref ->
        ref
    end
  end

  @doc "Units of the budget drawn so far on this node."
  @spec used() :: non_neg_integer()
  def used, do: :atomics.get(counter(), @used)

  @doc """
  Admits a document whose parse would create atoms for `names`, drawing the
  names that are not known yet from the budget.
  """
  @spec admit([String.t()], keyword()) :: :ok | {:error, :atom_budget_exhausted}
  def admit(names, config) do
    max = max_new_atoms(config)
    ref = counter()
    remaining = max - :atomics.get(ref, @used)
    extra = extra(config)

    case count_unknown(names, extra, remaining, 0) do
      0 -> :ok
      :over -> exhausted(ref)
      count -> reserve(ref, count, max)
    end
  end

  defp count_unknown(_names, _extra, remaining, count) when count > 0 and count > remaining,
    do: :over

  defp count_unknown([], _extra, _remaining, count), do: count

  defp count_unknown([name | names], extra, remaining, count) do
    if known?(name, extra),
      do: count_unknown(names, extra, remaining, count),
      else: count_unknown(names, extra, remaining, count + 1)
  end

  defp reserve(ref, count, max) do
    if :atomics.add_get(ref, @used, count) <= max do
      :ok
    else
      :atomics.sub(ref, @used, count)
      exhausted(ref)
    end
  end

  defp exhausted(ref) do
    if :atomics.compare_exchange(ref, @warned, 0, 1) == :ok do
      Logger.warning(
        "[ExSaml] SafeXml atom budget exhausted: documents with element or attribute " <>
          "names not seen before are now rejected. Raise `:max_new_atoms` or declare " <>
          "the names with `:extra_names` / `:extra_prefixes` under `config :ex_saml, :safe_xml`."
      )
    end

    {:error, :atom_budget_exhausted}
  end

  defp known?(name, {extra_names, extra_prefixes}) do
    KnownNames.known?(name) or name in extra_names or
      extra_prefixed?(name, extra_prefixes) or existing_atom?(name)
  end

  defp extra_prefixed?(_name, []), do: false

  defp extra_prefixed?(name, prefixes) do
    case String.split(name, ":", parts: 2) do
      ["xmlns", prefix] -> prefix in prefixes
      [prefix, local] -> prefix in prefixes and KnownNames.known_local?(local)
      _ -> false
    end
  end

  defp existing_atom?(name) do
    _ = :erlang.binary_to_existing_atom(name, :utf8)
    true
  rescue
    ArgumentError -> false
  end

  defp counter, do: :persistent_term.get(@key, nil) || init()

  @doc false
  def max_new_atoms(config) do
    case Keyword.get(config, :max_new_atoms, @default_max_new_atoms) do
      n when is_integer(n) and n >= 0 -> n
      _ -> @default_max_new_atoms
    end
  end

  defp extra(config) do
    {strings(Keyword.get(config, :extra_names, [])),
     strings(Keyword.get(config, :extra_prefixes, []))}
  end

  defp strings(list) when is_list(list), do: Enum.filter(list, &is_binary/1)
  defp strings(_), do: []
end
