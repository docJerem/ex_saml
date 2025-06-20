defmodule ExSaml.SpData do
  @moduledoc false

  require Logger
  require ExSaml.Esaml
  alias ExSaml.SpData

  defstruct id: "",
            entity_id: "",
            certfile: "",
            keyfile: "",
            contact_name: "",
            contact_email: "",
            org_name: "",
            org_displayname: "",
            org_url: "",
            cert: :undefined,
            key: :undefined,
            valid?: true

  @type t :: %__MODULE__{
          id: binary(),
          entity_id: binary(),
          certfile: binary(),
          keyfile: binary(),
          contact_name: binary(),
          contact_email: binary(),
          org_name: binary(),
          org_displayname: binary(),
          org_url: binary(),
          cert: :undefined | binary(),
          key: :undefined | :RSAPrivateKey,
          valid?: boolean()
        }

  @type id :: binary

  @default_contact_name "ExSaml SP Admin"
  @default_contact_email "admin@ExSaml"
  @default_org_name "ExSaml SP"
  @default_org_displayname "SAML SP built with ExSaml"
  @default_org_url "https://github.com/handnot2/ExSaml"

  @spec load_providers(list(map)) :: %{required(id) => t}
  def load_providers(prov_configs) do
    prov_configs
    |> Enum.map(&load_provider/1)
    |> Enum.filter(fn sp_data -> sp_data.valid? end)
    |> Enum.map(fn sp_data -> {sp_data.id, sp_data} end)
    |> Enum.into(%{})
  end

  @spec load_provider(map) :: %SpData{} | no_return
  def load_provider(%{} = opts_map) do
    %__MODULE__{
      id: Map.get(opts_map, :id, ""),
      entity_id: Map.get(opts_map, :entity_id, ""),
      certfile: Map.get(opts_map, :certfile, ""),
      keyfile: Map.get(opts_map, :keyfile, ""),
      contact_name: Map.get(opts_map, :contact_name, @default_contact_name),
      contact_email: Map.get(opts_map, :contact_email, @default_contact_email),
      org_name: Map.get(opts_map, :org_name, @default_org_name),
      org_displayname: Map.get(opts_map, :org_displayname, @default_org_displayname),
      org_url: Map.get(opts_map, :org_url, @default_org_url),
      key: Map.get(opts_map, :key, :undefined),
      cert: Map.get(opts_map, :cert, :undefined)
    }
    |> set_id(opts_map)
    |> load_cert(opts_map)
    |> load_key(opts_map)
  end

  @spec set_id(%SpData{}, map()) :: %SpData{}
  defp set_id(%SpData{} = sp_data, %{} = opts_map) do
    case Map.get(opts_map, :id, "") do
      "" ->
        Logger.error("[ExSaml] Invalid SP Config: #{inspect(opts_map)}")
        %SpData{sp_data | valid?: false}

      id ->
        %SpData{sp_data | id: id}
    end
  end

  @spec load_cert(%SpData{}, map()) :: %SpData{}
  defp load_cert(%SpData{cert: cert, certfile: ""} = sp_data, _) when is_binary(cert) do
    %SpData{sp_data | cert: cert}
  end

  defp load_cert(%SpData{certfile: ""} = sp_data, _) do
    %SpData{sp_data | cert: :undefined}
  end

  defp load_cert(%SpData{certfile: certfile} = sp_data, %{} = opts_map) do
    try do
      cert =
        if sp_data.cert !== :undefined,
          do: sp_data.cert,
          else: :esaml_util.load_certificate(certfile)

      %SpData{sp_data | cert: cert}
    rescue
      _error ->
        Logger.error(
          "[ExSaml] Failed load SP certfile [#{inspect(certfile)}]: #{inspect(opts_map)}"
        )

        %SpData{sp_data | valid?: false}
    end
  end

  @spec load_key(%SpData{}, map()) :: %SpData{}
  defp load_key(%SpData{key: key} = sp_data, _) when is_tuple(key) do
    %SpData{sp_data | key: key}
  end

  defp load_key(%SpData{keyfile: ""} = sp_data, _) do
    %SpData{sp_data | key: :undefined}
  end

  defp load_key(%SpData{keyfile: keyfile} = sp_data, %{} = opts_map) do
    try do
      key = :esaml_util.load_private_key(keyfile)
      %SpData{sp_data | key: key}
    rescue
      _error ->
        Logger.error(
          "[ExSaml] Failed load SP keyfile [#{inspect(keyfile)}]: #{inspect(opts_map)}"
        )

        %SpData{sp_data | key: :undefined, valid?: false}
    end
  end
end
