defmodule ExSaml.Helper do
  @moduledoc false

  alias ExSaml.{Assertion, IdpData}
  alias ExSaml.Core

  @spec get_idp(binary) :: nil | IdpData.t()
  def get_idp(idp_id) do
    idps = Application.get_env(:ex_saml, :identity_providers, %{})
    Map.get(idps, idp_id)
  end

  @spec get_metadata_uri(nil | binary, binary) :: nil | charlist
  def get_metadata_uri(nil, _idp_id), do: nil

  def get_metadata_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata" |> String.to_charlist()
  end

  def get_metadata_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata/#{idp_id}" |> String.to_charlist()
  end

  @spec get_consume_uri(nil | binary, binary) :: nil | charlist
  def get_consume_uri(nil, _idp_id), do: nil

  def get_consume_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume" |> String.to_charlist()
  end

  def get_consume_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume/#{idp_id}" |> String.to_charlist()
  end

  @spec get_logout_uri(nil | binary, binary) :: nil | charlist
  def get_logout_uri(nil, _idp_id), do: nil

  def get_logout_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout" |> String.to_charlist()
  end

  def get_logout_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout/#{idp_id}" |> String.to_charlist()
  end

  def sp_metadata(sp) do
    :xmerl.export([Core.Sp.generate_metadata(sp)], :xmerl_xml)
  end

  def gen_idp_signin_req(sp, idp_metadata, nameid_format) do
    idp_signin_url = idp_metadata.login_location

    xml_frag = Core.Sp.generate_authn_request(idp_signin_url, sp, nameid_format)

    {idp_signin_url, xml_frag}
  end

  def gen_idp_signout_req(sp, idp_metadata, subject, session_index) do
    idp_signout_url = idp_metadata.logout_location
    xml_frag = Core.Sp.generate_logout_request(idp_signout_url, session_index, subject, sp)
    {idp_signout_url, xml_frag}
  end

  def gen_idp_signout_resp(sp, idp_metadata, signout_status) do
    idp_signout_url = idp_metadata.logout_location
    xml_frag = Core.Sp.generate_logout_response(idp_signout_url, signout_status, sp)
    {idp_signout_url, xml_frag}
  end

  def decode_idp_auth_resp(sp, saml_encoding, saml_response) do
    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         {:ok, core_assertion} <- Core.Sp.validate_assertion(xml_frag, sp) do
      {:ok, Assertion.from_core(core_assertion)}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def decode_idp_signout_resp(sp, saml_encoding, saml_response) do
    resp_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"},
      {~c"ds", ~c"http://www.w3.org/2000/09/xmldsig#"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutResponse", xml_frag, [{:namespace, resp_ns}]) do
      Core.Sp.validate_logout_response(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_idp_signout_req(sp, saml_encoding, saml_request) do
    req_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_request),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutRequest", xml_frag, [{:namespace, req_ns}]) do
      Core.Sp.validate_logout_request(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp decode_saml_payload(saml_encoding, saml_payload) do
    xml = Core.Binding.decode_response(saml_encoding, saml_payload)
    {:ok, xml}
  rescue
    error -> {:error, {:invalid_response, "#{inspect(error)}"}}
  end
end
