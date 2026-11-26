defmodule ExSaml.UITest do
  use ExUnit.Case, async: true

  alias ExSaml.UI

  describe "value(:entity_id, idp)" do
    test "is the IdP's own SP entity ID" do
      idp = %{
        sp_entity_id: "acme_idp",
        sp_id: "account_sp",
        saml_service_provider_id: "account_sp"
      }

      assert UI.value(:entity_id, idp) == "acme_idp"
    end

    test "is the service provider's id without one on the IdP" do
      assert UI.value(:entity_id, %{sp_entity_id: nil, sp_id: "account_sp"}) == "account_sp"
      assert UI.value(:entity_id, %{sp_id: "account_sp"}) == "account_sp"

      assert UI.value(:entity_id, %{sp_id: nil, saml_service_provider_id: "account_sp"}) ==
               "account_sp"
    end
  end
end
