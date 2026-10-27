defmodule ExSamlSpDataSigMethodTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias ExSaml.SpData

  @ec_sp %{
    id: "sp_ec",
    entity_id: "urn:test:sp_ec",
    certfile: "test/data/test.crt",
    keyfile: "test/data/keys/ec_p256_sec1.pem"
  }

  test "sig_method is nil unless configured" do
    %SpData{sig_method: nil} = sp_data = SpData.load_provider(@ec_sp)
    assert sp_data.valid?
  end

  test "a method of the key's type is kept" do
    sp_data = SpData.load_provider(Map.put(@ec_sp, :sig_method, :ecdsa_sha384))

    assert sp_data.valid?
    assert sp_data.sig_method == :ecdsa_sha384
  end

  test "a method of another key type invalidates the SP" do
    log =
      capture_log(fn ->
        sp_data = SpData.load_provider(Map.put(@ec_sp, :sig_method, :rsa_sha256))
        refute sp_data.valid?
      end)

    assert log =~ "Invalid SP sig_method"
  end

  test "an unknown method invalidates the SP" do
    capture_log(fn ->
      refute SpData.load_provider(Map.put(@ec_sp, :sig_method, :rsa_md5)).valid?
    end)
  end

  test "without a key, any known method is kept" do
    sp_data = SpData.load_provider(%{@ec_sp | keyfile: ""} |> Map.put(:sig_method, :rsa_sha256))

    assert sp_data.valid?
    assert sp_data.sig_method == :rsa_sha256
  end
end
