defmodule ExSaml.Core.UtilPrivateKeyTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Util
  alias ExSaml.Core.Xml.Dsig.MlDsa

  @keys_dir Path.expand("../../data/keys", __DIR__)
  @p256 {1, 2, 840, 10_045, 3, 1, 7}

  defp import!(file) do
    pem = File.read!(Path.join(@keys_dir, file))
    Util.import_private_key({__MODULE__, file, System.unique_integer()}, pem)
  end

  test "a PKCS#8 RSA key" do
    assert {:ok, {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}} = import!("rsa_2048_pkcs8.pem")
  end

  test "a SEC 1 EC key, with its curve" do
    assert {:ok, {:ECPrivateKey, _, _, {:namedCurve, @p256}, _, _}} = import!("ec_p256_sec1.pem")
  end

  test "a PKCS#8 EC key, with its curve" do
    assert {:ok, {:ECPrivateKey, _, _, {:namedCurve, @p256}, _, _}} = import!("ec_p256_pkcs8.pem")
  end

  test "a PKCS#8 ML-DSA key where the VM has ML-DSA, no key elsewhere" do
    if MlDsa.available?() do
      assert {:ok, {:"ML-DSAPrivateKey", :mldsa65, _, _}} = import!("ml_dsa_65.pem")
    else
      assert {:error, :no_private_key} = import!("ml_dsa_65.pem")
    end
  end

  test "a PEM without a private key" do
    assert {:error, :no_private_key} = import!("ml_dsa_65.crt")
  end

  test "load_private_key/1 reads the same keys from a path" do
    assert {:ok, {:ECPrivateKey, _, _, _, _, _}} =
             Util.load_private_key(Path.join(@keys_dir, "ec_p256_sec1.pem"))
  end
end
