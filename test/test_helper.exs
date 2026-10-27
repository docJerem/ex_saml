# The ML-DSA tests need OTP 28.1+ linked with OpenSSL 3.5+. Elsewhere they
# are excluded, unless EX_SAML_REQUIRE_ML_DSA says a skip is a failure, as on
# the CI job meant to run them.
ml_dsa? = ExSaml.Core.Xml.Dsig.MlDsa.available?()

if System.get_env("EX_SAML_REQUIRE_ML_DSA") in ["1", "true"] and not ml_dsa? do
  raise "EX_SAML_REQUIRE_ML_DSA is set but this VM has no ML-DSA: #{inspect(:crypto.info_lib())}"
end

unless ml_dsa?, do: IO.puts("ML-DSA is unavailable on this VM: excluding the :ml_dsa tests")

ExUnit.start(exclude: if(ml_dsa?, do: [], else: [:ml_dsa]))
