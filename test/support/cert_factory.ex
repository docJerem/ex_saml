defmodule ExSaml.Test.CertFactory do
  @moduledoc """
  Test-only helper for generating self-signed X.509 certificates used in
  `ExSaml.Metadata` validation tests.

  Wraps the `X509` hex package with SAML-flavoured defaults. Every `build/1`
  call produces a fresh 2048-bit RSA key and a matching self-signed
  certificate with a 10-year validity window.

  Returns a map with three views of the same cert:

    * `:der`  — raw DER bytes
    * `:pem`  — PEM-encoded binary
    * `:b64`  — base64 DER, suitable for embedding in `<ds:X509Certificate>`
  """

  @type cert :: %{der: binary(), pem: binary(), b64: binary()}

  @default_subject "/CN=ex_saml-test"
  @default_key_size 2048
  @default_validity_days 3650

  @spec build(keyword()) :: cert()
  def build(opts \\ []) do
    subject = Keyword.get(opts, :subject, @default_subject)
    key_size = Keyword.get(opts, :key_size, @default_key_size)
    template = Keyword.get(opts, :template, :server)
    extensions = Keyword.get(opts, :extensions, [])
    validity = validity_from(opts)

    key = X509.PrivateKey.new_rsa(key_size)

    cert =
      X509.Certificate.self_signed(key, subject,
        template: template,
        validity: validity,
        extensions: extensions,
        hash: :sha256
      )

    der = X509.Certificate.to_der(cert)
    pem = X509.Certificate.to_pem(cert)

    %{der: der, pem: pem, b64: Base.encode64(der)}
  end

  # -----
  # Shorthand builders for common fixtures
  # -----

  @doc "Self-signed leaf cert with digitalSignature + keyEncipherment key usage."
  @spec signing(keyword()) :: cert()
  def signing(opts \\ []) do
    build(
      Keyword.merge(
        [
          template: :server,
          extensions: [
            basic_constraints: X509.Certificate.Extension.basic_constraints(false),
            key_usage:
              X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment])
          ]
        ],
        opts
      )
    )
  end

  @doc "Self-signed leaf cert intended for encryption only (no digitalSignature)."
  @spec encryption(keyword()) :: cert()
  def encryption(opts \\ []) do
    build(
      Keyword.merge(
        [
          template: :server,
          extensions: [
            basic_constraints: X509.Certificate.Extension.basic_constraints(false),
            key_usage: X509.Certificate.Extension.key_usage([:keyEncipherment])
          ]
        ],
        opts
      )
    )
  end

  @doc "CA certificate (BasicConstraints CA:TRUE, KeyUsage includes keyCertSign)."
  @spec ca(keyword()) :: cert()
  def ca(opts \\ []) do
    build(
      Keyword.merge(
        [
          template: :root_ca,
          extensions: [
            basic_constraints: X509.Certificate.Extension.basic_constraints(true),
            key_usage:
              X509.Certificate.Extension.key_usage([
                :digitalSignature,
                :keyCertSign,
                :cRLSign
              ])
          ]
        ],
        opts
      )
    )
  end

  @doc "Already-expired leaf cert (notAfter 1 day ago, notBefore 30 days ago)."
  @spec expired(keyword()) :: cert()
  def expired(opts \\ []) do
    signing(Keyword.put(opts, :validity, expired_validity()))
  end

  # -----
  # Internals
  # -----

  defp validity_from(opts) do
    case Keyword.fetch(opts, :validity) do
      {:ok, v} ->
        v

      :error ->
        X509.Certificate.Validity.days_from_now(
          Keyword.get(opts, :validity_days, @default_validity_days)
        )
    end
  end

  defp expired_validity do
    not_before = DateTime.add(DateTime.utc_now(), -30 * 86_400, :second)
    not_after = DateTime.add(DateTime.utc_now(), -1 * 86_400, :second)
    X509.Certificate.Validity.new(not_before, not_after)
  end
end
