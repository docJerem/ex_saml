defmodule ExSaml.ErrorMessagesTest do
  use ExUnit.Case, async: true

  alias ExSaml.ErrorMessages

  @response_checks ~w(bad_issuer bad_in_response_to bad_destination bad_subject_confirmation session_expired duplicate bad_name_id unsigned_cbc)a

  test "every response validation reason has a message in English and French" do
    for reason <- @response_checks, locale <- ["en", "fr"] do
      message = ErrorMessages.get(reason, locale)
      assert is_binary(message)
      refute message == Atom.to_string(reason)
    end
  end

  test "an {:error, reason} tuple resolves like the bare reason" do
    assert ErrorMessages.get({:error, :bad_destination}) == ErrorMessages.get(:bad_destination)
  end
end
