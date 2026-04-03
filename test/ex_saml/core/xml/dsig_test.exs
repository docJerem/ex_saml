defmodule ExSaml.Core.Xml.DsigTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.Dsig

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  @sha1_signed_xml ~S|<?xml version="1.0"?><x:foo ID="9616e6c0-f525-11b7-afb7-5cf9dd711ed3" xmlns:x="urn:foo:x:"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#9616e6c0-f525-11b7-afb7-5cf9dd711ed3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>blah</x:name></x:foo>|

  @bad_digest_xml ~S|<?xml version="1.0"?><x:foo ID="9616e6c0-f525-11b7-afb7-5cf9dd711ed3" xmlns:x="urn:foo:x:"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#9616e6c0-f525-11b7-afb7-5cf9dd711ed3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>b1ah</x:name></x:foo>|

  @bad_signature_xml ~S|<?xml version="1.0"?><x:foo ID="9616e6c0-f525-11b7-afb7-5cf9dd711ed3" xmlns:x="urn:foo:x:"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#9616e6c0-f525-11b7-afb7-5cf9dd711ed3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>FzMI9JNIp2IYjB5pnReqi+khe1k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><x:name>b1ah</x:name></x:foo>|

  defp parse_xml(xml_string) do
    {doc, _} =
      :xmerl_scan.string(String.to_charlist(xml_string), namespace_conformant: true)

    doc
  end

  defp test_sign_key do
    cert_bin =
      <<48, 130, 1, 173, 48, 130, 1, 103, 160, 3, 2, 1, 2, 2, 9, 0, 155, 15, 116, 226, 54, 209,
        145, 118, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 48, 66, 49, 11, 48, 9,
        6, 3, 85, 4, 6, 19, 2, 88, 88, 49, 21, 48, 19, 6, 3, 85, 4, 7, 12, 12, 68, 101, 102, 97,
        117, 108, 116, 32, 67, 105, 116, 121, 49, 28, 48, 26, 6, 3, 85, 4, 10, 12, 19, 68, 101,
        102, 97, 117, 108, 116, 32, 67, 111, 109, 112, 97, 110, 121, 32, 76, 116, 100, 48, 30,
        23, 13, 49, 51, 48, 53, 48, 50, 48, 54, 48, 48, 51, 52, 90, 23, 13, 50, 51, 48, 53, 48,
        50, 48, 54, 48, 48, 51, 52, 90, 48, 66, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 88, 88,
        49, 21, 48, 19, 6, 3, 85, 4, 7, 12, 12, 68, 101, 102, 97, 117, 108, 116, 32, 67, 105,
        116, 121, 49, 28, 48, 26, 6, 3, 85, 4, 10, 12, 19, 68, 101, 102, 97, 117, 108, 116, 32,
        67, 111, 109, 112, 97, 110, 121, 32, 76, 116, 100, 48, 76, 48, 13, 6, 9, 42, 134, 72,
        134, 247, 13, 1, 1, 1, 5, 0, 3, 59, 0, 48, 56, 2, 49, 0, 205, 22, 207, 74, 179, 213,
        185, 209, 141, 250, 249, 250, 90, 172, 216, 115, 36, 248, 202, 38, 35, 250, 140, 203,
        148, 166, 140, 157, 135, 4, 125, 142, 129, 148, 170, 140, 171, 183, 154, 14, 45, 63, 60,
        99, 68, 109, 247, 155, 2, 3, 1, 0, 1, 163, 80, 48, 78, 48, 29, 6, 3, 85, 29, 14, 4, 22,
        4, 20, 217, 116, 226, 255, 194, 252, 218, 129, 177, 246, 103, 26, 72, 200, 32, 122, 187,
        222, 157, 58, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 217, 116, 226, 255, 194,
        252, 218, 129, 177, 246, 103, 26, 72, 200, 32, 122, 187, 222, 157, 58, 48, 12, 6, 3, 85,
        29, 19, 4, 5, 48, 3, 1, 1, 255, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0,
        3, 49, 0, 66, 238, 235, 142, 200, 32, 210, 110, 101, 63, 239, 197, 154, 4, 128, 26, 192,
        193, 3, 10, 250, 95, 242, 106, 110, 98, 1, 100, 8, 229, 143, 141, 180, 42, 219, 11, 94,
        149, 187, 74, 164, 45, 37, 79, 228, 71, 103, 175>>

    # credo:disable-for-lines:2 Credo.Check.Readability.MaxLineLength
    modulus =
      31_566_101_599_917_470_453_416_065_772_975_030_637_050_267_921_499_643_485_243_561_060_280_673_467_204_714_198_784_209_398_028_051_515_492_879_184_033_691

    # credo:disable-for-lines:2 Credo.Check.Readability.MaxLineLength
    private_exponent =
      18_573_989_898_799_417_322_963_879_097_353_191_425_554_564_320_258_643_998_367_520_268_996_258_880_659_389_403_428_515_182_780_052_189_009_731_243_940_089

    key =
      {:RSAPrivateKey, :"two-prime", modulus, 65_537, private_exponent,
       6_176_779_427_556_368_800_436_097_873_318_862_403_597_526_763_704_995_657_789,
       5_110_446_628_398_630_915_379_329_225_736_384_395_133_647_699_411_033_691_319,
       3_629_707_330_424_811_560_529_090_457_257_061_337_677_158_715_287_651_140_161,
       3_337_927_863_271_614_430_989_022_488_622_788_202_360_360_154_126_504_237_157,
       3_289_563_093_010_152_325_531_764_796_397_097_457_944_832_648_507_910_197_015,
       :asn1_NOVALUE}

    {key, cert_bin}
  end

  defp test_sign_256_key do
    cert_bin =
      <<48, 130, 2, 88, 48, 130, 1, 193, 160, 3, 2, 1, 2, 2, 9, 0, 143, 6, 244, 72, 167, 203,
        103, 249, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 69, 49, 11, 48,
        9, 6, 3, 85, 4, 6, 19, 2, 65, 85, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 83, 111, 109,
        101, 45, 83, 116, 97, 116, 101, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24, 73, 110, 116,
        101, 114, 110, 101, 116, 32, 87, 105, 100, 103, 105, 116, 115, 32, 80, 116, 121, 32, 76,
        116, 100, 48, 30, 23, 13, 49, 53, 48, 49, 48, 57, 48, 53, 53, 56, 50, 56, 90, 23, 13,
        49, 56, 48, 49, 48, 56, 48, 53, 53, 56, 50, 56, 90, 48, 69, 49, 11, 48, 9, 6, 3, 85, 4,
        6, 19, 2, 65, 85, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12, 10, 83, 111, 109, 101, 45, 83,
        116, 97, 116, 101, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24, 73, 110, 116, 101, 114, 110,
        101, 116, 32, 87, 105, 100, 103, 105, 116, 115, 32, 80, 116, 121, 32, 76, 116, 100, 48,
        129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48,
        129, 137, 2, 129, 129, 0, 226, 96, 97, 235, 98, 1, 16, 138, 195, 252, 131, 198, 89, 74,
        61, 140, 212, 78, 159, 123, 99, 28, 153, 153, 53, 193, 67, 109, 72, 5, 148, 219, 215, 43,
        114, 158, 115, 146, 245, 138, 110, 187, 86, 167, 232, 15, 75, 90, 39, 50, 192, 75, 180,
        64, 97, 107, 84, 135, 124, 189, 87, 96, 62, 133, 63, 147, 146, 200, 97, 209, 193, 17,
        186, 23, 41, 243, 247, 94, 51, 116, 64, 104, 108, 253, 157, 152, 31, 189, 28, 67, 24, 20,
        12, 216, 67, 144, 186, 216, 245, 111, 142, 219, 106, 11, 59, 106, 147, 184, 89, 104, 55,
        80, 79, 112, 40, 181, 99, 211, 254, 130, 151, 2, 109, 137, 153, 40, 216, 255, 2, 3, 1, 0,
        1, 163, 80, 48, 78, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 226, 28, 15, 2, 132, 199,
        176, 227, 86, 54, 191, 35, 102, 122, 246, 50, 138, 160, 135, 239, 48, 31, 6, 3, 85, 29,
        35, 4, 24, 48, 22, 128, 20, 226, 28, 15, 2, 132, 199, 176, 227, 86, 54, 191, 35, 102,
        122, 246, 50, 138, 160, 135, 239, 48, 12, 6, 3, 85, 29, 19, 4, 5, 48, 3, 1, 1, 255, 48,
        13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 129, 129, 0, 205, 96, 78, 143,
        187, 166, 157, 119, 160, 185, 177, 84, 220, 232, 121, 254, 52, 50, 111, 54, 114, 42, 132,
        147, 98, 202, 12, 7, 194, 120, 234, 67, 26, 218, 126, 193, 245, 72, 75, 95, 224, 211, 23,
        244, 240, 57, 207, 46, 99, 142, 76, 218, 100, 184, 132, 172, 34, 73, 193, 145, 142, 72,
        53, 165, 23, 144, 255, 102, 86, 99, 42, 254, 82, 107, 53, 119, 240, 62, 200, 212, 83,
        220, 57, 80, 230, 146, 109, 43, 211, 31, 166, 82, 178, 55, 114, 110, 148, 164, 247, 254,
        162, 135, 126, 157, 123, 185, 30, 146, 185, 60, 125, 234, 98, 188, 205, 109, 134, 74, 58,
        230, 84, 245, 87, 233, 232, 133, 5, 2>>

    # credo:disable-for-lines:2 Credo.Check.Readability.MaxLineLength
    modulus =
      158_966_980_232_852_666_772_927_195_913_239_826_068_125_056_530_979_279_609_712_979_168_793_279_569_950_881_734_703_825_673_400_914_686_519_075_266_453_462_906_345_312_980_842_795_804_140_929_898_282_998_881_309_114_359_443_174_166_979_208_804_324_900_933_216_050_217_378_336_424_610_098_894_747_923_637_370_129_796_798_783_736_195_833_452_722_831_496_313_972_485_597_624_172_644_388_752_444_143_966_442_019_071

    # credo:disable-for-lines:2 Credo.Check.Readability.MaxLineLength
    private_exponent =
      81_585_278_241_787_073_666_896_657_377_387_148_477_980_168_094_656_271_566_789_692_148_593_343_582_026_914_676_392_925_775_132_211_811_359_523_575_799_353_416_465_883_426_318_681_613_016_771_856_031_686_932_947_271_317_419_547_861_320_644_294_073_546_214_321_361_245_588_222_429_356_422_579_589_512_434_099_189_282_561_422_126_611_592_192_445_638_395_200_306_602_306_031_474_495_398_876_927_483_244_443_369_593

    # credo:disable-for-lines:8 Credo.Check.Readability.MaxLineLength
    key =
      {:RSAPrivateKey, :"two-prime", modulus, 65_537, private_exponent,
       12_815_152_123_986_810_526_369_994_227_491_082_588_178_787_406_540_561_310_765_978_351_462_418_958_697_931_052_574_961_306_076_834_858_513_248_417_634_296_430_722_377_133_684_866_082_077_619_514_584_491_459,
       12_404_611_251_965_211_323_458_298_415_076_779_598_256_259_333_742_031_592_133_644_354_834_252_221_601_927_657_224_330_177_651_511_823_990_769_238_743_820_731_690_160_529_549_534_378_492_093_966_021_787_669,
       12_713_470_949_925_240_093_275_522_448_216_850_277_486_308_815_036_508_762_104_942_467_263_257_296_453_352_812_079_684_136_246_663_289_377_845_680_597_663_167_924_634_849_028_624_106_358_859_697_266_275_251,
       6_810_924_077_860_081_545_742_457_087_875_899_675_964_008_664_805_732_102_649_450_821_129_373_208_143_854_079_642_954_317_600_927_742_717_607_462_760_847_234_526_126_256_852_014_054_284_747_688_684_682_049,
       4_159_324_767_638_175_662_417_764_641_421_395_971_040_638_684_938_277_905_991_804_960_733_387_537_828_956_767_796_004_537_366_153_684_030_130_407_445_292_440_219_293_856_342_103_196_426_697_248_208_199_489,
       :asn1_NOVALUE}

    {key, cert_bin}
  end

  describe "verify/1" do
    test "valid SHA1 signature" do
      doc = parse_xml(@sha1_signed_xml)
      assert :ok = Dsig.verify(doc)
    end

    test "valid SHA256 signature" do
      # The cert base64 data contains newlines significant for the digest,
      # so we load from a fixture file to preserve them exactly.
      xml = File.read!(Path.join([__DIR__, "../../fixtures/sha256_signed_response.xml"]))
      doc = parse_xml(xml)
      assert :ok = Dsig.verify(doc)
    end
  end

  describe "verify/2" do
    test "with matching fingerprint" do
      doc = parse_xml(@sha1_signed_xml)

      fingerprint =
        <<198, 86, 10, 182, 119, 241, 20, 3, 198, 88, 35, 42, 145, 76, 251, 113, 52, 21, 246,
          156>>

      assert :ok = Dsig.verify(doc, [fingerprint])
    end

    test "unknown cert returns {:error, :cert_not_accepted}" do
      doc = parse_xml(@sha1_signed_xml)
      assert {:error, :cert_not_accepted} = Dsig.verify(doc, [<<198>>])
    end

    test "bad digest returns {:error, :bad_digest}" do
      doc = parse_xml(@bad_digest_xml)
      assert {:error, :bad_digest} = Dsig.verify(doc)
    end

    test "bad signature returns {:error, :bad_signature}" do
      doc = parse_xml(@bad_signature_xml)
      assert {:error, :bad_signature} = Dsig.verify(doc)
    end
  end

  describe "sign and verify roundtrip" do
    test "sign with SHA1 key and verify" do
      doc =
        parse_xml(
          ~S|<x:foo id="test" xmlns:x="urn:foo:x:"><x:name>blah</x:name></x:foo>|
        )

      {key, cert_bin} = test_sign_key()

      signed_xml =
        Dsig.sign(doc, key, cert_bin, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

      assert :ok = Dsig.verify(signed_xml, [:crypto.hash(:sha, cert_bin)])
    end

    test "sign with SHA256 key and verify" do
      doc =
        parse_xml(
          ~S|<x:foo id="test" xmlns:x="urn:foo:x:"><x:name>blah</x:name></x:foo>|
        )

      {key, cert_bin} = test_sign_256_key()
      signed_xml = Dsig.sign(doc, key, cert_bin, :rsa_sha256)

      assert :ok = Dsig.verify(signed_xml, [:crypto.hash(:sha, cert_bin)])
    end
  end

  describe "strip/1" do
    test "strip removes signature and returns original element" do
      doc =
        parse_xml(
          ~S|<x:foo id="test" xmlns:x="urn:foo:x:"><x:name>blah</x:name></x:foo>|
        )

      {key, cert_bin} = test_sign_key()

      signed_xml =
        Dsig.sign(doc, key, cert_bin, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

      stripped = Dsig.strip(signed_xml)
      assert stripped == doc
      assert signed_xml != doc
    end
  end

  describe "sign generates ID" do
    test "sign adds ID attribute when element has none" do
      doc =
        parse_xml(
          ~S|<x:foo xmlns:x="urn:foo:x:"><x:name>blah</x:name></x:foo>|
        )

      {key, cert_bin} = test_sign_key()

      signed_xml =
        Dsig.sign(doc, key, cert_bin, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

      ds_ns = [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}]

      [id_attr] = :xmerl_xpath.string(~c"@ID", signed_xml, namespace: ds_ns)
      root_id = xmlAttribute(id_attr, :value)
      assert is_list(root_id)
      assert root_id != []

      [uri_attr] =
        :xmerl_xpath.string(
          ~c"ds:Signature/ds:SignedInfo/ds:Reference/@URI",
          signed_xml,
          namespace: ds_ns
        )

      uri_value = xmlAttribute(uri_attr, :value)
      assert uri_value == [?# | root_id]
    end
  end
end
