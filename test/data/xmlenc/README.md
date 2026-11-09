# XML Encryption test vectors

Test vectors from third parties, to check `ExSaml.Core.Xml.Enc` against
ciphertexts ExSaml did not produce. Retrieved on 2026-11-09.

## `w3c/`: XML Encryption 1.1 test cases

Source: test cases of the W3C XML Security Working Group,
<https://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/>, key
transport section (WRAP.1 to WRAP.4), files contributed by Oracle under
`files/oracle/`. Copyright W3C, used under the
[W3C document license](https://www.w3.org/Consortium/Legal/copyright-documents)
the page refers to.

| Test case | File | Private key |
|---|---|---|
| WRAP.1 | `cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml` | RSA-2048 |
| WRAP.2 | `cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml` | RSA-3072 |
| WRAP.3 | `cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml` | RSA-3072 |
| WRAP.4 | `cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml` | RSA-4096 |

- The ciphertext files and `plaintext.xml` are unchanged.
- The private keys are published as PKCS#12 files, `RSA-<size>_SHA256WithRSA.p12`,
  protected by the password `passwd`. They are stored here as PEM, converted with:

  ```sh
  openssl pkcs12 -in RSA-2048_SHA256WithRSA.p12 -passin pass:passwd -nocerts -nodes \
    | openssl pkey -out RSA-2048_SHA256WithRSA.key.pem
  ```

The other test cases of the page (key agreement, key derivation, key wrapping
with AES-KW) use algorithms ExSaml does not support.

## `wycheproof/`: Wycheproof test vectors

Source: <https://github.com/C2SP/wycheproof>, `testvectors_v1/`, Apache License 2.0.
Each file names its source file and the filter applied. They were reduced with
`jq`, to keep only what XML Encryption uses and the fields the tests read:

| File | Source | Kept |
|---|---|---|
| `aes_gcm.json` | `aes_gcm_test.json` | groups with a 96-bit IV and a 128-bit tag, tests without AAD |
| `aes_cbc_pkcs5.json` | `aes_cbc_pkcs5_test.json` | all tests |
| `rsa_oaep_2048_<sha>_<mgf>.json` | `rsa_oaep_2048_<sha>_<mgf>_test.json` | all tests, private key as PEM only |

```sh
jq '{algorithm, source: "…", filter: "…", testGroups: [.testGroups[]
  | select(.ivSize == 96 and .tagSize == 128)
  | {keySize, tests: [.tests[] | select(.aad == "")
  | {tcId, comment, flags, key, iv, msg, ct, tag, result}]}]}' aes_gcm_test.json

jq '{algorithm, source: "…", filter: "…", testGroups: [.testGroups[]
  | {keySize, tests: [.tests[] | {tcId, comment, flags, key, iv, msg, ct, result}]}]}' \
  aes_cbc_pkcs5_test.json

jq '{algorithm, source: "…", filter: "…", testGroups: [.testGroups[]
  | {keySize, sha, mgfSha, privateKeyPem,
     tests: [.tests[] | {tcId, comment, flags, msg, ct, label, result}]}]}' \
  rsa_oaep_2048_sha256_mgf1sha256_test.json
```

Wycheproof's AES-CBC vectors use PKCS#7 padding, while XML Encryption only reads
the last byte of the padding (XML Encryption 1.1 §5.4.1): 45 of the 144 vectors
invalid for PKCS#7 (ANSI X.923 and ISO 10126 paddings, and PKCS#7 paddings with
inconsistent bytes) are valid XML Encryption paddings. The tests compute the
expected result of those vectors accordingly.
