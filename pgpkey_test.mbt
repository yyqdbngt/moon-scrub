///|
test "pgp and dsa private key blocks are detected" {
  let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQVYBF\ndF9D\ntest\n-----END PGP PRIVATE KEY BLOCK-----"
  let pgp_found = @moon_scrub.scan(
    pgp,
    policy=@moon_scrub.ScanPolicy::secrets_only(),
  )
  assert_eq(pgp_found.length(), 1)
  assert_eq(pgp_found[0].kind, @moon_scrub.PrivateKey)
  let dsa = "-----BEGIN DSA PRIVATE KEY-----\nMIIBug\ntest\n-----END DSA PRIVATE KEY-----"
  let dsa_found = @moon_scrub.scan(
    dsa,
    policy=@moon_scrub.ScanPolicy::secrets_only(),
  )
  assert_eq(dsa_found.length(), 1)
}
