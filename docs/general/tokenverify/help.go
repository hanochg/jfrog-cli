package tokenverify

var Usage = []string{"atv", "atv --token-file=<path>"}

func GetDescription() string {
	return `Verifies a JFrog access token: checks its format and signature, checks that it has not expired, asks the configured JFrog server whether it is still accepted, and reports its type.`
}

func GetAIDescription() string {
	return `Verify a JFrog Platform access token and report what kind of token it is. The token's signature is checked against the configured server's root certificate, its claims and expiry are validated, and the server's Access readiness endpoint is asked whether it still accepts the token.

When to use:
- Checking whether a token is still valid before using it in CI.
- Finding out what kind of token you were given (identity, admin, groups, roles, scoped or Connect).
- Debugging authentication failures caused by an expired, revoked or foreign token.

Prerequisites:
- A server configured with jf config add or jf login. Its credentials are never used to verify the token, and its tokens are never refreshed.

Common patterns:
  $ jf atv                                                 # paste the token at the hidden prompt
  $ jf atc | jf atv                                        # verify a freshly minted token
  $ jf atv --token-file=token.txt                          # read the token from a file
  $ jf atv --token-file=token.txt --format=json | jq .types

Gotchas:
- The token can't be passed as an argument, because arguments are visible to other processes and kept in shell history. Use stdin or --token-file.
- Without --token-file, the token is read from stdin. In a terminal, it prompts and waits without echoing the input.
- JSON input is read for its access_token value.
- Only configured servers can be used. There's no --insecure-tls: trust a private CA by adding it to ~/.jfrog/security/certs. http:// servers work, but print a warning.
- Reference tokens can't be verified; verify the JWT access token instead.
- Internal tokens are reported as Internal Token, except Connect pairing and device tokens, which are reported by name.
- The token is sent to the server only after its signature checks out.
- The exit code is 1 when the token is invalid. The payload is printed even when the token is invalid.

Related: jf atc, jf eot

QA:
Q: How do I check whether a JFrog access token is still valid?
A: Run jf atv and paste the token at the prompt, or use jf atv --token-file=<path>

Q: How do I verify the token that jf atc just created and get JSON output?
A: jf atc | jf atv --format=json
`
}
