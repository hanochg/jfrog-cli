package tokenverify

var Usage = []string{"atv", "atv --token-file=<path>"}

func GetDescription() string {
	return `Verifies a JFrog access token, JWT or reference. A JWT's signature and expiry are checked locally first. The configured JFrog server is then asked whether it accepts the token, and the token's format and type are reported.`
}

func GetAIDescription() string {
	return `Verify a JFrog Platform access token, JWT or reference, and report its format and what kind of token it is. For a JWT, the signature is checked against the configured server's root certificate and the claims and expiry are validated. The server's GET /access/api/v1/tokens/me endpoint is then called with the token, and only a token the server accepts is valid. A value without dots isn't shaped like a JWT, so it's sent to that endpoint as a possible reference token, and its details come from the server.

When to use:
- Checking whether a token is still valid before using it in CI.
- Finding out what kind of token you were given: a JWT or a reference token, and its types (identity, admin, groups, roles, entitlements, scoped, internal, Connect or Mission Control pairing).
- Debugging authentication failures caused by an expired, revoked or foreign token.

Prerequisites:
- A server configured with jf config add or jf login. Its credentials are never used to verify the token, and its tokens are never refreshed.

Common patterns:
  $ jf atv                                                 # paste the token at the hidden prompt
  $ jf atc | jf atv                                        # verify a freshly minted token
  $ jf atc --reference | jq -r .reference_token | jf atv   # verify a reference token
  $ jf atv --token-file=token.txt                          # read the token from a file
  $ jf atv --token-file=token.txt --format=json | jq .types

Gotchas:
- The token can't be passed as an argument, because arguments are visible to other processes and kept in shell history. Use stdin or --token-file.
- Without --token-file, the token is read from stdin. In a terminal, it prompts and waits without echoing the input. The prompt reads a single line: if the pasted text has more lines, it's all discarded, so pass multi-line input such as jf atc's JSON with --token-file or through a pipe. Terminals that can't hide input, such as Git Bash's, need --token-file or a pipe.
- Only configured servers can be used. There's no --insecure-tls: trust a private CA by adding it to ~/.jfrog/security/certs. http:// servers work, but print a warning.
- A value without dots isn't shaped like a JWT, so it's treated as a reference token and sent to the server as is. A 401 from the server is reported as a revoked token (Access answers the same way for a value that was never a token). Only the server knows a reference token's details, so a revoked one has no data to show. A value with dots that doesn't parse as a JWT fails locally and is never sent.
- JSON input is read for its access_token value, so to verify the reference token from jf atc --reference output, extract reference_token first.
- The types come from the token's scopes only, one per kind of scope, so a token can have several. Quoted scopes and the legacy member-of-groups: and api:* scopes are recognized.
- A token with a scope starting with internal: has Internal Token among its types. Connect pairing, Connect device and Mission Control pairing scopes are also reported by name.
- A JWT is sent to the server only after its signature checks out.
- --format=json output has a format field: JWT or Reference. For a reference token, the payload is the token details the server returned.
- The exit code is 1 when the token is invalid. The payload and the types its scopes claim are printed even when the token is invalid; the table then marks the types as unverified.

Related: jf atc, jf eot

QA:
Q: How do I check whether a JFrog access token is still valid?
A: Run jf atv and paste the token at the prompt, or use jf atv --token-file=<path>

Q: How do I verify the token that jf atc just created and get JSON output?
A: jf atc | jf atv --format=json
`
}
