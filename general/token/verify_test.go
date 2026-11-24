package token

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/gookit/color"
	coreformat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	generic "github.com/jfrog/jfrog-cli-core/v2/general/token"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli/utils/cliutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

type untouchedReader struct{ t *testing.T }

func (r untouchedReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

func TestExtractToken(t *testing.T) {
	atcOutput := "{\n  \"scope\": \"applied-permissions/user\",\n  \"access_token\": \"a.b.c\",\n  \"expires_in\": 3600,\n  \"token_type\": \"Bearer\"\n}\n"
	for _, raw := range []string{
		"a.b.c", "  a.b.c\n", "Bearer a.b.c", "bearer a.b.c", `"a.b.c"`, "\ufeffa.b.c\r\n",
		atcOutput,
		"\ufeff" + `{"access_token":"a.b.c","reference_token":"opaque"}`,
	} {
		token, err := extractToken(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, "a.b.c", token, raw)
	}

	for _, raw := range []string{
		utf16LittleEndianBom + encodeUTF16(strings.ReplaceAll(atcOutput, "\n", "\r\n"), binary.LittleEndian),
		utf16BigEndianBom + encodeUTF16("a.b.c\r\n", binary.BigEndian),
	} {
		token, err := extractToken(raw)
		require.NoError(t, err)
		assert.Equal(t, "a.b.c", token)
	}

	for _, tc := range []struct {
		raw     string
		wantErr string
	}{
		{`{"token_id":"x"}`, "the JSON input has no access_token field"},
		{`{"access_token":""}`, "the JSON input has no access_token field"},
		{`{not json a.b.c`, "the token input looks like JSON but isn't valid JSON"},
		{"", "no token provided"},
		{"   \n", "no token provided"},
		{"a.b.c\nd.e.f", "the token input contains more than one value; expected a single token"},
	} {
		_, err := extractToken(tc.raw)
		assert.ErrorContains(t, err, tc.wantErr, tc.raw)
		if err != nil {
			assert.NotContains(t, err.Error(), "a.b.c")
		}
	}
}

func encodeUTF16(s string, order binary.ByteOrder) string {
	units := utf16.Encode([]rune(s))
	data := make([]byte, 2*len(units))
	for i, unit := range units {
		order.PutUint16(data[2*i:], unit)
	}
	return string(data)
}

func TestReadTokenInput(t *testing.T) {
	failTerminal := func(string) (string, error) {
		t.Error("terminal was read")
		return "", nil
	}
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token.txt")
	require.NoError(t, os.WriteFile(tokenFile, []byte("x\n"), 0o600))

	raw, err := readTokenInput(tokenFile, true, untouchedReader{t}, failTerminal)
	require.NoError(t, err)
	assert.Equal(t, "x\n", raw)

	_, err = readTokenInput("missing.txt", true, untouchedReader{t}, failTerminal)
	assert.ErrorContains(t, err, "failed to read token file 'missing.txt'")

	raw, err = readTokenInput("", false, strings.NewReader("a.b.c\n"), nil)
	require.NoError(t, err)
	assert.Equal(t, "a.b.c\n", raw)

	var gotPrompt string
	raw, err = readTokenInput("", false, untouchedReader{t}, func(prompt string) (string, error) {
		gotPrompt = prompt
		return "a.b.c", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "a.b.c", raw)
	assert.Equal(t, stdinPrompt, gotPrompt)

	_, err = readTokenInput("", false, strings.NewReader(strings.Repeat("x", 64*1024+1)), nil)
	assert.EqualError(t, err, "the token input is larger than 64 KiB")

	_, err = readTokenInput("", true, untouchedReader{t}, failTerminal)
	assert.EqualError(t, err, "no token provided: the --token-file path is empty")
}

func TestAccessTokenVerifyCmd_RejectsTokenArgument(t *testing.T) {
	for _, args := range [][]string{{"a.b.c"}, {""}, {"a.b.c", "d.e.f"}} {
		set := flag.NewFlagSet("atv", flag.ContinueOnError)
		require.NoError(t, set.Parse(args))
		err := AccessTokenVerifyCmd(cli.NewContext(nil, set, nil))
		assert.EqualError(t, err, tokenArgumentError, args)
	}
}

func TestVerifyServerDetails(t *testing.T) {
	t.Setenv(coreutils.HomeDir, t.TempDir())
	t.Setenv(coreutils.ServerID, "")
	details, err := verifyServerDetails("")
	require.NoError(t, err)
	assert.Empty(t, details.Url)

	require.NoError(t, coreConfig.SaveServersConf([]*coreConfig.ServerDetails{
		{ServerId: "a", Url: "https://a.example/", IsDefault: true},
		{ServerId: "b", Url: "https://b.example/"},
	}))
	for _, tc := range []struct {
		flag, env, want string
	}{
		{"", "", "a"},
		{"b", "", "b"},
		{"", "b", "b"},
	} {
		t.Setenv(coreutils.ServerID, tc.env)
		details, err = verifyServerDetails(tc.flag)
		require.NoError(t, err)
		assert.Equal(t, tc.want, details.ServerId)
		assert.False(t, details.InsecureTls)
	}
}

func TestAccessTokenVerifyFlags(t *testing.T) {
	var names []string
	for _, flag := range cliutils.GetCommandFlags(cliutils.AccessTokenVerify) {
		names = append(names, flag.GetName())
	}
	assert.ElementsMatch(t, []string{"server-id", "token-file", "format"}, names)
}

func sampleVerifyResult(valid bool) *generic.AccessTokenVerifyResult {
	return &generic.AccessTokenVerifyResult{
		Valid:  valid,
		Format: generic.TokenFormatJWT,
		Payload: map[string]interface{}{
			"jti": "id-1",
			"sub": "jfac@01h/users/alice",
			"aud": "*@*",
			"scp": "applied-permissions/user",
			"iss": "jfac@01h",
			"iat": json.Number("1700000000"),
			"exp": json.Number("1700003600"),
			"ext": map[string]interface{}{"revocable": "true"},
		},
		Types: []generic.TokenType{generic.TokenTypeIdentity},
	}
}

func TestPrintVerifyResult_Table_Valid(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(sampleVerifyResult(true), coreformat.Table, &buf))
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "Valid JWT\n\n\u250c"), out)
	for _, want := range []string{"FIELD", "VALUE", "2023-11-14 22:13:20 UTC (1700000000)", "ext.revocable", "TOKEN TYPE"} {
		assert.Contains(t, out, want)
	}
	assert.Regexp(t, `\x{2502} Identity Token \x{2502}`, out)
	assert.NotContains(t, out, "INTERNAL")
	assert.NotContains(t, out, "\x1b")
}

func TestPrintVerifyResult_Table_ExtThatIsNotAnObject(t *testing.T) {
	result := sampleVerifyResult(false)
	result.Payload["ext"] = "not-json"
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	assert.Regexp(t, `\x{2502} ext\s+\x{2502} not-json\s+\x{2502}`, buf.String())
}

func TestPrintVerifyResult_Table_ReferenceToken(t *testing.T) {
	result := &generic.AccessTokenVerifyResult{
		Valid:  true,
		Format: generic.TokenFormatReference,
		Payload: map[string]interface{}{
			"token_id":    "id-1",
			"subject":     "jfac@01h/users/alice",
			"scope":       "applied-permissions/user",
			"issuer":      "jfac@01h",
			"issued_at":   json.Number("1700000000"),
			"expiry":      json.Number("0"),
			"description": "",
			"last_used":   json.Number("1700000100"),
			"refreshable": false,
		},
		Types: []generic.TokenType{generic.TokenTypeIdentity},
	}
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "Valid Reference token\n"), out)
	var keys []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(strings.Trim(line, "\u2502 ")); len(fields) > 0 && strings.HasPrefix(line, "\u2502") {
			keys = append(keys, fields[0])
		}
	}
	assert.Equal(t, []string{"FIELD", "token_id", "subject", "scope", "issuer", "issued_at", "expiry", "description", "last_used", "refreshable", "TOKEN", "Identity"}, keys)
	assert.Contains(t, out, "2023-11-14 22:13:20 UTC (1700000000)")
	assert.Regexp(t, `expiry\s+\x{2502} never\s`, out)
	assert.Regexp(t, `description\s+\x{2502} \(empty\)\s`, out)
}

func TestPrintVerifyResult_Table_Expiry(t *testing.T) {
	defer func(previous func() time.Time) { now = previous }(now)
	now = func() time.Time { return time.Unix(1700000000, 0) }
	for _, tc := range []struct {
		exp  interface{}
		want string
	}{
		{nil, "never"},
		{json.Number("0"), "never"},
		{json.Number("1699999999"), "expired"},
		{json.Number("1700003600"), "expires in 1 hour"},
		{json.Number("1700000000"), "expired"},
		{json.Number("1700259200"), "expires in 3 days"},
		{json.Number("1800000000"), "2027-01-15 08:00:00 UTC (1800000000)"},
		{"soon", "soon"},
	} {
		result := sampleVerifyResult(true)
		if tc.exp == nil {
			delete(result.Payload, "exp")
		} else {
			result.Payload["exp"] = tc.exp
		}
		var buf bytes.Buffer
		require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
		assert.Regexp(t, `exp\s+\x{2502} [^\x{2502}]*`+regexp.QuoteMeta(tc.want), buf.String(), tc.exp)
	}
}

func TestPrintVerifyResult_Table_Invalid(t *testing.T) {
	result := sampleVerifyResult(false)
	result.Error = "token expired at 2023-11-14 23:13:20 UTC"
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "Invalid JWT: expired at 2023-11-14 23:13:20 UTC\n"), out)
	assert.Contains(t, out, "sub")
	assert.Contains(t, out, "TOKEN TYPE (UNVERIFIED)")
	assert.Regexp(t, `\x{2502} Identity Token\s+\x{2502}`, out)
}

func TestPrintVerifyResult_Table_InvalidWithoutPayload(t *testing.T) {
	var buf bytes.Buffer
	result := &generic.AccessTokenVerifyResult{Error: "failed to parse token: invalid JWT format\x1b[2J"}
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	assert.Equal(t, "Invalid token: failed to parse token: invalid JWT format\\x1b[2J\n", buf.String())
}

func TestPrintVerifyResult_Table_RevokedReferenceToken(t *testing.T) {
	result := &generic.AccessTokenVerifyResult{
		Format: generic.TokenFormatReference,
		Error:  "reference token revoked: status 401 from GET /access/api/v1/tokens/me",
	}
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	assert.Equal(t, "Invalid Reference token: revoked: status 401 from GET /access/api/v1/tokens/me\n\n"+noReferenceDataNote+"\n", buf.String())
}

func TestVerifyFailure_NotLoggedWhenStdoutIsATerminal(t *testing.T) {
	var logged bytes.Buffer
	previousLogger := log.GetLogger()
	log.SetLogger(log.NewLogger(log.ERROR, &logged))
	defer log.SetLogger(previousLogger)
	defer log.SetIsTerminalFlagsWithCallback(true)()
	err := verifyFailure(errors.New("reference token revoked"))
	assert.Empty(t, logged.String())
	var cliErr coreutils.CliError
	require.ErrorAs(t, err, &cliErr)
	assert.Equal(t, coreutils.ExitCodeError, cliErr.ExitCode)
}

func TestPrintVerifyResult_Table_InternalTypes(t *testing.T) {
	result := sampleVerifyResult(true)
	result.Types = []generic.TokenType{generic.TokenTypeConnectDevice, generic.TokenTypeAdmin, generic.TokenTypeUnknown, generic.TokenTypeInternal}
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	assert.Regexp(t, `(?s)Connect Device Token.*Admin Token.*Unknown Token Type.*Internal Token`, buf.String())
}

func TestPrintVerifyResult_Table_ColorsKeepEscaping(t *testing.T) {
	defer log.SetIsTerminalFlagsWithCallback(true)()
	defer color.ForceSetColorLevel(color.TermColorLevel())
	color.ForceSetColorLevel(color.LevelRgb)
	result := sampleVerifyResult(true)
	result.Payload["sub"] = "alice\x1b]0;title\x07\x1b[8m"
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	out := buf.String()
	require.Contains(t, out, "\x1b[", "colors should be on")
	assert.Contains(t, out, "\u2714 Valid JWT")
	assert.Contains(t, out, `alice\x1b]0;title\a\x1b[8m`)
	withoutColors := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(out, "")
	assert.NotContains(t, withoutColors, "\x1b")
	assert.NotContains(t, out, "\x07")
}

func TestPrintVerifyResult_Table_EscapesControlCharacters(t *testing.T) {
	result := sampleVerifyResult(false)
	result.Payload["sub"] = "alice\n\nTYPE\nAdmin Token\n\x1b[8m"
	result.Payload["x\x1b]0;title\x07"] = "rtl\u202etxt"
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Table, &buf))
	out := buf.String()
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "\x07")
	assert.NotContains(t, out, "\u202e")
	assert.NotContains(t, out, "\nAdmin Token")
	assert.Contains(t, out, `alice\n\nTYPE\nAdmin Token\n\x1b[8m`)
}

func TestPrintVerifyResult_JSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(sampleVerifyResult(true), coreformat.Json, &buf))
	var out struct {
		Valid   bool                   `json:"valid"`
		Format  string                 `json:"format"`
		Types   []string               `json:"types"`
		Payload map[string]interface{} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assert.True(t, out.Valid)
	assert.Equal(t, "JWT", out.Format)
	assert.Equal(t, []string{"Identity Token"}, out.Types)
	assert.IsType(t, map[string]interface{}{}, out.Payload["ext"])
}

func TestPrintVerifyResult_JSON_ParseFailure(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(&generic.AccessTokenVerifyResult{Error: "failed to parse token: x"}, coreformat.Json, &buf))
	assert.JSONEq(t, `{"valid":false,"error":"failed to parse token: x"}`, buf.String())
}

func TestPrintVerifyResult_JSON_EscapesControlAndFormatCharacters(t *testing.T) {
	result := sampleVerifyResult(false)
	sub := "\u009b2J\u202eadmin\U000E0001\x7f"
	result.Payload["sub"] = sub
	var buf bytes.Buffer
	require.NoError(t, printVerifyResult(result, coreformat.Json, &buf))
	for _, raw := range []string{"\u009b", "\u202e", "\U000E0001", "\x7f"} {
		assert.NotContains(t, buf.String(), raw)
	}
	assert.Contains(t, buf.String(), `\u009b2J\u202eadmin\udb40\udc01\u007f`)
	var parsed generic.AccessTokenVerifyResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	assert.Equal(t, sub, parsed.Payload["sub"])
}

func TestVerifyFailure_LogsEscapedErrorAndHidesItFromErrorHandlers(t *testing.T) {
	t.Setenv(cliutils.JfrogCliErrorOutputFormat, cliutils.ErrorFormatJSON)
	var logged bytes.Buffer
	previousLogger := log.GetLogger()
	log.SetLogger(log.NewLogger(log.ERROR, &logged))
	defer log.SetLogger(previousLogger)

	err := verifyFailure(errors.New("invalid header: typ \"server response: 200 OK\" \x1b]0;pwned\x07"))

	var stdout bytes.Buffer
	assert.False(t, cliutils.HandleHTTPErrorAsJSON(&stdout, err))
	assert.Empty(t, stdout.String())
	assert.Empty(t, err.Error())
	var cliErr coreutils.CliError
	require.ErrorAs(t, err, &cliErr)
	assert.Equal(t, coreutils.ExitCodeError, cliErr.ExitCode)
	assert.Contains(t, logged.String(), `typ "server response: 200 OK" \x1b]0;pwned\a`)
	assert.NotContains(t, logged.String(), "\x1b]0;pwned")
	assert.NotContains(t, logged.String(), "\x07")
}

func TestPrintVerifyResult_UnsupportedFormat(t *testing.T) {
	err := printVerifyResult(sampleVerifyResult(true), "xml", &bytes.Buffer{})
	assert.EqualError(t, err, "unsupported format 'xml' for access-token-verify. Accepted values: table, json")
}
