package token

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/jedib0t/go-pretty/v6/table"
	commonCliUtils "github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	"github.com/jfrog/jfrog-cli-core/v2/common/commands"
	coreformat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	generic "github.com/jfrog/jfrog-cli-core/v2/general/token"
	coreConfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli/utils/cliutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/urfave/cli"
)

const (
	stdinPrompt          = "Reading the access token from stdin. Paste it and press Enter (input is hidden): "
	maxTokenInput        = 64 * 1024
	utf8Bom              = "\xef\xbb\xbf"
	utf16LittleEndianBom = "\xff\xfe"
	utf16BigEndianBom    = "\xfe\xff"
	maxValueWidth        = 80
	expiryWarningWindow  = 7 * 24 * time.Hour
	tokenArgumentError   = "the token can't be passed as an argument, because arguments are visible to other processes and kept in shell history. Pass it with --token-file=<path> or on stdin"
)

var (
	orderedClaims       = []string{"jti", "sub", "aud", "scp", "iss", "iat", "exp"}
	orderedTokenDetails = []string{"token_id", "subject", "scope", "issuer", "issued_at", "expiry"}
	epochFields         = map[string]bool{"iat": true, "issued_at": true, "last_used": true}
	expiryFields        = map[string]bool{"exp": true, "expiry": true}
	internalTypes       = map[generic.TokenType]bool{generic.TokenTypeInternal: true, generic.TokenTypeConnectPairing: true, generic.TokenTypeConnectDevice: true}
	now                 = time.Now
)

func AccessTokenVerifyCmd(c *cli.Context) error {
	if c.NArg() > 0 {
		return errorutils.CheckErrorf(tokenArgumentError)
	}
	outputFormat, err := commonCliUtils.GetOutputFormat(c, coreformat.Table)
	if err != nil {
		return err
	}
	if outputFormat != coreformat.Table && outputFormat != coreformat.Json {
		return unsupportedVerifyFormat(outputFormat)
	}
	serverDetails, err := verifyServerDetails(c.String("server-id"))
	if err != nil {
		return err
	}
	raw, err := readTokenInput(c.String(cliutils.TokenFile), c.IsSet(cliutils.TokenFile), os.Stdin, terminalReader())
	if err != nil {
		return err
	}
	tokenUnderInvestigation, err := extractToken(raw)
	if err != nil {
		return err
	}

	verifyCmd := generic.NewAccessTokenVerifyCommand().SetServerDetails(serverDetails).SetToken(tokenUnderInvestigation)
	verifyErr := commands.Exec(verifyCmd)
	printErr := printVerifyResult(verifyCmd.Result(), outputFormat, os.Stdout)
	if verifyErr != nil {
		verifyErr = verifyFailure(verifyErr)
	}
	return errors.Join(verifyErr, printErr)
}

func verifyFailure(verifyErr error) error {
	log.Error(escapeControlCharacters(verifyErr.Error()))
	return coreutils.CliError{ExitCode: coreutils.ExitCodeError}
}

func verifyServerDetails(serverIdFlag string) (*coreConfig.ServerDetails, error) {
	serverId := serverIdFlag
	if serverId == "" {
		serverId = os.Getenv(coreutils.ServerID)
	}
	return commands.GetConfig(serverId, true)
}

func readTokenInput(tokenFile string, tokenFileSet bool, stdin io.Reader, readTerminal func(prompt string) (string, error)) (string, error) {
	switch {
	case tokenFileSet && strings.TrimSpace(tokenFile) == "":
		return "", errorutils.CheckErrorf("no token provided: the --token-file path is empty")
	case tokenFileSet:
		file, err := os.Open(tokenFile)
		if err != nil {
			return "", errorutils.CheckErrorf("failed to read token file '%s': %s", tokenFile, err.Error())
		}
		defer func() { _ = file.Close() }()
		return readLimited(file)
	case readTerminal != nil:
		return readTerminal(stdinPrompt)
	default:
		return readLimited(stdin)
	}
}

func readLimited(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxTokenInput+1))
	if err != nil {
		return "", errorutils.CheckError(err)
	}
	if len(data) > maxTokenInput {
		return "", errorutils.CheckErrorf("the token input is larger than 64 KiB")
	}
	return string(data), nil
}

func extractToken(raw string) (string, error) {
	input := strings.TrimSpace(strings.TrimPrefix(decodeUTF16(raw), utf8Bom))
	var tokenValue string
	if strings.HasPrefix(input, "{") {
		var atcOutput struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal([]byte(input), &atcOutput); err != nil {
			return "", errorutils.CheckErrorf("the token input looks like JSON but isn't valid JSON: %s", jsonErrorWithoutInput(err))
		}
		if atcOutput.AccessToken == "" {
			return "", errorutils.CheckErrorf("the JSON input has no access_token field")
		}
		tokenValue = strings.TrimSpace(atcOutput.AccessToken)
	} else {
		tokenValue = stripTokenDecorations(input)
	}
	if tokenValue == "" {
		return "", errorutils.CheckErrorf("no token provided: pass it with --token-file=<path> or on stdin")
	}
	if strings.ContainsAny(tokenValue, " \t\r\n") {
		return "", errorutils.CheckErrorf("the token input contains more than one value; expected a single token")
	}
	return tokenValue, nil
}

func decodeUTF16(raw string) string {
	var order binary.ByteOrder
	switch {
	case strings.HasPrefix(raw, utf16LittleEndianBom):
		order = binary.LittleEndian
	case strings.HasPrefix(raw, utf16BigEndianBom):
		order = binary.BigEndian
	default:
		return raw
	}
	data := raw[2:]
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16([]byte(data[i:i+2])))
	}
	return string(utf16.Decode(units))
}

func stripTokenDecorations(input string) string {
	if len(input) >= 2 && strings.HasPrefix(input, `"`) && strings.HasSuffix(input, `"`) {
		input = input[1 : len(input)-1]
	}
	if len(input) >= 7 && strings.EqualFold(input[:7], "bearer ") {
		input = input[7:]
	}
	return strings.TrimSpace(input)
}

func jsonErrorWithoutInput(err error) string {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Sprintf("syntax error at byte %d", syntaxErr.Offset)
	}
	return "unexpected structure"
}

func escapeJSONControlCharacters(data string) string {
	var b strings.Builder
	for _, r := range data {
		if r < 0x7f || !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) {
			b.WriteRune(r)
			continue
		}
		if r1, r2 := utf16.EncodeRune(r); r1 != unicode.ReplacementChar {
			_, _ = fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			continue
		}
		_, _ = fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

func unsupportedVerifyFormat(outputFormat coreformat.OutputFormat) error {
	return errorutils.CheckErrorf("unsupported format '%s' for access-token-verify. Accepted values: table, json", outputFormat)
}

func printVerifyResult(result *generic.AccessTokenVerifyResult, outputFormat coreformat.OutputFormat, w io.Writer) error {
	switch outputFormat {
	case coreformat.Json:
		if result == nil {
			return nil
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return errorutils.CheckError(err)
		}
		_, err = fmt.Fprintln(w, escapeJSONControlCharacters(string(data)))
		return errorutils.CheckError(err)
	case coreformat.Table:
		return printVerifyTable(result, w)
	default:
		return unsupportedVerifyFormat(outputFormat)
	}
}

func printVerifyTable(result *generic.AccessTokenVerifyResult, w io.Writer) error {
	if result == nil {
		return nil
	}
	sections := []string{verdictLine(result)}
	if result.Payload != nil {
		fields := newVerifyTable("FIELD", "VALUE")
		fields.SetColumnConfigs([]table.ColumnConfig{{Number: 2, WidthMax: maxValueWidth}})
		for _, row := range payloadRows(result.Payload, result.Format) {
			fields.AppendRow(table.Row{row.key, row.value})
		}
		sections = append(sections, fields.Render())
	}
	if result.Valid {
		types := newVerifyTable("TOKEN TYPE", "INTERNAL")
		for _, tokenType := range result.Types {
			types.AppendRow(typeRow(tokenType))
		}
		sections = append(sections, types.Render())
	}
	_, err := fmt.Fprintln(w, strings.Join(sections, "\n\n"))
	return errorutils.CheckError(err)
}

func newVerifyTable(headers ...interface{}) table.Writer {
	tw := table.NewWriter()
	tw.SetStyle(table.StyleLight)
	tw.AppendHeader(headers)
	return tw
}

func verdictLine(result *generic.AccessTokenVerifyResult) string {
	subject := "token"
	if result.Format == generic.TokenFormatJWT {
		subject = "JWT"
	} else if result.Format != "" {
		subject = string(result.Format) + " token"
	}
	if result.Valid {
		return strings.TrimSpace(coreutils.PrintBold(coreutils.PrintGreen("\u2714 Valid " + subject)))
	}
	line := strings.TrimSpace(coreutils.PrintBold(coreutils.PrintRed("\u2716 Invalid " + subject)))
	if result.Error != "" {
		line += ": " + escapeControlCharacters(result.Error)
	}
	return line
}

func typeRow(tokenType generic.TokenType) table.Row {
	name := string(tokenType)
	if tokenType == generic.TokenTypeUnknown {
		name = coreutils.PrintComment(name)
	}
	internal := "No"
	if internalTypes[tokenType] {
		internal = coreutils.PrintYellow("Yes")
	}
	return table.Row{name, internal}
}

type fieldRow struct {
	key, value string
}

func payloadRows(payload map[string]interface{}, format generic.TokenFormat) []fieldRow {
	ordered := orderedClaims
	if format == generic.TokenFormatReference {
		ordered = orderedTokenDetails
	}
	var rows []fieldRow
	for _, key := range ordered {
		value, ok := payload[key]
		switch {
		case key == "exp" && !ok:
			rows = append(rows, fieldRow{fieldName(key), formatExpiry(nil)})
		case ok:
			rows = append(rows, fieldRow{fieldName(key), formatValue(key, value)})
		}
	}
	for _, key := range sortedKeys(payload) {
		if key == "ext" || slices.Contains(ordered, key) {
			continue
		}
		rows = append(rows, fieldRow{fieldName(key), formatValue(key, payload[key])})
	}
	switch ext := payload["ext"].(type) {
	case nil:
	case map[string]interface{}:
		for _, key := range sortedKeys(ext) {
			rows = append(rows, fieldRow{coreutils.PrintComment("ext.") + fieldName(key), plainValue(formatClaim(ext[key]))})
		}
	default:
		rows = append(rows, fieldRow{fieldName("ext"), plainValue(formatClaim(ext))})
	}
	return rows
}

func fieldName(key string) string {
	return coreutils.PrintBold(escapeControlCharacters(key))
}

func plainValue(value string) string {
	if value == "" {
		return coreutils.PrintComment("(empty)")
	}
	return escapeControlCharacters(value)
}

func escapeControlCharacters(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			quoted := strconv.QuoteRune(r)
			b.WriteString(quoted[1 : len(quoted)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func formatValue(key string, value interface{}) string {
	switch {
	case expiryFields[key]:
		return formatExpiry(value)
	case epochFields[key]:
		return formatEpoch(value)
	default:
		return plainValue(formatClaim(value))
	}
}

func parseEpoch(value interface{}) (int64, bool) {
	epoch, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
	return epoch, err == nil
}

func formatEpoch(value interface{}) string {
	epoch, ok := parseEpoch(value)
	if !ok || epoch <= 0 {
		return plainValue(formatClaim(value))
	}
	return epochDate(epoch) + " " + epochNumber(epoch)
}

func formatExpiry(value interface{}) string {
	if value == nil {
		return "never"
	}
	epoch, ok := parseEpoch(value)
	switch {
	case ok && epoch == 0:
		return "never"
	case !ok || epoch < 0:
		return plainValue(formatClaim(value))
	}
	left := time.Unix(epoch, 0).Sub(now())
	switch {
	case left <= 0:
		return coreutils.PrintRed(epochDate(epoch)) + " " + epochNumber(epoch) + " " + coreutils.PrintRed("expired")
	case left < expiryWarningWindow:
		return coreutils.PrintYellow(epochDate(epoch)) + " " + epochNumber(epoch) + " " + coreutils.PrintYellow("expires in "+remaining(left))
	default:
		return epochDate(epoch) + " " + epochNumber(epoch)
	}
}

func epochDate(epoch int64) string {
	return time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

func epochNumber(epoch int64) string {
	return coreutils.PrintComment(fmt.Sprintf("(%d)", epoch))
}

func remaining(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return countOf(int(d/(24*time.Hour)), "day")
	case d >= time.Hour:
		return countOf(int(d/time.Hour), "hour")
	default:
		return countOf(int(d/time.Minute), "minute")
	}
}

func countOf(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func formatClaim(value interface{}) string {
	if values, ok := value.([]interface{}); ok {
		parts := make([]string, 0, len(values))
		for _, v := range values {
			parts = append(parts, fmt.Sprint(v))
		}
		return strings.Join(parts, ", ")
	}
	if nested, ok := value.(map[string]interface{}); ok {
		data, err := json.Marshal(nested)
		if err == nil {
			return string(data)
		}
	}
	return fmt.Sprint(value)
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
