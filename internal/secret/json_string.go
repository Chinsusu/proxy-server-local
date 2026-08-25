package secret

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

// JSONBytes is a secret JSON field that never materializes its value as a Go
// string. Callers own and must Wipe Bytes on every completion path.
type JSONBytes struct{ Bytes []byte }

func (value *JSONBytes) UnmarshalJSON(raw []byte) error {
	decoded, err := DecodeJSONStringBytes(raw)
	if err != nil {
		return err
	}
	Wipe(value.Bytes)
	value.Bytes = decoded
	return nil
}

// DecodeJSONStringBytes parses exactly one JSON string without converting the
// plaintext to a Go string. null is rejected here; an optional *JSONBytes
// field keeps omitted/null compatibility at the enclosing DTO level.
func DecodeJSONStringBytes(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("secret: JSON value must be a string")
	}
	decoded := make([]byte, 0, len(raw)-2)
	fail := func() ([]byte, error) {
		Wipe(decoded)
		return nil, errors.New("secret: invalid JSON string")
	}
	for index := 1; index < len(raw)-1; index++ {
		character := raw[index]
		if character < 0x20 {
			return fail()
		}
		if character == '"' {
			return fail()
		}
		if character != '\\' {
			decoded = append(decoded, character)
			continue
		}
		index++
		if index >= len(raw)-1 {
			return fail()
		}
		switch escaped := raw[index]; escaped {
		case '"', '\\', '/':
			decoded = append(decoded, escaped)
		case 'b':
			decoded = append(decoded, '\b')
		case 'f':
			decoded = append(decoded, '\f')
		case 'n':
			decoded = append(decoded, '\n')
		case 'r':
			decoded = append(decoded, '\r')
		case 't':
			decoded = append(decoded, '\t')
		case 'u':
			if index+4 >= len(raw)-1 {
				return fail()
			}
			codePoint, ok := jsonHexCodePoint(raw[index+1 : index+5])
			if !ok {
				return fail()
			}
			index += 4
			if codePoint >= 0xD800 && codePoint <= 0xDBFF {
				if index+6 >= len(raw)-1 || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return fail()
				}
				low, valid := jsonHexCodePoint(raw[index+3 : index+7])
				if !valid || low < 0xDC00 || low > 0xDFFF {
					return fail()
				}
				codePoint = 0x10000 + ((codePoint - 0xD800) << 10) + (low - 0xDC00)
				index += 6
			} else if codePoint >= 0xDC00 && codePoint <= 0xDFFF {
				return fail()
			}
			decoded = utf8.AppendRune(decoded, rune(codePoint))
		default:
			return fail()
		}
	}
	if !utf8.Valid(decoded) || bytes.IndexByte(decoded, 0) >= 0 {
		return fail()
	}
	return decoded, nil
}

func jsonHexCodePoint(value []byte) (rune, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result rune
	for _, digit := range value {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result += rune(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result += rune(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			result += rune(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

// Wipe overwrites a mutable secret buffer. It intentionally accepts bytes,
// never a string.
func Wipe(value []byte) { wipe(value) }
