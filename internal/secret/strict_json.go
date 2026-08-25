package secret

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// These bounds keep unauthenticated, 1 MiB request bodies from consuming
// unbounded stack, map allocation, or scanner CPU. They intentionally leave
// substantial headroom for the small control-plane DTOs.
const (
	strictJSONMaxDepth   = 32
	strictJSONMaxTokens  = 4096
	strictJSONMaxMembers = 2048
)

// StrictJSONObject parses a caller-owned JSON object without Decoder/Token
// buffers. It returns slices into body (not copies), rejects unknown fields
// and case-folded duplicate aliases, and validates nested JSON syntax.
func StrictJSONObject(body []byte, allowed []string) (map[string][]byte, error) {
	permit := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		permit[strings.ToLower(field)] = struct{}{}
	}
	p := strictJSONParser{body: body}
	fields, err := p.object(permit, true)
	if err != nil || p.skip() != len(body) {
		return nil, fmt.Errorf("secret: invalid JSON object")
	}
	return fields, nil
}

type strictJSONParser struct {
	body    []byte
	pos     int
	depth   int
	tokens  int
	members int
}

func (p *strictJSONParser) token() error {
	p.tokens++
	if p.tokens > strictJSONMaxTokens {
		return fmt.Errorf("token budget")
	}
	return nil
}

func (p *strictJSONParser) enterContainer() error {
	if err := p.token(); err != nil {
		return err
	}
	p.depth++
	if p.depth > strictJSONMaxDepth {
		return fmt.Errorf("depth budget")
	}
	return nil
}

func (p *strictJSONParser) skip() int {
	for p.pos < len(p.body) && (p.body[p.pos] == ' ' || p.body[p.pos] == '\n' || p.body[p.pos] == '\r' || p.body[p.pos] == '\t') {
		p.pos++
	}
	return p.pos
}
func (p *strictJSONParser) object(allowed map[string]struct{}, root bool) (map[string][]byte, error) {
	p.skip()
	if p.pos >= len(p.body) || p.body[p.pos] != '{' {
		return nil, fmt.Errorf("object")
	}
	if err := p.enterContainer(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.pos++
	seen := map[string]struct{}{}
	values := map[string][]byte{}
	p.skip()
	if p.pos < len(p.body) && p.body[p.pos] == '}' {
		p.pos++
		return values, nil
	}
	for {
		p.skip()
		p.members++
		if p.members > strictJSONMaxMembers {
			return nil, fmt.Errorf("member budget")
		}
		start, end, err := p.stringEnd()
		if err != nil {
			return nil, err
		}
		keyBytes, err := DecodeJSONStringBytes(p.body[start:end])
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(string(keyBytes))
		Wipe(keyBytes)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate")
		}
		seen[key] = struct{}{}
		if root {
			if _, ok := allowed[key]; !ok {
				return nil, fmt.Errorf("unknown")
			}
		}
		p.skip()
		if p.pos >= len(p.body) || p.body[p.pos] != ':' {
			return nil, fmt.Errorf("colon")
		}
		p.pos++
		p.skip()
		valueStart := p.pos
		if err := p.value(); err != nil {
			return nil, err
		}
		if root {
			values[key] = p.body[valueStart:p.pos]
		}
		p.skip()
		if p.pos >= len(p.body) {
			return nil, fmt.Errorf("end")
		}
		if p.body[p.pos] == '}' {
			p.pos++
			return values, nil
		}
		if p.body[p.pos] != ',' {
			return nil, fmt.Errorf("comma")
		}
		p.pos++
	}
}
func (p *strictJSONParser) value() error {
	p.skip()
	if p.pos >= len(p.body) {
		return fmt.Errorf("value")
	}
	switch p.body[p.pos] {
	case '{':
		_, err := p.object(nil, false)
		return err
	case '[':
		if err := p.enterContainer(); err != nil {
			return err
		}
		defer func() { p.depth-- }()
		p.pos++
		p.skip()
		if p.pos < len(p.body) && p.body[p.pos] == ']' {
			p.pos++
			return nil
		}
		for {
			if err := p.value(); err != nil {
				return err
			}
			p.skip()
			if p.pos >= len(p.body) {
				return fmt.Errorf("array")
			}
			if p.body[p.pos] == ']' {
				p.pos++
				return nil
			}
			if p.body[p.pos] != ',' {
				return fmt.Errorf("array")
			}
			p.pos++
		}
	case '"':
		_, _, err := p.stringEnd()
		return err
	default:
		start := p.pos
		for p.pos < len(p.body) && !strings.ContainsRune(" \t\r\n,]}", rune(p.body[p.pos])) {
			p.pos++
		}
		if start == p.pos {
			return fmt.Errorf("atom")
		}
		atom := p.body[start:p.pos]
		if err := p.token(); err != nil {
			return err
		}
		if string(atom) != "true" && string(atom) != "false" && string(atom) != "null" && !validJSONNumber(atom) {
			return fmt.Errorf("atom")
		}
		return nil
	}
}
func (p *strictJSONParser) stringEnd() (int, int, error) {
	if p.pos >= len(p.body) || p.body[p.pos] != '"' {
		return 0, 0, fmt.Errorf("string")
	}
	if err := p.token(); err != nil {
		return 0, 0, err
	}
	start := p.pos
	p.pos++
	for p.pos < len(p.body) {
		c := p.body[p.pos]
		if c == '"' {
			p.pos++
			return start, p.pos, nil
		}
		if c < 0x20 {
			return 0, 0, fmt.Errorf("control")
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.body) {
				return 0, 0, fmt.Errorf("escape")
			}
			if p.body[p.pos] == 'u' {
				if p.pos+4 >= len(p.body) {
					return 0, 0, fmt.Errorf("unicode")
				}
				for _, h := range p.body[p.pos+1 : p.pos+5] {
					if !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
						return 0, 0, fmt.Errorf("unicode")
					}
				}
				p.pos += 5
				continue
			}
			if !strings.ContainsRune(`"\\/bfnrt`, rune(p.body[p.pos])) {
				return 0, 0, fmt.Errorf("escape")
			}
			p.pos++
			continue
		}
		if c >= 0x80 {
			_, size := utf8.DecodeRune(p.body[p.pos:])
			if size == 1 {
				return 0, 0, fmt.Errorf("utf8")
			}
			p.pos += size
			continue
		}
		p.pos++
	}
	return 0, 0, fmt.Errorf("string")
}
func validJSONNumber(value []byte) bool { // strconv is deliberately avoided so only JSON grammar is accepted.
	i := 0
	if value[i] == '-' {
		i++
		if i == len(value) {
			return false
		}
	}
	if value[i] == '0' {
		i++
	} else if value[i] >= '1' && value[i] <= '9' {
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
	} else {
		return false
	}
	if i < len(value) && value[i] == '.' {
		i++
		start := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	if i < len(value) && (value[i] == 'e' || value[i] == 'E') {
		i++
		if i < len(value) && (value[i] == '+' || value[i] == '-') {
			i++
		}
		start := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	return i == len(value)
}
