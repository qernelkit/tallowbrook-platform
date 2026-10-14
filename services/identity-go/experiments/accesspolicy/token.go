// Package accesspolicy lexes the access-policy strings used for gated
// exports, such as
//
//	(dept: ops) and (region: eu)
//
// and rejects anything outside the small grammar before the policy is used.
package accesspolicy

import (
	"fmt"
	"strings"
	"text/scanner"
)

// Kind is a token kind.
type Kind int

const (
	KindIdent Kind = iota
	KindColon
	KindLParen
	KindRParen
	KindAnd
	KindOr
	KindNot
)

func (k Kind) String() string {
	return [...]string{"ident", "colon", "lparen", "rparen", "and", "or", "not"}[k]
}

type Token struct {
	Kind Kind
	Text string
	Pos  int
}

type lexer struct {
	s    *scanner.Scanner
	errs []string
}

// Lex splits a policy string into tokens.
func Lex(src string) ([]Token, error) {
	var sc scanner.Scanner
	sc.Init(strings.NewReader(src))
	sc.Mode = scanner.ScanIdents
	sc.IsIdentRune = func(ch rune, i int) bool {
		return ch == '_' || ch == '-' && i > 0 || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' && i > 0
	}
	l := &lexer{s: &sc}
	sc.Error = func(_ *scanner.Scanner, msg string) { l.errs = append(l.errs, msg) }
	var out []Token
	for {
		tok := l.s.Scan()
		if tok == scanner.EOF {
			break
		}
		pos := l.s.Position.Offset
		text := l.s.TokenText()
		switch {
		case tok == scanner.Ident && text == "and":
			out = append(out, Token{KindAnd, text, pos})
		case tok == scanner.Ident && text == "or":
			out = append(out, Token{KindOr, text, pos})
		case tok == scanner.Ident && text == "not":
			out = append(out, Token{KindNot, text, pos})
		case tok == scanner.Ident:
			out = append(out, Token{KindIdent, text, pos})
		case tok == ':':
			out = append(out, Token{KindColon, text, pos})
		case tok == '(':
			out = append(out, Token{KindLParen, text, pos})
		case tok == ')':
			out = append(out, Token{KindRParen, text, pos})
		default:
			return nil, fmt.Errorf("accesspolicy: unexpected %q at %d", text, pos)
		}
	}
	if len(l.errs) > 0 {
		return nil, fmt.Errorf("accesspolicy: %s", strings.Join(l.errs, "; "))
	}
	return out, balanced(out)
}

func balanced(toks []Token) error {
	depth := 0
	for _, t := range toks {
		switch t.Kind {
		case KindLParen:
			depth++
		case KindRParen:
			depth--
			if depth < 0 {
				return fmt.Errorf("accesspolicy: unmatched ) at %d", t.Pos)
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("accesspolicy: unclosed (")
	}
	return nil
}

// Normalise re-joins tokens with single spaces, in the form the export
// encryption expects.
func Normalise(toks []Token) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 && t.Kind != KindColon && t.Kind != KindRParen && toks[i-1].Kind != KindLParen {
			b.WriteByte(' ')
		}
		b.WriteString(t.Text)
	}
	return b.String()
}
