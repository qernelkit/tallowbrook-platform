//! Lexer for the auditor query language.

use logos::Logos;

#[derive(Logos, Debug, PartialEq)]
#[logos(skip r"[ \t\r\n]+")]
pub enum Token {
    #[token("account")]
    Account,
    #[token("period")]
    Period,
    #[token("status")]
    Status,
    #[token("branch")]
    Branch,
    #[token("amount")]
    Amount,
    #[token("signed")]
    Signed,
    #[token("held")]
    Held,
    #[token("posted")]
    Posted,
    #[token("AND")]
    And,
    #[token("OR")]
    Or,
    #[token("NOT")]
    Not,
    #[token(":")]
    Colon,
    #[token(">=")]
    AtLeast,
    #[token("<=")]
    AtMost,
    #[token("(")]
    Open,
    #[token(")")]
    Close,
    #[regex(r"[0-9]{4}-[0-9]{2}", |lex| lex.slice().to_owned())]
    Month(String),
    #[regex(r"[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Number(i64),
    #[regex(r"[a-z][a-z0-9-]*", |lex| lex.slice().to_owned())]
    Word(String),
}

/// Lexes a whole query, reporting the byte offset of the first character it cannot read.
pub fn lex(input: &str) -> Result<Vec<Token>, usize> {
    let mut lexer = Token::lexer(input);
    let mut out = Vec::new();
    while let Some(token) = lexer.next() {
        match token {
            Ok(t) => out.push(t),
            Err(()) => return Err(lexer.span().start),
        }
    }
    Ok(out)
}
