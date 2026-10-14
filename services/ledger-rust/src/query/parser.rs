//! Recursive-descent parser and evaluator for auditor queries.
//!
//! ```text
//! query  := and ("OR" and)*
//! and    := unary ("AND" unary)*
//! unary  := "NOT" unary | "(" query ")" | filter
//! filter := "account" ":" number | "period" ":" month | "status" ":" state
//!         | "branch" ":" word | "amount" (">=" | "<=") number
//! ```

use super::tokens::{Token, lex};
use crate::model::Period;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchState {
    Signed,
    Held,
    Posted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Account(u32),
    Period(Period),
    Status(BatchState),
    Branch(String),
    AmountAtLeast(i64),
    AmountAtMost(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Filter(Filter),
    And(Box<Query>, Box<Query>),
    Or(Box<Query>, Box<Query>),
    Not(Box<Query>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    #[error("unexpected character at offset {0}")]
    Lex(usize),
    #[error("unexpected end of query")]
    End,
    #[error("unexpected {0} at token {1}")]
    Unexpected(String, usize),
    #[error("{0} is not a valid period")]
    BadPeriod(String),
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Result<Token, QueryError> {
        if self.pos >= self.tokens.len() {
            return Err(QueryError::End);
        }
        let token = std::mem::replace(&mut self.tokens[self.pos], Token::Close);
        self.pos += 1;
        Ok(token)
    }

    fn unexpected(&self, token: &Token) -> QueryError {
        QueryError::Unexpected(format!("{token:?}"), self.pos)
    }

    fn expect(&mut self, wanted: Token) -> Result<(), QueryError> {
        let token = self.next()?;
        if token == wanted {
            Ok(())
        } else {
            Err(self.unexpected(&token))
        }
    }

    fn query(&mut self) -> Result<Query, QueryError> {
        let mut left = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.pos += 1;
            let right = self.and()?;
            left = Query::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Query, QueryError> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Token::And) {
            self.pos += 1;
            let right = self.unary()?;
            left = Query::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Query, QueryError> {
        match self.peek() {
            Some(Token::Not) => {
                self.pos += 1;
                Ok(Query::Not(Box::new(self.unary()?)))
            }
            Some(Token::Open) => {
                self.pos += 1;
                let inner = self.query()?;
                self.expect(Token::Close)?;
                Ok(inner)
            }
            _ => Ok(Query::Filter(self.filter()?)),
        }
    }

    fn filter(&mut self) -> Result<Filter, QueryError> {
        let field = self.next()?;
        if field == Token::Amount {
            let op = self.next()?;
            let value = match self.next()? {
                Token::Number(n) => n,
                other => return Err(self.unexpected(&other)),
            };
            return match op {
                Token::AtLeast => Ok(Filter::AmountAtLeast(value)),
                Token::AtMost => Ok(Filter::AmountAtMost(value)),
                other => Err(self.unexpected(&other)),
            };
        }
        self.expect(Token::Colon)?;
        let value = self.next()?;
        match (field, value) {
            (Token::Account, Token::Number(n)) => u32::try_from(n)
                .map(Filter::Account)
                .map_err(|_| QueryError::Unexpected(n.to_string(), self.pos)),
            (Token::Period, Token::Month(m)) => m
                .parse()
                .map(Filter::Period)
                .map_err(|_| QueryError::BadPeriod(m)),
            (Token::Status, Token::Signed) => Ok(Filter::Status(BatchState::Signed)),
            (Token::Status, Token::Held) => Ok(Filter::Status(BatchState::Held)),
            (Token::Status, Token::Posted) => Ok(Filter::Status(BatchState::Posted)),
            (Token::Branch, Token::Word(w)) => Ok(Filter::Branch(w)),
            (_, other) => Err(self.unexpected(&other)),
        }
    }
}

pub fn parse(input: &str) -> Result<Query, QueryError> {
    let tokens = lex(input).map_err(QueryError::Lex)?;
    let mut parser = Parser { tokens, pos: 0 };
    let query = parser.query()?;
    if parser.pos != parser.tokens.len() {
        return Err(QueryError::Unexpected("trailing input".into(), parser.pos));
    }
    Ok(query)
}

/// What the evaluator needs to know about a batch.
#[derive(Debug, Clone)]
pub struct BatchSummary {
    pub accounts: Vec<u32>,
    pub period: Period,
    pub state: BatchState,
    pub branch: String,
    pub largest_line_minor: i64,
}

pub fn matches(query: &Query, batch: &BatchSummary) -> bool {
    match query {
        Query::Filter(f) => match f {
            Filter::Account(a) => batch.accounts.contains(a),
            Filter::Period(p) => batch.period == *p,
            Filter::Status(s) => batch.state == *s,
            Filter::Branch(b) => batch.branch == *b,
            Filter::AmountAtLeast(n) => batch.largest_line_minor >= *n,
            Filter::AmountAtMost(n) => batch.largest_line_minor <= *n,
        },
        Query::And(l, r) => matches(l, batch) && matches(r, batch),
        Query::Or(l, r) => matches(l, batch) || matches(r, batch),
        Query::Not(q) => !matches(q, batch),
    }
}
