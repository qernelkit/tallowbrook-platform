// A small tokenizer for help-centre articles. Articles use a subset of Markdown:
// headings, bullet lists, fenced code and paragraphs.

export type TokenKind = 'heading' | 'list' | 'code' | 'text';

export interface HelpToken {
  kind: TokenKind;
  level?: number;
  lines: string[];
}

class Lexer {
  private index = 0;
  constructor(private readonly lines: string[]) {}

  done(): boolean {
    return this.index >= this.lines.length;
  }

  next(): HelpToken | null {
    while (!this.done() && this.lines[this.index].trim() === '') this.index += 1;
    if (this.done()) return null;
    const line = this.lines[this.index];
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      this.index += 1;
      return { kind: 'heading', level: heading[1].length, lines: [heading[2]] };
    }
    if (line.startsWith('```')) {
      const body: string[] = [];
      this.index += 1;
      while (!this.done() && !this.lines[this.index].startsWith('```')) body.push(this.lines[this.index++]);
      this.index += 1;
      return { kind: 'code', lines: body };
    }
    if (/^[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (!this.done() && /^[-*]\s+/.test(this.lines[this.index])) items.push(this.lines[this.index++].replace(/^[-*]\s+/, ''));
      return { kind: 'list', lines: items };
    }
    const para: string[] = [];
    while (!this.done() && this.lines[this.index].trim() !== '' && !/^(#|```|[-*]\s)/.test(this.lines[this.index])) {
      para.push(this.lines[this.index++].trim());
    }
    return { kind: 'text', lines: [para.join(' ')] };
  }
}

export function tokenizeArticle(markdown: string): HelpToken[] {
  const lexer = new Lexer(markdown.replace(/\r\n/g, '\n').split('\n'));
  const tokens: HelpToken[] = [];
  for (;;) {
    const token = lexer.next();
    if (!token) break;
    tokens.push(token);
  }
  return tokens;
}
