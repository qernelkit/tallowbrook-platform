// Fields the gateway keeps in the server-side session.
import 'express-session';

declare module 'express-session' {
  interface SessionData {
    accountId: string;
    pendingAccountId: string;
    passkeyChallenge: string;
    supervisorId: string;
  }
}
