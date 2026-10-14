// Cookie sessions for the shipper web app, stored in Mongo so any gateway pod can
// serve any request.
import session from 'express-session';
import { config, secret } from '../config.js';

class MongoSessionStore extends session.Store {
  /**
   * @param {import('mongodb').Collection<any>} collection
   */
  constructor(collection) {
    super();
    this.collection = collection;
  }

  /** @type {session.Store['get']} */
  get(sid, callback) {
    this.collection
      .findOne({ _id: sid, expiresAt: { $gt: new Date() } })
      .then((doc) => callback(null, doc ? doc.data : null))
      .catch((err) => callback(err));
  }

  /** @type {session.Store['set']} */
  set(sid, data, callback) {
    const expiresAt = data.cookie?.expires ? new Date(data.cookie.expires) : new Date(Date.now() + 86_400_000);
    this.collection
      .updateOne({ _id: sid }, { $set: { data, expiresAt } }, { upsert: true })
      .then(() => callback?.())
      .catch((err) => callback?.(err));
  }

  /** @type {session.Store['destroy']} */
  destroy(sid, callback) {
    this.collection
      .deleteOne({ _id: sid })
      .then(() => callback?.())
      .catch((err) => callback?.(err));
  }

  /** @type {session.Store['touch']} */
  touch(sid, data, callback) {
    this.set(sid, data, callback);
  }
}

/**
 * @param {import('express').Express} app
 * @param {import('mongodb').Db} db
 */
export function installSessions(app, db) {
  app.use(
    session({
      name: config.session.cookieName,
      secret: secret('SESSION_COOKIE_SECRETS').split(','),
      store: new MongoSessionStore(db.collection('sessions')),
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: config.session.cookieMaxAgeMs },
    }),
  );
}
