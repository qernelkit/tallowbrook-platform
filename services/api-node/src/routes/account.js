import { Router } from 'express';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { config } from '../config.js';
import { passkeyRegistrationOptions, labelIsFree } from '../auth/passkeys.js';
import { checkPassword, hashPassword, passwordProblems } from '../auth/passwords.js';
import { generateRecoveryCodes, redeemRecoveryCode } from '../auth/recoveryCodes.js';
import { issueSessionToken, sessionTokenAuth } from '../auth/sessionTokens.js';
import { checkAuthenticatorCode, startAuthenticatorEnrolment } from '../auth/totp.js';
import { asyncHandler, badRequest, unauthorized } from '../middleware/errors.js';
import { childLogger } from '../logger.js';
import { collection } from '../db/collections.js';

const log = childLogger('account');
const LOCKOUT_AFTER = 8;

/**
 * @param {import('mongodb').Db} db
 */
export function accountRoutes(db) {
  const router = Router();
  const accounts = collection(db, 'accounts');

  router.post(
    '/login',
    asyncHandler(async (req, res) => {
      const email = String(req.body?.email ?? '')
        .trim()
        .toLowerCase();
      const password = String(req.body?.password ?? '');
      const account = await accounts.findOne({ email });
      if (!account || account.failedLogins >= LOCKOUT_AFTER) throw unauthorized('login_failed');
      const { ok, rehash } = await checkPassword(account.credential, password);
      if (!ok) {
        await accounts.updateOne({ _id: account._id }, { $inc: { failedLogins: 1 } });
        throw unauthorized('login_failed');
      }
      const update = { failedLogins: 0, lastLoginAt: new Date() };
      if (rehash) update.credential = { scheme: 'argon2', hash: await hashPassword(password) };
      await accounts.updateOne({ _id: account._id }, { $set: update });
      if (account.authenticator?.confirmedAt) {
        req.session.pendingAccountId = String(account._id);
        res.json({ next: 'authenticator' });
        return;
      }
      req.session.accountId = String(account._id);
      res.json({ token: issueSessionToken(req.sessionID, String(account._id)) });
    }),
  );

  router.post(
    '/login/authenticator',
    asyncHandler(async (req, res) => {
      const pending = req.session.pendingAccountId;
      if (!pending) throw unauthorized();
      const account = await accounts.findOne({ _id: pending });
      const code = String(req.body?.code ?? '');
      let ok = await checkAuthenticatorCode(account.authenticator, code);
      if (!ok && code.length > 6) {
        const index = await redeemRecoveryCode(account.recoveryCodes ?? [], code);
        if (index >= 0) {
          await accounts.updateOne({ _id: account._id }, { $set: { [`recoveryCodes.${index}`]: null } });
          ok = true;
        }
      }
      if (!ok) throw unauthorized('second_factor_failed');
      delete req.session.pendingAccountId;
      req.session.accountId = String(account._id);
      res.json({ token: issueSessionToken(req.sessionID, String(account._id)) });
    }),
  );

  router.post(
    '/password',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const problems = passwordProblems(String(req.body?.newPassword ?? ''));
      if (problems.length) throw badRequest('password_rejected', { newPassword: problems.join('; ') });
      const account = await accounts.findOne({ _id: res.locals.session.sub });
      const { ok } = await checkPassword(account.credential, String(req.body?.currentPassword ?? ''));
      if (!ok) throw unauthorized('current_password_wrong');
      await accounts.updateOne(
        { _id: account._id },
        { $set: { credential: { scheme: 'argon2', hash: await hashPassword(req.body.newPassword) }, passwordChangedAt: new Date() } },
      );
      log.info({ accountId: String(account._id) }, 'password changed');
      res.status(204).end();
    }),
  );

  router.post(
    '/authenticator',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const account = await accounts.findOne({ _id: res.locals.session.sub });
      const { enrolment, uri } = startAuthenticatorEnrolment(account);
      const { codes, hashes } = await generateRecoveryCodes();
      await accounts.updateOne({ _id: account._id }, { $set: { authenticator: enrolment, recoveryCodes: hashes } });
      res.json({ uri, recoveryCodes: codes });
    }),
  );

  router.post(
    '/authenticator/confirm',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const account = await accounts.findOne({ _id: res.locals.session.sub });
      if (!account.authenticator) throw badRequest('no_enrolment');
      if (!(await checkAuthenticatorCode(account.authenticator, String(req.body?.code ?? '')))) throw badRequest('code_wrong');
      await accounts.updateOne({ _id: account._id }, { $set: { 'authenticator.confirmedAt': new Date() } });
      res.status(204).end();
    }),
  );

  router.post(
    '/passkeys/options',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const account = await accounts.findOne({ _id: res.locals.session.sub });
      const options = await passkeyRegistrationOptions(
        { id: String(account._id), email: account.email, displayName: account.displayName },
        account.passkeys ?? [],
      );
      req.session.passkeyChallenge = options.challenge;
      res.json(options);
    }),
  );

  router.post(
    '/passkeys',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const account = await accounts.findOne({ _id: res.locals.session.sub });
      const label = String(req.body?.label ?? 'Security key');
      if (!labelIsFree(account.passkeys ?? [], label)) throw badRequest('label_taken');
      const verification = await verifyRegistrationResponse({
        response: req.body.response,
        expectedChallenge: String(req.session.passkeyChallenge ?? ''),
        expectedOrigin: config.publicBaseUrl.replace('api.', 'app.'),
        expectedRPID: config.passkeys.rpId,
      });
      delete req.session.passkeyChallenge;
      if (!verification.verified) throw badRequest('registration_not_verified');
      const { credential } = verification.registrationInfo;
      const stored = {
        credentialId: credential.id,
        credentialKey: Buffer.from(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports ?? [],
        label,
        createdAt: new Date(),
      };
      await accounts.updateOne({ _id: account._id }, /** @type {any} */ ({ $push: { passkeys: stored } }));
      res.status(201).json({ label });
    }),
  );

  router.post('/logout', (req, res, next) => {
    req.session.destroy((err) => (err ? next(err) : res.status(204).end()));
  });

  return router;
}
