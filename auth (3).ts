import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";

const scryptAsync = (
  password: string,
  salt: Buffer,
  keyLength: number,
  options: crypto.ScryptOptions,
) =>
  new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(derivedKey);
    });
  });

const SESSION_COOKIE = "havcan_session";
const CSRF_COOKIE = "havcan_csrf";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const SCRYPT_PREFIX = "scrypt";

export type OperatorSession = {
  subject: string;
  role: "operator";
  csrfToken: string;
  issuedAt: number;
  expiresAt: number;
};

declare global {
  namespace Express {
    interface Request {
      operator?: OperatorSession;
    }
  }
}

function isProduction() {
  return process.env.NODE_ENV === "production";
}

function secret() {
  return process.env.SESSION_SECRET || "";
}

function operatorUsername() {
  return process.env.HAVCAN_OPERATOR_USERNAME || "";
}

function passwordHash() {
  return process.env.HAVCAN_OPERATOR_PASSWORD_HASH || "";
}

function toBase64Url(value: Buffer | string) {
  return Buffer.from(value).toString("base64url");
}

function fromBase64Url(value: string) {
  return Buffer.from(value, "base64url");
}

function safeEqualText(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return (
    leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function sign(value: string) {
  return crypto.createHmac("sha256", secret()).update(value).digest("base64url");
}

function parsePasswordHash(encoded: string) {
  const [prefix, rawN, rawR, rawP, saltEncoded, digestEncoded] = encoded.split("$");
  const N = Number(rawN);
  const r = Number(rawR);
  const p = Number(rawP);
  if (
    prefix !== SCRYPT_PREFIX ||
    !Number.isInteger(N) ||
    !Number.isInteger(r) ||
    !Number.isInteger(p) ||
    N < 1024 ||
    r < 1 ||
    p < 1 ||
    !saltEncoded ||
    !digestEncoded
  ) {
    return null;
  }
  const salt = fromBase64Url(saltEncoded);
  const digest = fromBase64Url(digestEncoded);
  if (salt.length < 16 || digest.length < 32 || digest.length > 128) return null;
  return { N, r, p, salt, digest };
}

export async function verifyOperatorPassword(password: string) {
  const encoded = parsePasswordHash(passwordHash());
  if (!encoded) return false;
  try {
    const derived = await scryptAsync(password, encoded.salt, encoded.digest.length, {
      N: encoded.N,
      r: encoded.r,
      p: encoded.p,
      maxmem: 128 * 1024 * 1024,
    });
    return crypto.timingSafeEqual(derived, encoded.digest);
  } catch {
    return false;
  }
}

export function authConfigurationError() {
  if (secret().length < 32) return "SESSION_SECRET must be at least 32 characters.";
  if (!operatorUsername()) return "HAVCAN_OPERATOR_USERNAME is required.";
  if (!parsePasswordHash(passwordHash())) {
    return "HAVCAN_OPERATOR_PASSWORD_HASH is not a valid scrypt hash.";
  }
  return null;
}

export function assertProductionAuthConfiguration() {
  if (!isProduction()) return;
  const error = authConfigurationError();
  if (error) throw new Error(`Authentication configuration error: ${error}`);
}

export function createSession(subject: string): OperatorSession {
  const issuedAt = Math.floor(Date.now() / 1000);
  return {
    subject,
    role: "operator",
    csrfToken: toBase64Url(crypto.randomBytes(32)),
    issuedAt,
    expiresAt: issuedAt + SESSION_TTL_SECONDS,
  };
}

function encodeSession(session: OperatorSession) {
  const payload = toBase64Url(JSON.stringify(session));
  return `${payload}.${sign(payload)}`;
}

function decodeSession(token: string | undefined): OperatorSession | null {
  if (!token || !secret()) return null;
  const separator = token.lastIndexOf(".");
  if (separator <= 0) return null;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!safeEqualText(signature, sign(payload))) return null;

  try {
    const session = JSON.parse(fromBase64Url(payload).toString("utf8")) as OperatorSession;
    const now = Math.floor(Date.now() / 1000);
    if (
      session.role !== "operator" ||
      session.subject !== operatorUsername() ||
      !session.csrfToken ||
      !Number.isInteger(session.expiresAt) ||
      session.expiresAt <= now
    ) {
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

function bearerToken(req: Request) {
  const header = req.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : undefined;
}

export function sessionFromRequest(req: Request) {
  return (
    decodeSession(bearerToken(req)) ||
    decodeSession(req.cookies?.[SESSION_COOKIE])
  );
}

export function setSessionCookies(res: Response, session: OperatorSession) {
  const secure = isProduction();
  const sameSite = secure ? "none" : "lax";
  const cookieOptions = {
    httpOnly: true,
    secure,
    sameSite: sameSite as "none" | "lax",
    maxAge: SESSION_TTL_SECONDS * 1000,
    path: "/",
  };
  res.cookie(SESSION_COOKIE, encodeSession(session), cookieOptions);
  res.cookie(CSRF_COOKIE, session.csrfToken, {
    ...cookieOptions,
    httpOnly: false,
  });
}

export function clearSessionCookies(res: Response) {
  const secure = isProduction();
  const sameSite = secure ? "none" : "lax";
  const options = {
    secure,
    sameSite: sameSite as "none" | "lax",
    path: "/",
  };
  res.clearCookie(SESSION_COOKIE, options);
  res.clearCookie(CSRF_COOKIE, options);
}

export function requireOperator(req: Request, res: Response, next: NextFunction) {
  const configurationError = authConfigurationError();
  if (configurationError) {
    res.status(503).json({ message: "Authentication is not configured." });
    return;
  }
  const session = sessionFromRequest(req);
  if (!session) {
    res.status(401).json({ message: "Authentication required." });
    return;
  }
  req.operator = session;
  next();
}

export function requireCsrf(req: Request, res: Response, next: NextFunction) {
  const session = req.operator || sessionFromRequest(req);
  const supplied = req.get("x-havcan-csrf");
  if (!session || !supplied || !safeEqualText(supplied, session.csrfToken)) {
    res.status(403).json({ message: "CSRF protection failed." });
    return;
  }
  next();
}

export function currentSession(req: Request) {
  return req.operator || sessionFromRequest(req);
}

export { SESSION_TTL_SECONDS };