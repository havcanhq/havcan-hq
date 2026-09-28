import crypto from "node:crypto";
import { Router, type IRouter } from "express";
import { z } from "zod";
import {
  clearSessionCookies,
  createSession,
  currentSession,
  requireOperator,
  setSessionCookies,
  verifyOperatorPassword,
} from "../lib/auth";

const router: IRouter = Router();

const loginSchema = z.object({
  username: z.string().min(1).max(256),
  password: z.string().min(1).max(1024),
});

router.post("/auth/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Username and password are required." });
    return;
  }

  const configuredUsername = process.env.HAVCAN_OPERATOR_USERNAME || "";
  if (!configuredUsername || !process.env.SESSION_SECRET) {
    res.status(503).json({ message: "Authentication is not configured." });
    return;
  }

  const usernameBuffer = Buffer.from(parsed.data.username);
  const configuredBuffer = Buffer.from(configuredUsername);
  const usernameMatches =
    usernameBuffer.length === configuredBuffer.length &&
    crypto.timingSafeEqual(usernameBuffer, configuredBuffer);
  const passwordMatches = usernameMatches
    ? await verifyOperatorPassword(parsed.data.password)
    : false;

  if (!usernameMatches || !passwordMatches) {
    res.status(401).json({ message: "Invalid credentials." });
    return;
  }

  const session = createSession(configuredUsername);
  setSessionCookies(res, session);
  res.status(200).json({
    ok: true,
    user: { username: session.subject, role: session.role },
    expiresAt: new Date(session.expiresAt * 1000).toISOString(),
    csrfToken: session.csrfToken,
  });
});

router.get("/auth/session", requireOperator, (req, res) => {
  const session = currentSession(req);
  if (!session) {
    res.status(401).json({ message: "Authentication required." });
    return;
  }
  res.json({
    authenticated: true,
    user: { username: session.subject, role: session.role },
    expiresAt: new Date(session.expiresAt * 1000).toISOString(),
    csrfToken: session.csrfToken,
  });
});

router.post("/auth/logout", (_req, res) => {
  clearSessionCookies(res);
  res.status(204).send();
});

export default router;