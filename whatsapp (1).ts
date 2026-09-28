import crypto from "node:crypto";
import { Readable } from "node:stream";
import { Router, type IRouter, type Request } from "express";
import { and, desc, eq, sql } from "drizzle-orm";
import { z } from "zod";
import { requireCsrf, requireOperator } from "../lib/auth";
import {
  db,
  whatsappConversations,
  whatsappMessages,
  whatsappWebhookEvents,
} from "@workspace/db";

declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
    }
  }
}

const router: IRouter = Router();

const GRAPH_VERSION = "v23.0";
const PHONE_NUMBER_ID = process.env.META_WHATSAPP_PHONE_NUMBER_ID || "";
const WABA_ID = process.env.META_WHATSAPP_WABA_ID || "";

const sendMessageSchema = z.object({
  to: z.string().min(3).max(32),
  type: z.enum(["text", "image", "video", "document", "audio", "template"]).default("text"),
  text: z.string().max(4096).optional(),
  mediaId: z.string().max(256).optional(),
  caption: z.string().max(1024).optional(),
  filename: z.string().max(255).optional(),
  template: z
    .object({
      name: z.string().min(1).max(512),
      languageCode: z.string().min(2).max(32).default("en_US"),
      parameters: z.array(z.string().max(1024)).max(20).default([]),
    })
    .optional(),
});

router.use("/whatsapp/status", requireOperator);
router.use("/whatsapp/conversations", requireOperator);
router.use("/whatsapp/media", requireOperator);
router.use("/whatsapp/messages", requireOperator, requireCsrf);

type MetaPayload = Record<string, unknown>;
type MetaRequestInit = {
  method?: string;
  body?: string;
  headers?: Record<string, string>;
};

function configuredSecrets() {
  return {
    accessToken: Boolean(process.env.META_WHATSAPP_ACCESS_TOKEN),
    phoneNumberId: Boolean(process.env.META_WHATSAPP_PHONE_NUMBER_ID),
    verifyToken: Boolean(process.env.META_WHATSAPP_VERIFY_TOKEN),
    appSecret: Boolean(process.env.META_APP_SECRET),
  };
}

function canUseMeta() {
  return true;
}

function safeTimestamp(value: unknown): Date {
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds > 0
    ? new Date(seconds * 1000)
    : new Date();
}

function messageText(message: MetaPayload): string | null {
  const type = String(message.type || "");
  const value = message[type];
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (typeof record.body === "string") return record.body;
    if (typeof record.caption === "string") return record.caption;
    if (typeof record.filename === "string") return record.filename;
  }
  if (typeof message.text === "string") return message.text;
  return null;
}

function messageMedia(message: MetaPayload): {
  mediaId: string | null;
  mimeType: string | null;
  filename: string | null;
} {
  const type = String(message.type || "");
  const value = message[type];
  if (!value || typeof value !== "object") {
    return { mediaId: null, mimeType: null, filename: null };
  }
  const record = value as Record<string, unknown>;
  return {
    mediaId: typeof record.id === "string" ? record.id : null,
    mimeType: typeof record.mime_type === "string" ? record.mime_type : null,
    filename: typeof record.filename === "string" ? record.filename : null,
  };
}

function previewFor(content: string | null, messageType: string) {
  if (content) return content.slice(0, 240);
  return `[${messageType}]`;
}

function signatureIsValid(rawBody: Buffer, signature: string | undefined) {
  const appSecret = process.env.META_APP_SECRET;
  if (!appSecret || !signature) return false;
  const expected = `sha256=${crypto
    .createHmac("sha256", appSecret)
    .update(rawBody)
    .digest("hex")}`;
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

async function metaRequest(path: string, init: MetaRequestInit = {}) {
  const accessToken = process.env.META_WHATSAPP_ACCESS_TOKEN;
  if (!accessToken) {
    const failure = new Error("META_WHATSAPP_ACCESS_TOKEN is not configured.");
    (failure as Error & { status?: number }).status = 503;
    throw failure;
  }
  const requestHeaders = {
    ...(init.headers || {}),
    authorization: `Bearer ${accessToken}`,
  };
  const response = await fetch(`https://graph.facebook.com/${GRAPH_VERSION}${path}`, {
    method: init.method || "GET",
    headers: requestHeaders,
    body: init.body,
  });
  const text = await response.text();
  let payload: MetaPayload = {};
  try {
    payload = text ? (JSON.parse(text) as MetaPayload) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok) {
    const error = payload.error;
    const message =
      error && typeof error === "object" && typeof (error as MetaPayload).message === "string"
        ? String((error as MetaPayload).message)
        : "Meta WhatsApp request failed.";
    const failure = new Error(message);
    (failure as Error & { status?: number; payload?: MetaPayload }).status = response.status;
    (failure as Error & { status?: number; payload?: MetaPayload }).payload = payload;
    throw failure;
  }
  return payload;
}

async function findOrCreateConversation(waId: string, displayName?: string) {
  const existing = await db.query.whatsappConversations.findFirst({
    where: eq(whatsappConversations.waId, waId),
  });
  if (existing) {
    if (displayName && existing.displayName !== displayName) {
      const [updated] = await db
        .update(whatsappConversations)
        .set({ displayName, updatedAt: new Date() })
        .where(eq(whatsappConversations.id, existing.id))
        .returning();
      return updated || existing;
    }
    return existing;
  }
  const [created] = await db
    .insert(whatsappConversations)
    .values({ waId, displayName: displayName || null })
    .onConflictDoNothing({ target: whatsappConversations.waId })
    .returning();
  if (created) return created;
  const retry = await db.query.whatsappConversations.findFirst({
    where: eq(whatsappConversations.waId, waId),
  });
  if (!retry) throw new Error("Unable to create WhatsApp conversation.");
  return retry;
}

async function recordInboundMessage(message: MetaPayload, contactName?: string) {
  const from = typeof message.from === "string" ? message.from : null;
  const waMessageId = typeof message.id === "string" ? message.id : null;
  if (!from || !waMessageId) return;

  const type = typeof message.type === "string" ? message.type : "unknown";
  const text = messageText(message);
  const media = messageMedia(message);
  const conversation = await findOrCreateConversation(from, contactName);
  const occurredAt = safeTimestamp(message.timestamp);

  const inserted = await db
    .insert(whatsappMessages)
    .values({
      conversationId: conversation.id,
      waMessageId,
      customerPhone: from,
      direction: "inbound",
      messageType: type,
      content: text,
      mediaId: media.mediaId,
      mediaMimeType: media.mimeType,
      mediaFilename: media.filename,
      occurredAt,
      status: "received",
      rawPayload: message,
    })
    .onConflictDoNothing({ target: whatsappMessages.waMessageId })
    .returning({ id: whatsappMessages.id });

  if (inserted.length) {
    await db
      .update(whatsappConversations)
      .set({
        lastMessageAt: occurredAt,
        lastMessagePreview: previewFor(text, type),
        unreadCount: sql`${whatsappConversations.unreadCount} + 1`,
        updatedAt: new Date(),
      })
      .where(eq(whatsappConversations.id, conversation.id));
  }
}

async function recordStatus(status: MetaPayload) {
  const waMessageId = typeof status.id === "string" ? status.id : null;
  const messageStatus = typeof status.status === "string" ? status.status : null;
  if (!waMessageId || !messageStatus) return;
  const errors = Array.isArray(status.errors) ? status.errors : [];
  const statusError =
    errors.length && errors[0] && typeof errors[0] === "object"
      ? JSON.stringify(errors[0])
      : null;
  await db
    .update(whatsappMessages)
    .set({ status: messageStatus, statusError })
    .where(eq(whatsappMessages.waMessageId, waMessageId));
}

async function processWebhook(payload: MetaPayload) {
  const entries = Array.isArray(payload.entry) ? payload.entry : [];
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") continue;
    const changes = Array.isArray((entry as MetaPayload).changes)
      ? ((entry as MetaPayload).changes as unknown[])
      : [];
    for (const change of changes) {
      if (!change || typeof change !== "object") continue;
      const value = (change as MetaPayload).value;
      if (!value || typeof value !== "object") continue;
      const valueRecord = value as MetaPayload;
      const contacts = Array.isArray(valueRecord.contacts)
        ? valueRecord.contacts
        : [];
      const contactNames = new Map<string, string>();
      for (const contact of contacts) {
        if (!contact || typeof contact !== "object") continue;
        const contactRecord = contact as MetaPayload;
        const waId = typeof contactRecord.wa_id === "string" ? contactRecord.wa_id : null;
        const profile = contactRecord.profile;
        const name =
          profile && typeof profile === "object" && typeof (profile as MetaPayload).name === "string"
            ? String((profile as MetaPayload).name)
            : null;
        if (waId && name) contactNames.set(waId, name);
      }
      const messages = Array.isArray(valueRecord.messages) ? valueRecord.messages : [];
      for (const item of messages) {
        if (!item || typeof item !== "object") continue;
        const message = item as MetaPayload;
        const id = typeof message.id === "string" ? message.id : null;
        if (!id) continue;
        const eventKey = `message:${id}`;
        const inserted = await db
          .insert(whatsappWebhookEvents)
          .values({ eventKey, eventType: "message", payload: message })
          .onConflictDoNothing()
          .returning({ eventKey: whatsappWebhookEvents.eventKey });
        if (inserted.length) {
          await recordInboundMessage(
            message,
            typeof message.from === "string" ? contactNames.get(message.from) : undefined,
          );
        }
      }
      const statuses = Array.isArray(valueRecord.statuses) ? valueRecord.statuses : [];
      for (const item of statuses) {
        if (!item || typeof item !== "object") continue;
        const status = item as MetaPayload;
        const id = typeof status.id === "string" ? status.id : null;
        const statusValue = typeof status.status === "string" ? status.status : "unknown";
        if (!id) continue;
        const eventKey = `status:${id}:${statusValue}:${String(status.timestamp || "")}`;
        const inserted = await db
          .insert(whatsappWebhookEvents)
          .values({ eventKey, eventType: "status", payload: status })
          .onConflictDoNothing()
          .returning({ eventKey: whatsappWebhookEvents.eventKey });
        if (inserted.length) await recordStatus(status);
      }
    }
  }
}

router.get("/whatsapp/status", async (_req, res) => {
  const secrets = configuredSecrets();
  let connected = false;
  let error: string | undefined;
  if (canUseMeta()) {
    try {
      await metaRequest(`/${PHONE_NUMBER_ID}`);
      connected = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : "Meta connection failed.";
    }
  }
  res.json({
    configured: secrets.verifyToken && secrets.appSecret,
    connected,
    phoneNumberIdConfigured: secrets.phoneNumberId,
    error,
  });
});

router.get("/whatsapp/conversations", async (_req, res) => {
  const conversations = await db
    .select()
    .from(whatsappConversations)
    .orderBy(desc(whatsappConversations.lastMessageAt), desc(whatsappConversations.updatedAt));
  res.json(
    conversations.map((conversation) => ({
      id: conversation.id,
      waId: conversation.waId,
      displayName: conversation.displayName,
      lastMessageAt: conversation.lastMessageAt,
      lastMessagePreview: conversation.lastMessagePreview,
      unreadCount: conversation.unreadCount,
    })),
  );
});

router.get("/whatsapp/conversations/:conversationId/messages", async (req, res) => {
  const conversationId = z.string().uuid().safeParse(req.params.conversationId);
  if (!conversationId.success) {
    res.status(400).json({ message: "Invalid conversation id." });
    return;
  }
  const messages = await db
    .select()
    .from(whatsappMessages)
    .where(eq(whatsappMessages.conversationId, conversationId.data))
    .orderBy(whatsappMessages.occurredAt);
  res.json(
    messages.map((message) => ({
      id: message.id,
      waMessageId: message.waMessageId,
      conversationId: message.conversationId,
      direction: message.direction,
      type: message.messageType,
      content: message.content,
      mediaUrl: message.mediaId ? `/api/whatsapp/media/${encodeURIComponent(message.mediaId)}` : null,
      mediaMimeType: message.mediaMimeType,
      mediaFilename: message.mediaFilename,
      occurredAt: message.occurredAt,
      status: message.status,
      statusError: message.statusError,
    })),
  );
});

router.post("/whatsapp/messages", async (req, res) => {
  const parsed = sendMessageSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid WhatsApp message.", issues: parsed.error.issues });
    return;
  }
  const input = parsed.data;
  const conversation = await findOrCreateConversation(input.to);
  const body: MetaPayload = {
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to: input.to,
    type: input.type,
  };
  if (input.type === "text") {
    if (!input.text) {
      res.status(400).json({ message: "Text messages require text." });
      return;
    }
    body.text = { body: input.text, preview_url: false };
  } else if (input.type === "template") {
    if (!input.template) {
      res.status(400).json({ message: "Template messages require template details." });
      return;
    }
    body.template = {
      name: input.template.name,
      language: { code: input.template.languageCode },
      ...(input.template.parameters.length
        ? {
            components: [
              {
                type: "body",
                parameters: input.template.parameters.map((text) => ({ type: "text", text })),
              },
            ],
          }
        : {}),
    };
  } else {
    if (!input.mediaId) {
      res.status(400).json({ message: "Media messages require a mediaId." });
      return;
    }
    body[input.type] = {
      id: input.mediaId,
      ...(input.caption ? { caption: input.caption } : {}),
      ...(input.filename && input.type === "document" ? { filename: input.filename } : {}),
    };
  }

  try {
    const meta = await metaRequest(`/${PHONE_NUMBER_ID}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const messages = Array.isArray(meta.messages) ? meta.messages : [];
    const metaMessage = messages[0] && typeof messages[0] === "object" ? (messages[0] as MetaPayload) : {};
    const waMessageId = typeof metaMessage.id === "string" ? metaMessage.id : null;
    const occurredAt = new Date();
    if (waMessageId) {
      await db.insert(whatsappMessages).values({
        conversationId: conversation.id,
        waMessageId,
        customerPhone: input.to,
        direction: "outbound",
        messageType: input.type,
        content: input.text || input.caption || null,
        mediaId: input.mediaId || null,
        mediaFilename: input.filename || null,
        occurredAt,
        status: "sent",
        rawPayload: body,
      }).onConflictDoNothing({ target: whatsappMessages.waMessageId });
      await db.update(whatsappConversations).set({
        lastMessageAt: occurredAt,
        lastMessagePreview: previewFor(input.text || input.caption || null, input.type),
        updatedAt: occurredAt,
      }).where(eq(whatsappConversations.id, conversation.id));
    }
    res.status(201).json({ ok: true, messageId: waMessageId, meta });
  } catch (cause) {
    const error = cause as Error & { status?: number };
    res.status(error.status && error.status >= 400 && error.status < 500 ? error.status : 502).json({
      message: error.message || "WhatsApp message could not be sent.",
    });
  }
});

router.post("/whatsapp/messages/:messageId/read", async (req, res) => {
  const messageId = z.string().min(1).max(256).safeParse(req.params.messageId);
  if (!messageId.success) {
    res.status(400).json({ message: "Invalid message id." });
    return;
  }
  try {
    await metaRequest(`/${PHONE_NUMBER_ID}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messaging_product: "whatsapp", status: "read", message_id: messageId.data }),
    });
    await db.update(whatsappMessages).set({ isRead: true }).where(eq(whatsappMessages.waMessageId, messageId.data));
    res.json({ ok: true });
  } catch (cause) {
    const error = cause as Error & { status?: number };
    res.status(error.status && error.status >= 400 && error.status < 500 ? error.status : 502).json({
      message: error.message || "WhatsApp message could not be marked as read.",
    });
  }
});

router.get("/whatsapp/media/:mediaId", async (req, res) => {
  const mediaId = z.string().trim().min(1).max(256).safeParse(req.params.mediaId);
  if (!mediaId.success) {
    res.status(400).json({ message: "Invalid media id." });
    return;
  }
  try {
    const metadata = await metaRequest(`/${mediaId.data}`);
    const mediaUrl = typeof metadata.url === "string" ? metadata.url : null;
    if (!mediaUrl) {
      res.status(502).json({ message: "Meta did not provide a media URL." });
      return;
    }
    const mediaAccessToken = process.env.META_WHATSAPP_ACCESS_TOKEN;
    const mediaResponse = await fetch(mediaUrl, {
      headers: mediaAccessToken ? { authorization: `Bearer ${mediaAccessToken}` } : {},
    });
    if (!mediaResponse.ok || !mediaResponse.body) {
      res.status(502).json({ message: "WhatsApp media could not be downloaded." });
      return;
    }
    res.status(200);
    if (typeof metadata.mime_type === "string") res.setHeader("content-type", metadata.mime_type);
    if (typeof metadata.file_size === "number") res.setHeader("content-length", String(metadata.file_size));
    Readable.fromWeb(mediaResponse.body as never).pipe(res);
  } catch (cause) {
    const error = cause as Error & { status?: number };
    res.status(error.status && error.status >= 400 && error.status < 500 ? error.status : 502).json({
      message: error.message || "WhatsApp media could not be loaded.",
    });
  }
});

router.get("/whatsapp/webhook", (req, res) => {
  const mode = typeof req.query["hub.mode"] === "string" ? req.query["hub.mode"] : "";
  const token = typeof req.query["hub.verify_token"] === "string" ? req.query["hub.verify_token"] : "";
  const challenge = typeof req.query["hub.challenge"] === "string" ? req.query["hub.challenge"] : "";
  if (mode === "subscribe" && token && token === process.env.META_WHATSAPP_VERIFY_TOKEN && challenge) {
    res.status(200).type("text/plain").send(challenge);
    return;
  }
  res.sendStatus(403);
});

router.post("/whatsapp/webhook", async (req: Request, res) => {
  if (!signatureIsValid(req.rawBody || Buffer.alloc(0), req.header("x-hub-signature-256"))) {
    res.sendStatus(401);
    return;
  }
  try {
    await processWebhook(req.body as MetaPayload);
    res.sendStatus(200);
  } catch (cause) {
    req.log.error({ err: cause }, "WhatsApp webhook processing failed");
    res.sendStatus(500);
  }
});

export default router;