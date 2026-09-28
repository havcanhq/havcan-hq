import {
  boolean,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

export const whatsappConversations = pgTable("whatsapp_conversations", {
  id: uuid("id").defaultRandom().primaryKey(),
  waId: text("wa_id").notNull().unique(),
  displayName: text("display_name"),
  lastMessageAt: timestamp("last_message_at", { withTimezone: true }),
  lastMessagePreview: text("last_message_preview"),
  unreadCount: integer("unread_count").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const whatsappMessages = pgTable("whatsapp_messages", {
  id: uuid("id").defaultRandom().primaryKey(),
  conversationId: uuid("conversation_id")
    .notNull()
    .references(() => whatsappConversations.id, { onDelete: "cascade" }),
  waMessageId: text("wa_message_id").notNull().unique(),
  customerPhone: text("customer_phone").notNull(),
  direction: text("direction").notNull(),
  messageType: text("message_type").notNull(),
  content: text("content"),
  mediaId: text("media_id"),
  mediaMimeType: text("media_mime_type"),
  mediaFilename: text("media_filename"),
  occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
  status: text("status").notNull().default("received"),
  statusError: text("status_error"),
  isRead: boolean("is_read").notNull().default(false),
  rawPayload: jsonb("raw_payload"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const whatsappWebhookEvents = pgTable("whatsapp_webhook_events", {
  eventKey: text("event_key").primaryKey(),
  eventType: text("event_type").notNull(),
  payload: jsonb("payload").notNull(),
  receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
});

export type WhatsappConversation = typeof whatsappConversations.$inferSelect;
export type WhatsappMessage = typeof whatsappMessages.$inferSelect;