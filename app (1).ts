import express, { type Express } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";
import { assertProductionAuthConfiguration } from "./lib/auth";

const app: Express = express();

assertProductionAuthConfiguration();

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
const frontendOrigin = (process.env.HAVCAN_FRONTEND_ORIGIN?.trim() || "").replace(
  /\/+$/,
  "",
);
if (process.env.NODE_ENV === "production" && !frontendOrigin) {
  throw new Error("HAVCAN_FRONTEND_ORIGIN is required in production.");
}

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || (frontendOrigin && origin === frontendOrigin)) {
        callback(null, true);
        return;
      }
      callback(null, false);
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Accept", "Authorization", "Content-Type", "X-HAVCAN-CSRF"],
  }),
);
app.use(cookieParser());
app.use(
  express.json({
    verify: (req, _res, body) => {
      (req as typeof req & { rawBody?: Buffer }).rawBody = Buffer.from(body);
    },
  }),
);
app.use(express.urlencoded({ extended: true }));

app.use("/api", router);

export default app;
