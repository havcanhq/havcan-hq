import { Router, type IRouter } from "express";
import authRouter from "./auth";
import healthRouter from "./health";
import whatsappRouter from "./whatsapp";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(whatsappRouter);

export default router;
