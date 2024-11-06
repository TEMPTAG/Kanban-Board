import { Router } from "express";
import authRoutes from "./auth-routes.js";
import apiRoutes from "./api/index.js";
import { authenticateToken } from "../middleware/auth.js";

const router = Router();

// Use the authentication middleware for all API routes
router.use("/auth", authRoutes);

// Protect /api routes by requiring a valid token
router.use("/api", authenticateToken, apiRoutes);

export default router;
