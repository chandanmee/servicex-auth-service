import dotenv from "dotenv";
import express from "express";
import helmet from "helmet";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import swaggerSpec from "./docs/openapi.json";
import authRoutes from "./api/routes/auth.routes";
import { connectMongo } from "./infra/mongoose";

dotenv.config();

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;

async function start() {
  await connectMongo(process.env.MONGO_URI as string);

  const app = express();
  app.use(helmet());
  app.use(cookieParser());
  app.use(cors({
    credentials: true,
    origin: (origin, callback) => {
      // Allow requests from any origin for now (dev mode) or specify your client URL
      // In production, restrict this to your actual client domain
      callback(null, true);
    }
  }));
  app.use(bodyParser.json());

  app.use("/health", (_req, res) => res.json({ status: "ok" }));
  app.use("/auth", authRoutes);
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec as any));
  app.use("/uploads", express.static(process.env.LOCAL_UPLOAD_PATH || "uploads"));

  app.listen(PORT, () => console.log(`🚀 Auth service running on ${PORT}`));
}

start();
