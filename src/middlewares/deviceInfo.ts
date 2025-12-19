import { Request } from "express";

function getClientIp(req: Request) {
  const forwarded = (req.headers["x-forwarded-for"] || (req.headers as any)["X-Forwarded-For"]) as string | undefined;
  if (forwarded) return forwarded.split(",")[0].trim();
  if (req.ip) return req.ip;
  const conn = (req as any).connection;
  if (conn && conn.remoteAddress) return conn.remoteAddress;
  return null;
}

function simpleUAParse(ua?: string) {
  if (!ua) return { browser: null as string | null, os: null as string | null };
  let browser: string | null = null;
  if (ua.includes("Chrome/") && !ua.includes("Edg/") && !ua.includes("OPR/")) browser = "Chrome";
  else if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("Safari/") && ua.includes("Version/")) browser = "Safari";
  else if (ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("OPR/") || ua.includes("Opera/")) browser = "Opera";
  else browser = "Unknown";
  let os: string | null = null;
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Macintosh")) os = "macOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";
  else os = "Unknown";
  return { browser, os };
}

export function extractDeviceInfo(req: Request) {
  const ua = (req.headers["user-agent"] || "") as string;
  const agentInfo = simpleUAParse(ua);
  return {
    ip: getClientIp(req),
    userAgent: ua,
    browser: agentInfo.browser,
    os: agentInfo.os,
    raw: { headers: { "user-agent": ua } }
  };
}
