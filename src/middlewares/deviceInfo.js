// src/middlewares/deviceInfo.js
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'];
  if (forwarded) return forwarded.split(',')[0].trim();
  if (req.ip) return req.ip;
  if (req.connection && req.connection.remoteAddress) return req.connection.remoteAddress;
  return null;
}

function simpleUAParse(ua) {
  if (!ua) return { browser: null, os: null };
  // very small heuristics — not exhaustive, just helpful for logging
  let browser = null;
  if (ua.includes('Chrome/') && !ua.includes('Edg/') && !ua.includes('OPR/')) browser = 'Chrome';
  else if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Safari/') && ua.includes('Version/')) browser = 'Safari';
  else if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('OPR/') || ua.includes('Opera/')) browser = 'Opera';
  else browser = 'Unknown';

  let os = null;
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Macintosh')) os = 'macOS';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else os = 'Unknown';

  return { browser, os };
}

function extractDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  const agentInfo = simpleUAParse(ua);
  return {
    ip: getClientIp(req),
    userAgent: ua,
    browser: agentInfo.browser,
    os: agentInfo.os,
    raw: { headers: { 'user-agent': ua } }
  };
}

module.exports = { extractDeviceInfo };
