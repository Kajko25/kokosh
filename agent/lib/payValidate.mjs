const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Real payload shape (observed live, differs from the docs example): requestedInfo is
// top-level on the body alongside calls/capabilities/chainId, not nested under
// body.requestData.capabilities.dataCallback.requestedInfo.
export function validatePayerInfo(body) {
  const info = body?.requestedInfo;
  if (!info) return { ok: false, response: { errors: { email: "missing requestedInfo" } } };

  if (!EMAIL_RE.test(info.email ?? "")) {
    return { ok: false, response: { errors: { email: "Invalid email address" } } };
  }

  return { ok: true, response: { request: body } };
}
