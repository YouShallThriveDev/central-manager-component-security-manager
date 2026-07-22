/**
 * SSO Credentials provider for component apps.
 * Verifies HMAC-signed tokens from Central Manager and auto-creates/signs-in users.
 */
import { ConvexCredentials } from "@convex-dev/auth/providers/ConvexCredentials";
import { createAccount, retrieveAccount } from "@convex-dev/auth/server";
import type { DataModel } from "./_generated/dataModel";

declare const process: { env: Record<string, string | undefined> };

async function hmacSign(message: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message),
  );
  const bytes = new Uint8Array(signature);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str: string): string {
  // Restore base64 from base64url
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return atob(b64);
}

export const SSOCredentials = ConvexCredentials<DataModel>({
  id: "sso",
  authorize: async (params, ctx) => {
    const token = params.token as string;
    if (!token) throw new Error("No SSO token provided");

    const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
    if (!secret) throw new Error("SSO not configured");

    // Parse token: base64url(payload).signature
    const dotIndex = token.indexOf(".");
    if (dotIndex === -1) throw new Error("Invalid SSO token format");

    const payloadB64 = token.substring(0, dotIndex);
    const sig = token.substring(dotIndex + 1);

    // Decode and parse payload
    const payloadStr = base64UrlDecode(payloadB64);
    const payload = JSON.parse(payloadStr);

    // Verify expiry
    if (!payload.exp || Date.now() > payload.exp) {
      throw new Error("SSO token expired");
    }

    // Verify HMAC signature
    const expectedSig = await hmacSign(payloadStr, secret);
    if (sig !== expectedSig) {
      throw new Error("Invalid SSO token signature");
    }

    const email = payload.email as string;
    const name = payload.name as string;

    if (!email) throw new Error("No email in SSO token");

    // Try to retrieve existing account, or create new one
    try {
      const existing = await retrieveAccount(ctx, {
        provider: "sso",
        account: {
          id: email,
        },
      });
      return { userId: existing.user._id };
    } catch {
      // Account doesn't exist, create one
    }

    const { user } = await createAccount(ctx, {
      provider: "sso",
      account: {
        id: email,
      },
      profile: {
        email,
        name,
        emailVerificationTime: Date.now(),
      },
      shouldLinkViaEmail: true,
    });

    return { userId: user._id };
  },
});
