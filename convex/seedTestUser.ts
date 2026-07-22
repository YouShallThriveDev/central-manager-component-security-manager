import { createAccount, retrieveAccount } from "@convex-dev/auth/server";
import { v } from "convex/values";
import { Scrypt } from "lucia";
import { internalAction } from "./_generated/server";

const TEST_USER = {
  email: "agent-0bf78f18@test.local",
  password: "ogvIvvlMXDwiJjq-lYW_MBD6IHk8KwRS",
  name: "Test Agent",
} as const;

export const seedTestUser = internalAction({
  args: {},
  returns: v.object({
    success: v.boolean(),
    message: v.string(),
  }),
  handler: async ctx => {
    // Try both "test" (preview) and "password" (production) providers
    const providers = ["test", "password"];
    for (const provider of providers) {
      try {
        await retrieveAccount(ctx, {
          provider,
          account: { id: TEST_USER.email },
        });
        return { success: true, message: `Test user already exists (provider: ${provider})` };
      } catch {
        // Not found with this provider, continue
      }
    }

    // Try creating with each provider
    for (const provider of providers) {
      try {
        const hashedPassword = await new Scrypt().hash(TEST_USER.password);
        await createAccount(ctx, {
          provider,
          account: {
            id: TEST_USER.email,
            secret: hashedPassword,
          },
          profile: {
            email: TEST_USER.email,
            name: TEST_USER.name,
            emailVerificationTime: Date.now(),
          },
          shouldLinkViaEmail: false,
        });
        return { success: true, message: `Test user created successfully (provider: ${provider})` };
      } catch (error) {
        // This provider didn't work, try next
        if (provider === providers[providers.length - 1]) {
          return {
            success: false,
            message: `Failed to create test user with any provider: ${error}`,
          };
        }
      }
    }

    return { success: false, message: "No providers available" };
  },
});
