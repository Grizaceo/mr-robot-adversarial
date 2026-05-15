// Plain DTO + zod validation, no runtime side effects.
import { z } from "zod";

export const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  displayName: z.string().min(1).max(80),
  createdAt: z.string().datetime(),
});

export type User = z.infer<typeof UserSchema>;

export function parseUser(raw: unknown): User {
  return UserSchema.parse(raw);
}
