export interface Session {
  token?: {
    expiresAt: number;
  } | null;
}

export function getSessionExpiration(session: Session | null): number {
  return session.token.expiresAt;
}

