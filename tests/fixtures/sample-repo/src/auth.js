export function getSessionExpiration(session) {
  return session.token.expiresAt;
}

