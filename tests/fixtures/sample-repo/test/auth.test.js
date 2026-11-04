import assert from 'node:assert';
import { getSessionExpiration } from '../src/auth.js';

// Test 1: Valid session
const valid = getSessionExpiration({ token: { expiresAt: 1730000000 } });
assert.strictEqual(valid, 1730000000, 'Should return valid expiration timestamp');

// Test 2: Null/undefined token (fails before patch, passes after patch)
const nullToken = getSessionExpiration({ token: null });
assert.strictEqual(nullToken, 0, 'Should safely default to 0 on null/undefined token');

console.log('PASS: All auth session verification tests passed cleanly (2/2).');

