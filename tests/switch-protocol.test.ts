import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSwitchFrame
} from '../src/room/switch-event-normalizer.js';

describe('Switch Protocol Normalization & Frame Validation', () => {
  const agentId = 'agn_devpulse_sentinel';

  it('normalizes control frame: ping', () => {
    const raw = JSON.stringify({ type: 'ping' });
    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'PING');
  });

  it('normalizes control frame: connection_state', () => {
    const raw = {
      type: 'connection_state',
      rooms: ['room_ops', 'room_triage'],
      cursor: 1205,
      generation: 'gen_88f91'
    };
    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'CONNECTION_STATE');
    if (result.type === 'CONNECTION_STATE') {
      assert.deepEqual(result.rooms, ['room_ops', 'room_triage']);
      assert.equal(result.cursor, 1205);
      assert.equal(result.generation, 'gen_88f91');
    }
  });

  it('normalizes control frame: evicted', () => {
    const raw = {
      type: 'evicted',
      code: 'heartbeat_lapsed',
      reason: 'Heartbeat ping was not answered within 6 seconds'
    };
    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'EVICTED');
    if (result.type === 'EVICTED') {
      assert.equal(result.code, 'heartbeat_lapsed');
      assert.match(result.reason!, /Heartbeat ping/);
    }
  });

  it('correctly marks native Switch Console messages with isNativeConsole = true when bridge_id is null', () => {
    const raw = {
      event: 'message',
      data: {
        type: 'message',
        room_id: 'room_devpulse',
        bridge_id: null, // Native Switch Console!
        channel_type: 'channel_public',
        sequence: 4813,
        payload: {
          addressed: true,
          sender: 'usr_maintainer_alice',
          sender_name: 'Alice Maintainer',
          message_id: 'msg_1001',
          body: '@sentinel inspect crash in auth.ts',
          timestamp: 1730710000000,
          thread_id: null,
          attachments: []
        }
      },
      id: 4813
    };

    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'EVENT');
    if (result.type === 'EVENT') {
      assert.equal(result.event.isNativeConsole, true);
      assert.equal(result.event.bridgeId, null);
      assert.equal(result.event.senderId, 'usr_maintainer_alice');
      assert.equal(result.event.addressedToMe, true);
      assert.equal(result.event.isSelfMessage, false);
      assert.equal(result.event.sequence, 4813);
    }
  });

  it('marks bridged messages (Slack/Discord/Teams) with isNativeConsole = false when bridge_id is present', () => {
    const raw = {
      event: 'message',
      data: {
        type: 'message',
        room_id: 'room_devpulse',
        bridge_id: 'bridge_slack_prod_01', // Bridged from Slack!
        channel_type: 'channel_public',
        sequence: 4814,
        payload: {
          addressed: true,
          sender: 'usr_puppet_slack_U1234',
          sender_name: 'Bob Slack Puppet',
          message_id: 'msg_1002',
          body: '@sentinel info',
          timestamp: 1730710001000,
          thread_id: 'th_99',
          attachments: []
        }
      },
      id: 4814
    };

    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'EVENT');
    if (result.type === 'EVENT') {
      assert.equal(result.event.isNativeConsole, false);
      assert.equal(result.event.bridgeId, 'bridge_slack_prod_01');
      assert.equal(result.event.threadId, 'th_99');
    }
  });

  it('flags self-messages when sender matches the agent own agentId', () => {
    const raw = {
      event: 'message',
      data: {
        type: 'message',
        room_id: 'room_devpulse',
        bridge_id: null,
        sequence: 4815,
        payload: {
          addressed: false,
          sender: agentId, // Self!
          sender_name: 'Sentinel Bot',
          message_id: 'msg_1003',
          body: 'Investigation in progress...',
          timestamp: 1730710002000
        }
      },
      id: 4815
    };

    const result = normalizeSwitchFrame(raw, agentId);
    assert.equal(result.type, 'EVENT');
    if (result.type === 'EVENT') {
      assert.equal(result.event.isSelfMessage, true);
      assert.equal(result.event.senderId, agentId);
    }
  });

  it('ignores malformed frames and invalid JSON gracefully without throwing', () => {
    const badJson = '{ invalid json frame ';
    const res1 = normalizeSwitchFrame(badJson, agentId);
    assert.equal(res1.type, 'IGNORED');

    const emptyObj = {};
    const res2 = normalizeSwitchFrame(emptyObj, agentId);
    assert.equal(res2.type, 'IGNORED');
  });
});

