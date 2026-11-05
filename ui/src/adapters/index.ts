import { DevPulseAdapter } from './types';
import { MockDevPulseAdapter } from './mock-adapter';
import { LiveDevPulseAdapter } from './live-adapter';

let currentMode: 'mock' | 'live' =
  ((import.meta as unknown as { env: Record<string, string> }).env.VITE_MODE as 'mock' | 'live') || 'mock';

let activeAdapter: DevPulseAdapter = currentMode === 'live' ? new LiveDevPulseAdapter() : new MockDevPulseAdapter();

export function getAdapter(): DevPulseAdapter {
  return activeAdapter;
}

export function setAdapterMode(mode: 'mock' | 'live'): DevPulseAdapter {
  currentMode = mode;
  activeAdapter = mode === 'live' ? new LiveDevPulseAdapter() : new MockDevPulseAdapter();
  return activeAdapter;
}

export function getAdapterMode(): 'mock' | 'live' {
  return currentMode;
}

export * from './types';
export * from './mock-adapter';

