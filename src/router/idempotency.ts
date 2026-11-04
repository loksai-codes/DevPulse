export class IdempotencyTracker {
  private processedIds = new Set<string>();
  private correlations = new Map<string, unknown>();
  private maxEntries: number;

  constructor(maxEntries: number = 10000) {
    this.maxEntries = maxEntries;
  }

  /**
   * Atomically checks if an ID was already processed. If not, marks it.
   * Returns true if newly marked (first time seen), false if already processed.
   */
  public markProcessed(id: string): boolean {
    if (this.processedIds.has(id)) {
      return false; // Duplicate
    }

    // Basic LRU-like pruning if exceeding capacity
    if (this.processedIds.size >= this.maxEntries) {
      const first = this.processedIds.values().next().value;
      if (first !== undefined) {
        this.processedIds.delete(first);
      }
    }

    this.processedIds.add(id);
    return true;
  }

  public isProcessed(id: string): boolean {
    return this.processedIds.has(id);
  }

  public recordCorrelation(correlationId: string, metadata: unknown): void {
    if (this.correlations.size >= this.maxEntries) {
      const first = this.correlations.keys().next().value;
      if (first !== undefined) {
        this.correlations.delete(first);
      }
    }
    this.correlations.set(correlationId, metadata);
  }

  public getCorrelation(correlationId: string): unknown {
    return this.correlations.get(correlationId);
  }

  public hasCorrelation(correlationId: string): boolean {
    return this.correlations.has(correlationId);
  }

  public clear(): void {
    this.processedIds.clear();
    this.correlations.clear();
  }
}
