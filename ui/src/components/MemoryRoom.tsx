import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MemoryRecord } from '../adapters';

interface MemoryRoomProps {
  records: MemoryRecord[];
}

export const MemoryRoom: React.FC<MemoryRoomProps> = ({ records }) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<string>('ALL');

  const tabs = ['ALL', 'AUTH', 'DISPATCHER', 'CONFIG', 'DATABASE'];

  // Filter & rank by search query
  const filteredRecords = records
    .map((record) => {
      let score = record.similarity || 70;
      if (searchQuery.trim()) {
        const queryTerms = searchQuery.toLowerCase().split(/\s+/).filter(Boolean);
        let matches = 0;
        const text = `${record.signature} ${record.rootCause} ${record.fix}`.toLowerCase();
        for (const term of queryTerms) {
          if (text.includes(term)) matches++;
        }
        score = matches > 0 ? Math.min(99, 70 + matches * 10) : 20;
      }
      return { ...record, computedScore: score };
    })
    .filter((record) => {
      if (activeTab === 'ALL') return true;
      const text = `${record.signature} ${record.rootCause} ${record.fix}`.toLowerCase();
      return text.includes(activeTab.toLowerCase());
    })
    .sort((a, b) => b.computedScore - a.computedScore);

  // Helper to highlight matching words
  const highlightMatches = (text: string, query: string) => {
    if (!query.trim()) return text;
    const parts = text.split(new RegExp(`(${query.trim()})`, 'gi'));
    return parts.map((part, i) =>
      part.toLowerCase() === query.trim().toLowerCase() ? (
        <span
          key={i}
          style={{
            background: 'var(--memory-violet-soft)',
            color: 'var(--memory-violet)',
            fontWeight: 600,
            borderRadius: '2px',
            padding: '0 2px'
          }}
        >
          {part}
        </span>
      ) : (
        part
      )
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Records Room Cabinet Header */}
      <div
        className="paper-card"
        style={{
          padding: '18px 24px',
          background: 'var(--surface-paper-card)',
          border: '1px solid var(--border-paper)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px'
        }}
      >
        <div>
          <span
            className="font-mono"
            style={{
              fontSize: '11px',
              color: 'var(--memory-violet)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontWeight: 600
            }}
          >
            Archival Index :: The Records Room
          </span>
          <h2
            className="font-serif"
            style={{
              fontSize: '24px',
              fontWeight: 400,
              color: 'var(--ink-primary)',
              marginTop: '2px'
            }}
          >
            Prior Incident Case Files
          </h2>
        </div>

        {/* Search Bar */}
        <div style={{ minWidth: '320px' }}>
          <input
            type="text"
            placeholder="Search archival precedents by signature, cause, fix..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              background: 'var(--surface-paper-lifted)',
              border: '1px solid var(--border-paper)',
              borderRadius: '2px',
              outline: 'none',
              color: 'var(--ink-primary)'
            }}
            aria-label="Search past case files"
          />
        </div>
      </div>

      {/* Drawer Index Tabs */}
      <div style={{ display: 'flex', gap: '4px', borderBottom: '1px solid var(--border-paper)', paddingLeft: '8px' }}>
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '6px 14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 600,
              border: '1px solid var(--border-paper)',
              borderBottom: activeTab === tab ? '1px solid var(--surface-paper-card)' : '1px solid var(--border-paper)',
              marginBottom: activeTab === tab ? '-1px' : '0',
              background: activeTab === tab ? 'var(--surface-paper-card)' : 'var(--surface-paper)',
              color: activeTab === tab ? 'var(--memory-violet)' : 'var(--ink-secondary)',
              borderRadius: '4px 4px 0 0',
              cursor: 'pointer'
            }}
          >
            {tab} INDEX
          </button>
        ))}
      </div>

      {/* Filing Drawer Container with Index Cards */}
      <div
        style={{
          background: 'var(--surface-paper-card)',
          border: '1px solid var(--border-paper)',
          borderRadius: '2px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
          boxShadow: 'inset 0 2px 4px rgba(20, 32, 26, 0.05)'
        }}
      >
        <AnimatePresence>
          {filteredRecords.map((record) => (
            <motion.div
              key={record.id}
              initial={{ opacity: 0, y: -12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="paper-card"
              style={{
                padding: '16px 20px',
                background: 'var(--surface-paper-lifted)',
                border: '1px solid var(--border-paper)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px'
              }}
            >
              {/* Card Header & Physical Stamp */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ink-primary)' }}>
                    Case #{record.id}
                  </span>

                  {record.verified ? (
                    <span className="stamp-verified">VERIFIED // MAINTAINER SIGNED</span>
                  ) : (
                    <span className="stamp-unverified">UNVERIFIED // AUTO MEMORY</span>
                  )}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="font-mono" style={{ fontSize: '11px', color: 'var(--memory-violet)', fontWeight: 600 }}>
                    {record.computedScore}% Precedent Similarity
                  </span>
                  <span className="font-mono" style={{ fontSize: '10px', color: 'var(--ink-tertiary)' }}>
                    {new Date(record.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </div>

              {/* Error Signature */}
              <div
                className="font-mono"
                style={{
                  fontSize: '11px',
                  color: 'var(--ink-primary)',
                  background: 'var(--surface-paper)',
                  padding: '6px 10px',
                  borderRadius: '2px',
                  border: '1px solid var(--border-paper-light)',
                  wordBreak: 'break-all'
                }}
              >
                {highlightMatches(record.signature, searchQuery)}
              </div>

              {/* Root Cause & Validated Fix */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '14px' }}>
                <div style={{ fontSize: '12px', color: 'var(--ink-secondary)', lineHeight: 1.45 }}>
                  <span style={{ fontWeight: 600, color: 'var(--ink-primary)' }}>Etiology & Root Cause: </span>
                  {highlightMatches(record.rootCause, searchQuery)}
                </div>

                <div style={{ fontSize: '12px', color: 'var(--ink-secondary)', lineHeight: 1.45 }}>
                  <span style={{ fontWeight: 600, color: 'var(--memory-violet)' }}>Validated Prescription: </span>
                  {highlightMatches(record.fix, searchQuery)}
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};

