import React, { useEffect } from 'react';
import { useDevPulseStore } from './store/useDevPulseStore';
import { WardBoard } from './components/WardBoard';
import { PatientChart } from './components/PatientChart';
import { MemoryRoom } from './components/MemoryRoom';
import { AuditStrip } from './components/AuditStrip';
import { IngestDrawer } from './components/IngestDrawer';
import './styles/theme.css';

export const App: React.FC = () => {
  const {
    incidents,
    selectedIncidentId,
    statusFilter,
    searchQuery,
    activeTab,
    theme,
    adapterMode,
    isIngestOpen,
    memoryRecords,
    auditEntries,
    currentApprover,
    currentOrigin,
    tamperedSeq,
    isVerifyingChain,
    chainVerificationResult,
    init,
    selectIncident,
    setStatusFilter,
    setSearchQuery,
    setActiveTab,
    toggleTheme,
    toggleAdapterMode,
    setIngestOpen,
    setCurrentApprover,
    setCurrentOrigin,
    ingestTrace,
    submitTwoKeyApproval,
    tamperAuditEntry,
    restoreAuditChain,
    verifyAuditChain
  } = useDevPulseStore();

  useEffect(() => {
    init();
  }, [init]);

  // Apply theme to HTML root element
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const selectedIncident = incidents.find((i) => i.id === selectedIncidentId);

  return (
    <div
      className="ecg-grid-bg"
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        color: 'var(--ink-primary)'
      }}
    >
      {/* Top Clinical Triage Navigation Bar */}
      <header
        style={{
          borderBottom: '1px solid var(--border-paper)',
          background: 'var(--surface-paper-card)',
          padding: '12px clamp(16px, 3vw, 36px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '14px',
          position: 'sticky',
          top: 0,
          zIndex: 50
        }}
      >
        {/* Brand & Attending Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div
            onClick={() => {
              setActiveTab('ward');
              selectIncident(null);
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              cursor: 'pointer'
            }}
          >
            {/* Clinical Cross / Heartbeat Icon */}
            <div
              style={{
                width: '28px',
                height: '28px',
                borderRadius: '4px',
                background: 'var(--ink-primary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2BE59A" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3 12h4l3-8 4 16 3-8h4" />
              </svg>
            </div>

            <div>
              <h1
                className="font-serif"
                style={{
                  fontSize: '20px',
                  fontWeight: 400,
                  lineHeight: 1,
                  letterSpacing: '-0.02em',
                  color: 'var(--ink-primary)'
                }}
              >
                DevPulse
              </h1>
              <span
                className="font-mono"
                style={{
                  fontSize: '9px',
                  color: 'var(--ink-tertiary)',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase'
                }}
              >
                Triage Ward &bull; v0.1.0
              </span>
            </div>
          </div>

          {/* Primary View Switcher Tabs */}
          <nav
            style={{
              display: 'flex',
              gap: '2px',
              background: 'var(--surface-paper)',
              padding: '2px',
              borderRadius: '2px',
              border: '1px solid var(--border-paper-light)',
              marginLeft: '12px'
            }}
            aria-label="Navigation tabs"
          >
            {(
              [
                { id: 'ward', label: 'Triage Ward' },
                { id: 'records', label: 'Records Room' },
                { id: 'strip', label: 'Audit Strip' }
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  if (tab.id !== 'ward') selectIncident(null);
                }}
                style={{
                  padding: '5px 12px',
                  border: 'none',
                  background: activeTab === tab.id ? 'var(--surface-paper-card)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--ink-primary)' : 'var(--ink-secondary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: activeTab === tab.id ? 600 : 400,
                  borderRadius: '2px',
                  cursor: 'pointer',
                  boxShadow: activeTab === tab.id ? 'var(--shadow-paper)' : 'none'
                }}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Right Station Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Adapter Mode Toggle (Mock vs Live) */}
          <button
            onClick={toggleAdapterMode}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '5px 10px',
              borderRadius: '2px',
              border: '1px solid var(--border-paper)',
              background: 'var(--surface-paper)',
              color: 'var(--ink-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              cursor: 'pointer'
            }}
            title="Toggle between mock testbed and live daemon WebSocket"
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: adapterMode === 'live' ? '#2BE59A' : 'var(--amber-pending)'
              }}
            />
            <span>Mode: {adapterMode.toUpperCase()}</span>
          </button>

          {/* Theme Switcher: Daylight vs Night Shift */}
          <button
            onClick={toggleTheme}
            style={{
              padding: '5px 10px',
              borderRadius: '2px',
              border: '1px solid var(--border-paper)',
              background: 'var(--surface-paper)',
              color: 'var(--ink-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              cursor: 'pointer'
            }}
            title="Switch theme"
          >
            {theme === 'daylight' ? 'Night Shift' : 'Daylight Paper'}
          </button>

          {/* Ingest Alert Button */}
          <button
            onClick={() => setIngestOpen(true)}
            style={{
              padding: '6px 14px',
              borderRadius: '2px',
              border: 'none',
              background: 'var(--ink-primary)',
              color: 'var(--surface-paper-card)',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            + Ingest Alert
          </button>
        </div>
      </header>

      {/* Main Content Workspace */}
      <main
        style={{
          flex: 1,
          padding: '24px clamp(16px, 3vw, 36px)',
          maxWidth: '1600px',
          width: '100%',
          margin: '0 auto',
          boxSizing: 'border-box'
        }}
      >
        {activeTab === 'ward' && (
          selectedIncident ? (
            <PatientChart
              incident={selectedIncident}
              onBack={() => selectIncident(null)}
              onApprove={submitTwoKeyApproval}
              currentApprover={currentApprover}
              currentOrigin={currentOrigin}
              onApproverChange={setCurrentApprover}
              onOriginChange={setCurrentOrigin}
            />
          ) : (
            <WardBoard
              incidents={incidents}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={(id) => selectIncident(id)}
              statusFilter={statusFilter}
              onFilterChange={setStatusFilter}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              onOpenIngest={() => setIngestOpen(true)}
              currentApprover={currentApprover}
            />
          )
        )}

        {activeTab === 'records' && <MemoryRoom records={memoryRecords} />}

        {activeTab === 'strip' && (
          <AuditStrip
            entries={auditEntries}
            tamperedSeq={tamperedSeq}
            onTamper={tamperAuditEntry}
            onRestore={restoreAuditChain}
            onVerify={verifyAuditChain}
            isVerifying={isVerifyingChain}
            verificationResult={chainVerificationResult}
          />
        )}
      </main>

      {/* Slide-Out Clinical Ingest Drawer */}
      <IngestDrawer
        isOpen={isIngestOpen}
        onClose={() => setIngestOpen(false)}
        onIngest={async (trace) => {
          await ingestTrace(trace);
        }}
      />
    </div>
  );
};

