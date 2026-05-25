// TIMPS-Parasol · App.tsx

import { useMemo, useState } from 'react';
import { Home } from './pages/Home';
import { Vault } from './pages/Vault';
import { AuditLog } from './pages/AuditLog';
import { Sessions } from './pages/Sessions';
import { Settings } from './pages/Settings';

type Page = 'Home' | 'Vault' | 'AuditLog' | 'Sessions' | 'Settings';

export function App() {
  const [page, setPage] = useState<Page>('Home');
  const Current = useMemo(() => ({ Home, Vault, AuditLog, Sessions, Settings })[page], [page]);

  return (
    <div style={{ fontFamily: 'Inter, system-ui', margin: '0 auto', maxWidth: 980, padding: 24 }}>
      <h1>TIMPS-Parasol Dashboard</h1>
      <nav style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {(['Home', 'Vault', 'AuditLog', 'Sessions', 'Settings'] as Page[]).map((item) => (
          <button key={item} onClick={() => setPage(item)} style={{ padding: '8px 12px' }}>
            {item}
          </button>
        ))}
      </nav>
      <Current />
    </div>
  );
}
