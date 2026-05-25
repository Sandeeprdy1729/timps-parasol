import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// TIMPS-Parasol · App.tsx
import { useMemo, useState } from 'react';
import { Home } from './pages/Home';
import { Vault } from './pages/Vault';
import { AuditLog } from './pages/AuditLog';
import { Sessions } from './pages/Sessions';
import { Settings } from './pages/Settings';
export function App() {
    const [page, setPage] = useState('Home');
    const Current = useMemo(() => ({ Home, Vault, AuditLog, Sessions, Settings })[page], [page]);
    return (_jsxs("div", { style: { fontFamily: 'Inter, system-ui', margin: '0 auto', maxWidth: 980, padding: 24 }, children: [_jsx("h1", { children: "TIMPS-Parasol Dashboard" }), _jsx("nav", { style: { display: 'flex', gap: 8, marginBottom: 16 }, children: ['Home', 'Vault', 'AuditLog', 'Sessions', 'Settings'].map((item) => (_jsx("button", { onClick: () => setPage(item), style: { padding: '8px 12px' }, children: item }, item))) }), _jsx(Current, {})] }));
}
