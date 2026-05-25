import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// TIMPS-Parasol · AuditTable.tsx
export function AuditTable() {
    const rows = [
        { ts: '2026-05-25T00:00:00Z', action: 'LOG_READ', result: 'success' },
        { ts: '2026-05-25T00:10:00Z', action: 'LOG_AUTH', result: 'failure' }
    ];
    return (_jsxs("table", { style: { width: '100%', borderCollapse: 'collapse' }, children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { style: { textAlign: 'left' }, children: "Timestamp" }), _jsx("th", { style: { textAlign: 'left' }, children: "Action" }), _jsx("th", { style: { textAlign: 'left' }, children: "Result" })] }) }), _jsx("tbody", { children: rows.map((row) => (_jsxs("tr", { children: [_jsx("td", { children: row.ts }), _jsx("td", { children: row.action }), _jsx("td", { children: row.result })] }, row.ts))) })] }));
}
