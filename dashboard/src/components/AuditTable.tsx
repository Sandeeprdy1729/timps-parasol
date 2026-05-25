// TIMPS-Parasol · AuditTable.tsx

export function AuditTable() {
  const rows = [
    { ts: '2026-05-25T00:00:00Z', action: 'LOG_READ', result: 'success' },
    { ts: '2026-05-25T00:10:00Z', action: 'LOG_AUTH', result: 'failure' }
  ];
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr>
          <th style={{ textAlign: 'left' }}>Timestamp</th>
          <th style={{ textAlign: 'left' }}>Action</th>
          <th style={{ textAlign: 'left' }}>Result</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.ts}>
            <td>{row.ts}</td>
            <td>{row.action}</td>
            <td>{row.result}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
