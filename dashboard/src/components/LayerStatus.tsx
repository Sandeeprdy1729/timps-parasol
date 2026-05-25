// TIMPS-Parasol · LayerStatus.tsx

export function LayerStatus() {
  const layers = ['L1 Perimeter', 'L2 Identity', 'L3 Vault', 'L4 AI Shield', 'L5 Sentinel'];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
      {layers.map((layer) => (
        <div key={layer} style={{ border: '1px solid #ddd', borderRadius: 8, padding: 12 }}>
          <strong>{layer}</strong>
          <div style={{ color: '#16a34a' }}>Healthy</div>
        </div>
      ))}
    </div>
  );
}
