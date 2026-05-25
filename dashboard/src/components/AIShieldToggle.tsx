// TIMPS-Parasol · AIShieldToggle.tsx

import { useState } from 'react';

export function AIShieldToggle() {
  const [enabled, setEnabled] = useState(true);
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
      AI Shield Safe Mode: {enabled ? 'Enabled' : 'Disabled'}
    </label>
  );
}
