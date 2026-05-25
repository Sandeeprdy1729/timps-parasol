// TIMPS-Parasol · Settings.tsx

import { AIShieldToggle } from '../components/AIShieldToggle';

export function Settings() {
  return (
    <section>
      <h2>Settings</h2>
      <AIShieldToggle />
      <p style={{ marginTop: 8 }}>Hindi support, UPI billing, and DPDP controls are roadmap-ready.</p>
    </section>
  );
}
