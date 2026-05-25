// TIMPS-Parasol · Home.tsx

import { BreachAlert } from '../components/BreachAlert';
import { LayerStatus } from '../components/LayerStatus';

export function Home() {
  return (
    <section>
      <h2>Home</h2>
      <LayerStatus />
      <div style={{ marginTop: 12 }}>
        <BreachAlert />
      </div>
    </section>
  );
}
