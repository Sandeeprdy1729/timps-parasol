import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// TIMPS-Parasol · AIShieldToggle.tsx
import { useState } from 'react';
export function AIShieldToggle() {
    const [enabled, setEnabled] = useState(true);
    return (_jsxs("label", { style: { display: 'flex', alignItems: 'center', gap: 8 }, children: [_jsx("input", { type: "checkbox", checked: enabled, onChange: (e) => setEnabled(e.target.checked) }), "AI Shield Safe Mode: ", enabled ? 'Enabled' : 'Disabled'] }));
}
