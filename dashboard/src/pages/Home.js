import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// TIMPS-Parasol · Home.tsx
import { BreachAlert } from '../components/BreachAlert';
import { LayerStatus } from '../components/LayerStatus';
export function Home() {
    return (_jsxs("section", { children: [_jsx("h2", { children: "Home" }), _jsx(LayerStatus, {}), _jsx("div", { style: { marginTop: 12 }, children: _jsx(BreachAlert, {}) })] }));
}
