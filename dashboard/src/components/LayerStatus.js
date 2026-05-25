import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
// TIMPS-Parasol · LayerStatus.tsx
export function LayerStatus() {
    const layers = ['L1 Perimeter', 'L2 Identity', 'L3 Vault', 'L4 AI Shield', 'L5 Sentinel'];
    return (_jsx("div", { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }, children: layers.map((layer) => (_jsxs("div", { style: { border: '1px solid #ddd', borderRadius: 8, padding: 12 }, children: [_jsx("strong", { children: layer }), _jsx("div", { style: { color: '#16a34a' }, children: "Healthy" })] }, layer))) }));
}
