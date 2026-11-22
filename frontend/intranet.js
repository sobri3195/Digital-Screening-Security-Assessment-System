import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './intranet.css';
import 'bootstrap/dist/js/bootstrap.bundle.min.js';

const root = document.documentElement;
const themeKey = 'sentinel-theme';
try {
    if (localStorage.getItem(themeKey) === 'light') root.dataset.bsTheme = 'light';
} catch {
    // Theme switching still works when persistent storage is unavailable.
}
const chartCanvases = document.querySelectorAll('canvas[data-chart]');
async function renderCharts() {
    if (!chartCanvases.length) return;
    const { default: Chart } = await import('chart.js/auto');
    const color = getComputedStyle(root).getPropertyValue('--muted').trim();
    for (const canvas of chartCanvases) {
        const rows = JSON.parse(canvas.dataset.chart);
        Chart.getChart(canvas)?.destroy();
        new Chart(canvas, {
            type: 'bar',
            data: {
                labels: rows.map(row => row.label),
                datasets: [{ data: rows.map(row => Number(row.total)), backgroundColor: '#2563eb', borderRadius: 4 }]
            },
            options: {
                color,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color } },
                    y: { beginAtZero: true, ticks: { color, precision: 0 } }
                }
            }
        });
    }
}
for (const button of document.querySelectorAll('.theme-toggle')) {
    button.addEventListener('click', () => {
        root.dataset.bsTheme = root.dataset.bsTheme === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(themeKey, root.dataset.bsTheme); } catch {}
        renderCharts();
    });
}
const navToggle = document.querySelector('#nav-toggle');
const mobile = matchMedia('(max-width: 730px)');
const sidebar = document.querySelector('#sidebar');
function syncNavigation() {
    const visible = mobile.matches ? document.body.classList.contains('nav-open') : !document.body.classList.contains('nav-hidden');
    navToggle?.setAttribute('aria-expanded', String(visible));
}
navToggle?.addEventListener('click', () => {
    const className = mobile.matches ? 'nav-open' : 'nav-hidden';
    document.body.classList.toggle(className);
    syncNavigation();
    if (mobile.matches && document.body.classList.contains('nav-open')) sidebar?.querySelector('a')?.focus();
});
function closeMobileNavigation() {
    document.body.classList.remove('nav-open');
    syncNavigation();
    navToggle?.focus();
}
document.querySelector('.sidebar-backdrop')?.addEventListener('click', closeMobileNavigation);
document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && document.body.classList.contains('nav-open')) closeMobileNavigation();
});
mobile.addEventListener('change', syncNavigation);
syncNavigation();
const fullscreen = document.querySelector('#fullscreen');
if (fullscreen && !document.fullscreenEnabled) fullscreen.hidden = true;
fullscreen?.addEventListener('click', async () => {
    try {
        if (document.fullscreenElement) await document.exitFullscreen();
        else await root.requestFullscreen();
    } catch {}
});
document.querySelector('#print')?.addEventListener('click', () => window.print());
const table = document.querySelector('table[data-sort-page]');
if (table) {
    import('datatables.net').then(({ default: DataTable }) => {
        new DataTable(table, {
            order: [],
            paging: false,
            searching: false,
            info: false,
            autoWidth: false,
            columnDefs: [{ targets: -1, orderable: false }],
            language: { aria: { orderable: ': Urutkan halaman ini', orderableReverse: ': Balikkan urutan halaman ini' } }
        });
    });
}
document.addEventListener('click', async event => {
    const button = event.target.closest('button[data-confirm]');
    if (!button) return;
    event.preventDefault();
    const dialog = await import('./confirmation.js').catch(() => null);
    if (!dialog) {
        if (window.confirm(button.dataset.confirm)) button.form.requestSubmit(button);
        return;
    }
    const { default: Swal } = dialog;
    const decision = await Swal.fire({
        title: button.dataset.confirm,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Hapus',
        cancelButtonText: 'Batal',
        focusCancel: true,
        heightAuto: false
    });
    if (decision.isConfirmed) button.form.requestSubmit(button);
});
window.addEventListener('load', renderCharts);
