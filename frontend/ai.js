'use strict';

const taskPanel = document.querySelector('[data-ai-job]');
if (taskPanel) {
    const refresh = async () => {
        try {
            const response = await fetch(taskPanel.dataset.aiJob, {cache: 'no-store'});
            if (!response.ok) return;
            const status = await response.json();
            const state = taskPanel.querySelector('[data-ai-state]');
            if (state) state.textContent = status.state;
            if (['pending', 'processing'].includes(status.state)) window.setTimeout(refresh, 2400);
            else window.location.reload();
        } catch {
            taskPanel.querySelector('[data-ai-state]').textContent = 'Status perlu dimuat ulang.';
        }
    };
    window.setTimeout(refresh, 2000);
}
document.querySelector('[data-ai-copy]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const text = document.getElementById(button.dataset.aiCopy)?.textContent;
    if (!text || !navigator.clipboard) return;
    await navigator.clipboard.writeText(text);
    button.textContent = 'Disalin';
});
