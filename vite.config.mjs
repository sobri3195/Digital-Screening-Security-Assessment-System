import { defineConfig } from 'vite';

export default defineConfig({
    base: '/assets/build/',
    publicDir: false,
    build: {
        outDir: 'public/assets/build',
        manifest: true,
        rolldownOptions: {
            input: ['frontend/intranet.js', 'frontend/ai.js'],
        },
    },
});
