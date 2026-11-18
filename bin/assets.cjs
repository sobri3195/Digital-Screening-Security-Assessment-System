const { cpSync, mkdirSync } = require('node:fs');
const { join } = require('node:path');
const destination = 'public/assets/vendor';
mkdirSync(destination, { recursive: true });
const files = {
    'bootstrap.min.css': 'bootstrap/dist/css/bootstrap.min.css',
    'bootstrap.bundle.min.js': 'bootstrap/dist/js/bootstrap.bundle.min.js',
    'bootstrap-icons.css': 'bootstrap-icons/font/bootstrap-icons.css',
    fonts: 'bootstrap-icons/font/fonts',
    'chart.js': 'chart.js/dist/chart.umd.js',
    'jquery.js': 'jquery/dist/jquery.min.js',
    'datatables.js': 'datatables.net/js/dataTables.min.js',
    'sweetalert2.css': 'sweetalert2/dist/sweetalert2.min.css',
    'sweetalert2.js': 'sweetalert2/dist/sweetalert2.min.js',
};
for (const [name, source] of Object.entries(files)) {
    cpSync(join('node_modules', source), join(destination, name), { recursive: true });
}
