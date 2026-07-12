const { mkdirSync, copyFileSync } = require('node:fs');
mkdirSync('dist', { recursive: true });
copyFileSync('src/app.asar', 'dist/app.asar');
