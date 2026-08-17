// Сборка production-артефактов АРМ.
//
// Важно: раньше этот скрипт только упаковывал уже готовые app.min.js и
// styles.min.css, но не создавал их из исходников. Из-за этого правка в
// app.js могла не попасть на сайт — index.html подключает именно app.min.js.
// Теперь минификация выполняется здесь, поэтому исходник и то, что отдаётся
// пользователю, не расходятся.
//
// Минификатор берётся через npx (первый запуск скачивает esbuild); проект
// намеренно живёт без package.json и node_modules.

import fs from 'node:fs';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ESBUILD = 'esbuild@0.24.0';
const here = (name) => new URL(`./${name}`, import.meta.url);
// fileURLToPath корректно разбирает пробелы в пути (каталог «TAKT PT»).
const path = (name) => fileURLToPath(here(name));

function run(input, output) {
  // На Windows Node не запускает .cmd без shell (ограничение с 18.20/20/22),
  // поэтому команда собирается строкой, а пути берутся в кавычки — в пути
  // есть пробел («TAKT PT»). Тип файла esbuild определяет по расширению.
  const quote = (value) => `"${value}"`;
  const command = [
    'npx', '--yes', ESBUILD, quote(path(input)),
    '--minify', `--outfile=${quote(path(output))}`,
  ].join(' ');
  execFileSync(command, { stdio: ['ignore', 'ignore', 'inherit'], shell: true });
  console.log(`минифицировано: ${input} → ${output}`);
}

run('app.js', 'app.min.js');
run('styles.css', 'styles.min.css');

const html = fs.readFileSync(here('index.html'), 'utf8');
const css = fs.readFileSync(here('styles.min.css'), 'utf8');
const bundled = html.replace('</head>', `    <style data-takt-styles>${css}</style>\n  </head>`);

fs.writeFileSync(here('index.prod.html'), bundled);
fs.writeFileSync(here('index.prod.html.gz'), zlib.gzipSync(Buffer.from(bundled), { level: 9 }));

for (const name of ['app.min.js']) {
  const source = fs.readFileSync(here(name));
  fs.writeFileSync(here(`${name}.gz`), zlib.gzipSync(source, { level: 9 }));
}

console.log('готово: index.prod.html, index.prod.html.gz, app.min.js.gz');
