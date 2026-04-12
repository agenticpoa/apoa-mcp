import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/lib.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'node20',
  external: ['better-sqlite3'],
});
