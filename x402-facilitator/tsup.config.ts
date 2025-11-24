import { defineConfig } from 'tsup'

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    outDir: 'dist',
    dts: true, // 生成声明文件
    clean: true,
    minify: false,
    sourcemap: true,
    target: 'es2020',
    keepNames: true,
    treeshake: false
})
