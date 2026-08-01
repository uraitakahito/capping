// @ts-check
import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import importXPlugin from 'eslint-plugin-import-x';

export default defineConfig(
  //
  // Global ignores
  //
  {
    // docs-site/ is an Astro project with its own tsconfig and dependency tree;
    // linting it from here would judge Astro's code with this project's
    // type-aware rules, which cannot resolve it. scripts/ is plain Node ESM
    // outside the tsc project for the same reason.
    ignores: [
      'dist/**',
      'node_modules/**',
      'eslint.config.mjs',
      'vitest.config.mts',
      'docs-site/**',
      'scripts/**',
    ],
  },

  //
  // Base configurations
  //
  eslint.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,

  //
  // TypeScript parser options
  //
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  //
  // Import plugin configuration
  //
  {
    plugins: {
      'import-x': importXPlugin,
    },
    settings: {
      'import-x/resolver': {
        typescript: true,
        node: true,
      },
    },
    rules: {
      // Require file extensions for ES modules. In TypeScript ESM, .ts files are
      // imported with the .js extension — what Node.js resolves against dist/*.js.
      'import-x/extensions': [
        'error',
        'always',
        {
          ignorePackages: true,
          checkTypeImports: true,
          pattern: {
            ts: 'never',
            tsx: 'never',
            js: 'always',
            mjs: 'always',
            cjs: 'always',
          },
        },
      ],
      // Prohibit anonymous default exports
      'import-x/no-anonymous-default-export': ['error', { allowCallExpression: false }],
    },
  },

  //
  // Runtime syntax extension restrictions (erasable syntax only)
  //
  // TypeScript 固有のランタイム機能で JavaScript 構文を拡張しない
  // (新構文との競合・可読性低下・トランスパイラ複雑化を避けるため)。
  //
  {
    rules: {
      // Unused vars/args are errors, but a leading underscore marks an
      // intentionally-unused binding — needed for Fastify's (request, reply)
      // handler signature when only one side is used.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // Parameter Properties の禁止
      '@typescript-eslint/parameter-properties': ['error', { prefer: 'class-property' }],

      // Enums, Export Assignment, Decorators の禁止
      'no-restricted-syntax': [
        'error',
        {
          selector: 'TSEnumDeclaration',
          message: 'Enums are not allowed. Use a union type or a const object instead.',
        },
        {
          selector: 'TSExportAssignment',
          message: 'Export assignment (`export =`) is not allowed. Use ES module export syntax instead.',
        },
        {
          selector: 'Decorator',
          message: 'Legacy experimental decorators are not allowed.',
        },
      ],
    },
  },

  //
  // Test-specific rules
  //
  {
    files: ['test/**/*.ts'],
    rules: {
      // Allow non-null assertions in tests (commonly used after expect().toBeDefined())
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
);
