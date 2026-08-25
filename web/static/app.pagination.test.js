/* Standalone Node regression test: no browser framework or dependency needed. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function harness(pages) {
  const source = fs.readFileSync(require('node:path').join(__dirname, 'app.js'), 'utf8')
    .replace(/\}\)\(\);\s*$/, 'globalThis.__pgwPagination = { loadPaged }; })();');
  const context = {
    AbortController, Headers, URLSearchParams, setTimeout, clearTimeout,
    document: { addEventListener() {} },
    globalThis: null,
    fetch: async (url) => {
      const parsed = new URL(url, 'https://ui.test');
      const cursor = parsed.searchParams.get('cursor') || '';
      const page = pages[cursor];
      if (!page) throw new Error(`unexpected cursor ${cursor}`);
      return { ok: true, status: 200, json: async () => page };
    },
  };
  context.globalThis = context;
  vm.runInNewContext(source, context, { filename: 'app.js' });
  return context.__pgwPagination.loadPaged;
}

(async () => {
  const moreThan500 = Array.from({ length: 550 }, (_, index) => ({ id: String(index) }));
  const loadPaged = harness({
    '': { items: moreThan500.slice(0, 200), next_cursor: 'one' },
    one: { items: moreThan500.slice(200, 400), next_cursor: 'two' },
    two: { items: moreThan500.slice(400) },
  });
  const merged = await loadPaged('mappings');
  assert.equal(merged.length, 550, 'all v2 pages must merge deterministically');
  assert.equal(merged[0].id, '0');
  assert.equal(merged.at(-1).id, '549');

  const cycle = harness({ '': { items: [], next_cursor: 'repeat' }, repeat: { items: [], next_cursor: 'repeat' } });
  await assert.rejects(() => cycle('proxies'), /repeated/);
  process.stdout.write('app pagination tests passed\n');
})().catch((error) => { console.error(error); process.exitCode = 1; });
