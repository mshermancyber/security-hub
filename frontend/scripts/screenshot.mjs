import { chromium } from 'playwright'

const url = process.argv[2] || 'http://[::1]:5173/'
const out = process.argv[3] || '/tmp/terminal.png'

const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: 1680, height: 1050 } })
const page = await ctx.newPage()
const errors = []
page.on('pageerror', e => errors.push(`pageerror: ${e.message}`))
page.on('console', m => { if (m.type() === 'error') errors.push(`console.error: ${m.text()}`) })
await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 })
// give the React tree a beat to paint after API responses
await page.waitForTimeout(1500)
await page.screenshot({ path: out, fullPage: false })
if (errors.length) {
  console.error('--- browser errors ---')
  for (const e of errors) console.error(e)
} else {
  console.log('no browser errors')
}
console.log('saved', out)
await browser.close()
