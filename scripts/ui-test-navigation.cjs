'use strict';
// Navigation through the same controls as a user; no application-state or DOM visibility mutation.
const assert = require('node:assert/strict');
async function showPanel(page, id) {
  assert(['explorer', 'settings'].includes(id), 'Unknown side panel');
  const toggle = page.locator('#' + (id === 'explorer' ? 'explorer-toggle' : 'settings-toggle'));
  if (await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  await page.locator('#' + id).waitFor({state:'visible'});
  assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
}
async function revealDetails(page, selector) {
  const target = page.locator(selector); await target.waitFor({state:'attached'});
  const ancestors = target.locator('xpath=ancestor-or-self::details');
  for (let index = 0; index < await ancestors.count(); index++) {
    const detail = ancestors.nth(index);
    if (!await detail.evaluate(node => node.open)) await detail.locator(':scope > summary').click();
  }
  await target.waitFor({state:'visible'});
}
async function showAnalysisSection(page, id) {
  assert(['analysis-workspace','analysis-evidence','inv-panel','reconstruction-panel','analysis-advanced-tools'].includes(id), 'Unknown analysis section');
  await page.locator('[data-view=analysis]').click();
  await page.locator('[data-analysis-section="' + id + '"]').click();
  await page.locator('#' + id).waitFor({state:'visible'});
}
module.exports = {showPanel, revealDetails, showAnalysisSection};
