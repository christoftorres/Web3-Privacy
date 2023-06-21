const puppeteerExtraLib = require('puppeteer-extra')
const puppeteerExtraPluginStealthLib = require('puppeteer-extra-plugin-stealth')
const { getLogger } = require('./logging')
puppeteerExtraLib.use(puppeteerExtraPluginStealthLib())

const launch = async args => {
  const puppeteerArgs = {
    defaultViewport: null,
    args: [],
    executablePath: args.executablePath,
    headless: args.headless
  }
  puppeteerArgs.args.push(`--start-maximized`)
  puppeteerArgs.args.push(`--disable-popup-blocking`)
  puppeteerArgs.args.push(`--allow-popups-during-upload`)
  puppeteerArgs.args.push(`--disable-site-isolation-trials`)
  puppeteerArgs.args.push(`--no-sandbox`)
  puppeteerArgs.args.push(`--disable-dev-shm-usage`)

  if (args.walletPath) {
    puppeteerArgs.args.push(`--disable-extensions-except=${args.walletPath}`)
    puppeteerArgs.args.push(`--load-extension=${args.walletPath}`)
  }

  if (args.profilePath) {
    puppeteerArgs.args.push(`--user-data-dir=${args.profilePath}`)
  }

  if (args.extraArgs) {
    puppeteerArgs.args.push(...args.extraArgs)
  }

  const browser =  await puppeteerExtraLib.launch(puppeteerArgs)

  const pages = await browser.pages()

  return browser
}

module.exports = {
  launch
}
