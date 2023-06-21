const fsLib = require('fs')
const urlLib = require('url')
const puppeteer = require('puppeteer')

const isUrl = possibleUrl => {
  try {
    (new urlLib.URL(possibleUrl))  // eslint-disable-line
    return true
  } catch (_) {
    return false
  }
}

const isFile = path => {
  return fsLib.existsSync(path) && fsLib.lstatSync(path).isFile()
}

const isDirectory = path => {
  return fsLib.existsSync(path) && fsLib.lstatSync(path).isDirectory()
}

const validate = rawArgs => {
  let executablePath = puppeteer.executablePath();
  if (rawArgs.binary != undefined) {
    if (!isFile(rawArgs.binary)) {
      return [false, `Invalid path to browser binary: ${rawArgs.binary}`]
    }
    executablePath = rawArgs.binary
  }

  if ((rawArgs.url != undefined) && (!isUrl(rawArgs.url))) {
    return [false, `Found invalid URL: ${rawArgs.url}`]
  }

  let destination = '.'
  if (rawArgs.destination != undefined) {
    if (!isDirectory(rawArgs.destination)) {
      return [false, `Invalid destination path: ${rawArgs.destination}. Must be a directory.`]
    }
    destination = rawArgs.destination
  }

  const validatedArgs = {
    printFrameHierarchy: !!rawArgs.ancestors,
    debugLevel: rawArgs.debug,
    headless: !rawArgs.interactive,
    profilePath: rawArgs.profile,
    secs: rawArgs.secs,
    links: rawArgs.links,
    url: rawArgs.url,
    walletPath: rawArgs.wallet,
    destination: destination,
    force: rawArgs.force,
    executablePath
  }
  return [true, Object.freeze(validatedArgs)]
}

module.exports = {
  isFile,
  isUrl,
  validate
}
