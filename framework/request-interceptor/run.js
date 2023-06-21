#!/usr/bin/env node
const fs = require('fs')
const argparseLib = require('argparse')


const chromeCrawlLib = require('./chrome/crawl.js')
const chromeLoggerLib = require('./chrome/logging.js')
const chromeValidateLib = require('./chrome/validate.js')

const defaultDebugSetting = 'none'

const parser = new argparseLib.ArgumentParser({
  add_help: true,
  description: 'CLI tool for recording requests made when visiting a URL.'
})
parser.add_argument('-b', '--binary', {
  required: false,
  help: 'Path to a puppeteer compatible browser.'
})
parser.add_argument('--debug', {
  help: `Print debugging information. Default: ${defaultDebugSetting}.`,
  choices: ['none', 'debug', 'verbose'],
  default: defaultDebugSetting
})
parser.add_argument('-u', '--url', {
  help: 'The URL to record requests',
  required: false
})
parser.add_argument('-p', '--profile', {
  help: 'Path to use and store profile data to.',
  required: false
})
parser.add_argument('-a', '--ancestors', {
  help: 'Log each requests frame hierarchy, not just the immediate parent. ' +
        '(frame URLs are recorded from immediate frame to top most frame)',
  action: 'store_true'
})
parser.add_argument('--interactive', {
  help: 'Show the browser when recording (by default runs headless).',
  action: 'store_true'
})
group = parser.add_mutually_exclusive_group({required: true})
group.add_argument('-t', '--secs', {
  help: `The dwell time in seconds.`,
  type: 'int'
})
group.add_argument('-l', '--links', {
  help: `The maximum number of links to follow.`,
  type: 'int'
})
parser.add_argument('-w', '--wallet', {
  help: 'Path to the wallet extension.',
  required: true
})
parser.add_argument('-d', '--destination', {
  help: 'Path where to log intercepted requests.',
  required: false
})
parser.add_argument('-f', '--force', {
  help: 'Force override if results file already exists.',
  action: 'store_true'
})

const rawArgs = parser.parse_args()
const [isValid, errorOrArgs] = chromeValidateLib.validate(rawArgs)
if (!isValid) {
  throw errorOrArgs
}

(async _ => {
  const logger = chromeLoggerLib.getLoggerForLevel(errorOrArgs.debugLevel)
  let id
  if (errorOrArgs.url == undefined) {
    id = errorOrArgs.walletPath.slice(errorOrArgs.walletPath.lastIndexOf('/') + 1)
  } else {
    id = errorOrArgs.url.split('//')[1].split('?')[0].split('/')[0]
  }
  const path = errorOrArgs.destination+'/'+id+'.json'
  if (!fs.existsSync(path) || errorOrArgs.force) {
    logger.debug('Executing with arguments: ', errorOrArgs)
    const crawlLog = await chromeCrawlLib.crawl(errorOrArgs)
    try {
      fs.writeFileSync(path, JSON.stringify(crawlLog, null, 4))
    } catch (err) {
      console.error(err);
    }
    process.exit(crawlLog.success === true ? 0 : 1)
  } else {
    console.log('File '+path+' already exists!')
  }
})()
