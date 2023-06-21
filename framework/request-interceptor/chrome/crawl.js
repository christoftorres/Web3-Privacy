const chromeLoggerLib = require('./logging.js')
const chromePuppeteerLib = require('./puppeteer.js')
const { createTimer } = require('./timer');
const { importMetaMaskWallet, connectMetaMaskWallet } = require('./helper');
const NATIVE_CLICK = 'native';
const fs = require('fs');
const readline = require('readline');

function sleep(time) {
  return new Promise(resolve => setTimeout(resolve, time * 1000));
}

function getRandomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function removeDuplicates(arr) {
  return arr.filter((item, index) => arr.indexOf(item) === index);
}

function removeEmptyStrings(arr) {
  return arr.filter(n => n);
}

function normalizeHeaders(headers) {
    const normalized = {};
    Object.keys(headers).forEach(name => {
        normalized[name.toLowerCase().trim()] = headers[name];
    });
    return normalized;
}

const onRequest = async (options, requestLog, request) => {
  let requestContext = []

  const frame = request.frame()
  if (frame) {
    if (options.printFrameHierarchy) {
      requestContext = []
      let parentFrame = frame
      while (parentFrame) {
        requestContext.push(parentFrame.url())
        parentFrame = await parentFrame.parentFrame()
      }
    } else {
      requestContext.push(frame.url())
    }
  }

  const requestUrl = request.url()
  const requestType = request.resourceType()[0].toUpperCase() + request.resourceType().substring(1)
  const requestMethod = request.method()
  const requestHeaders = normalizeHeaders(request.headers())

  let requestPostData = request.postData()
  if (requestPostData === undefined) {
    requestPostData = ""
  }

  requestLog.requests.push({
    requestContext,
    id: request._requestId,
    url: requestUrl,
    type: requestType,
    status: undefined,
    method: requestMethod,
    headers: requestHeaders,
    postData: requestPostData,
    responseHeaders: {}
  })

  const numRequests = requestLog.requests.length
  const logger = chromeLoggerLib.getLoggerForLevel(options.debugLevel)
  logger.debug('Request '+numRequests+': \033[94m'+requestUrl.split('?', 1).toString().split(';', 1)+'\033[0m')
}

const handleWebSocketCreated = async (options, requestLog, webSockets, request) => {
  let requestContext = []

  if (request.initiator.stack.callFrames.length > 0) {
    const frame = request.initiator.stack.callFrames[0]
    if (frame) {
      if (options.printFrameHierarchy) {
        requestContext = []
        for (let i = 0; i < request.initiator.stack.callFrames.length; i++) {
          let frame = request.initiator.stack.callFrames[i]
          if (!requestContext.includes(frame.url)) {
            requestContext.push(frame.url)
          }
        }
      } else {
        requestContext.push(frame.url)
      }
    }
  }

  request['requestContext'] = requestContext
  webSockets.push(request)
}

const handleWebSocketFrameSent = async (options, requestLog, webSockets, request) => {
  for (let i = 0; i < webSockets.length; i++) {
    if (webSockets[i].requestId === request.requestId) {
      requestUrl = webSockets[i].url
      requestContext = webSockets[i].requestContext
      requestLog.requests.push({
        requestContext,
        id: request.requestId,
        url: requestUrl,
        type: 'WebSocket',
        status: undefined,
        method: '',
        headers: '',
        postData: request.response.payloadData,
        responseHeaders: {}
      })
      const numRequests = requestLog.requests.length
      const logger = chromeLoggerLib.getLoggerForLevel(options.debugLevel)
      logger.debug('Request '+numRequests+': \033[94m'+requestUrl.split('?', 1).toString().split(';', 1)+'\033[0m')
      break
    }
  }
}

const handleResponse = async (options, requestLog, request) => {
  for (let i = 0; i < requestLog.requests.length; i++) {
    if (requestLog.requests[i].id === request.requestId) {
      requestLog.requests[i].status = request.response.status
      requestLog.requests[i].responseHeaders = normalizeHeaders(request.response.headers)
      break
    }
  }
}

const handleResponseExtraInfo = async (options, requestLog, response) => {
  for (let i = 0; i < requestLog.requests.length; i++) {
    if (requestLog.requests[i].id === response.requestId) {
      requestLog.requests[i].responseHeaders = normalizeHeaders(response.headers)
      break
    }
  }
}

const onClose = async (options, page) => {
  console.log('Page closed: \033[94m'+page.url()+'\033[0m')
}

const onTargetCreated = async (options, requestLog, webSockets, cdpClients, target) => {
  if (target.type() !== 'page') {
    return
  }
  const page = await target.page()
  page.on('request', onRequest.bind(undefined, options, requestLog))
  page.on('close', onClose.bind(undefined, options, page))

  const cdpClient = await page.target().createCDPSession()
  await cdpClient.send('Network.enable')
  await cdpClient.send('Page.enable')
  cdpClient.on('Network.webSocketCreated', handleWebSocketCreated.bind(undefined, options, requestLog, webSockets))
  cdpClient.on('Network.webSocketFrameSent', handleWebSocketFrameSent.bind(undefined, options, requestLog, webSockets))
  cdpClient.on('Network.responseReceived', handleResponse.bind(undefined, options, requestLog))
  cdpClient.on('Network.responseReceivedExtraInfo', handleResponseExtraInfo.bind(undefined, options, requestLog))
  cdpClients.push(cdpClient)

  const logger = chromeLoggerLib.getLoggerForLevel(options.debugLevel)
  logger.debug('Completed configuring new page. ('+page.url()+')')
}

const crawl = async args => {
  const logger = chromeLoggerLib.getLoggerForLevel(args.debugLevel)
  const log = Object.create(null)

  log.arguments = args
  log.timestamps = {
    start: Date.now(),
    end: undefined
  }
  log.requests = []

  let cdpClients = []
  let webSockets = []

  let browser

  try {
    browser = await chromePuppeteerLib.launch(args)
    browser.on('targetcreated', onTargetCreated.bind(undefined, args, log, webSockets, cdpClients))

    if (args.url == undefined) {
      let pages = await browser.pages()
      let page = await pages[0]

      await page.goto("chrome://extensions/", {waitUntil: "domcontentloaded"})

      /*log.extensionID = await new Promise(resolve => {
        const readInput = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        })
        readInput.question('Please enter extension ID: ', (answer) => {
          readInput.close()
          resolve(answer)
        })
      })

      log.password = await new Promise(resolve => {
        const readInput = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        })
        readInput.question('Please enter password: ', (answer) => {
          readInput.close()
          resolve(answer)
        })
      })

      log.walletAddress = await new Promise(resolve => {
        const readInput = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        })
        readInput.question('Please enter wallet address: ', (answer) => {
          readInput.close()
          resolve(answer)
        })
      })

      // Search manifest for default popup and open it
      let manifest = JSON.parse(fs.readFileSync(args.walletPath+'/manifest.json'))
      page.close()
      page = await browser.newPage()
      if (manifest.hasOwnProperty("browser_action")) {
        await Promise.all([
            page.waitForNavigation(),
            page.goto("chrome-extension://"+log.extensionID+"/"+manifest.browser_action.default_popup, {waitUntil: "networkidle0"})
        ])
      } else {
        await Promise.all([
            page.waitForNavigation(),
            page.goto("chrome-extension://"+log.extensionID+"/"+manifest.action.default_popup, {waitUntil: "networkidle0"})
        ])
      }

      // Interact with wallet extension
      let elements = []
      let clickable_rects = []

      elements = await page.$$('button')
      for (const element of elements) {
        let boundingBox = await element.boundingBox()
        if (boundingBox != null) {
          const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, element)
          clickable_rects.push(rect)
        }
      }

      elements = await page.$$('div')
      for (const element of elements) {
        let boundingBox = await element.boundingBox()
        if (boundingBox != null) {
          const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, element)
          clickable_rects.push(rect)
        }
      }

      elements = await page.$$('span')
      for (const element of elements) {
        let boundingBox = await element.boundingBox()
        if (boundingBox != null) {
          const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, element)
          clickable_rects.push(rect)
        }
      }

      logger.debug("Found "+clickable_rects.length+" clickable elements.")

      let clicked_rects = []
      const start = Date.now()
      while ((clicked_rects.length < args.links) || (Date.now() - start < (60 * 1000))) {
        let clickable_rect = getRandomItem(clickable_rects)
        if (!clicked_rects.includes(clickable_rect)) {
          clicked_rects.push(clickable_rect)
          try {
              await page.mouse.click(clickable_rect.x + 1, clickable_rect.y + 1)
              await sleep(2)
          } catch {}
          if (manifest.hasOwnProperty("browser_action")) {
            await page.goto("chrome-extension://"+log.extensionID+"/"+manifest.browser_action.default_popup, {waitUntil: "networkidle0"})
          } else {
            await page.goto("chrome-extension://"+log.extensionID+"/"+manifest.action.default_popup, {waitUntil: "networkidle0"})
          }
        }
      }*/

      // Visit 3 different websites
      page = await browser.newPage()
      const websites = ["https://www.nytimes.com", "https://etherscan.io/", "https://app.uniswap.org/"]
      for (let i = 0; i < websites.length; i++) {
        logger.debug("Visiting "+websites[i])
        await Promise.all([
          page.waitForNavigation(),
          page.goto(websites[i], {waitUntil: "networkidle0"})
        ])
        await sleep(5)
      }



      logger.debug("Finished interacting with wallet extension.")
      log.success = true
    } else {
      const url = args.url

      log.url = url
      log.cookies = []
      log.success = true
      log.connected = false

      let pages = await browser.pages()
      let page = await pages[0]
      page.close()
      page = await browser.newPage()

      // Wait for wallet page to load
      await sleep(2)
      pages = await browser.pages()

      const wallet = await pages[pages.length - 1]
      await wallet.bringToFront();

      // Import wallet
      try {
        wallet.setDefaultNavigationTimeout(0)
        await importMetaMaskWallet(logger, wallet)
      } catch {
        logger.debug('\033[91mFailed to import wallet!\033[0m')
      }

      logger.debug(`Visiting ${url}`)
      await page.goto(url, {waitUntil: "domcontentloaded"})
      await page.bringToFront()

      const client = await page.target().createCDPSession();
      await client.send('Page.enable');

      // Connect to DApp
      try {
        page.setDefaultNavigationTimeout(0)
        page.setDefaultTimeout(0)
        let result = await connectMetaMaskWallet(logger, page, browser)
        log.connected         = result[0];
        log.connect_label     = result[1];
        log.metamask_label    = result[2];
        log.checkbox_clicked  = result[3];
        log.signature_request = result[4];
        log.switch_network    = result[5];
      } catch (error) {
        logger.debug('\033[91mFailed to connect to '+url+'!\033[0m')
        console.log(error);
      }

      if (args.links === undefined) {
        // Wait a certain time and do nothing
        const waitTimeMs = args.secs * 1000
        logger.debug(`Waiting for ${waitTimeMs}ms`)
        await page.waitForTimeout(waitTimeMs)
      } else {
        // Interact with DApp
        let counter = 0;
        let hrefs = await page.$$eval('a', as => as.map(a => a.href));
        while (counter < args.links) {
          counter += 1;
          let new_hrefs = await page.$$eval('a', as => as.map(a => a.href));
          hrefs = hrefs.concat(new_hrefs);
          hrefs = removeDuplicates(hrefs);
          hrefs = removeEmptyStrings(hrefs);
          let same_origin = []
          let domain_original = (new URL(url));
          for (const link of hrefs) {
            let domain = (new URL(link));
            if (domain.hostname.includes(domain_original.hostname)) {
              same_origin.push(link);
            }
          }
          hrefs = same_origin;
          logger.debug('Found '+hrefs.length+' links on DApp page: '+page.url());
          if (hrefs.length > 0) {
            random_link = getRandomItem(hrefs);
            logger.debug('Visiting '+random_link);
            await Promise.all([
                page.waitForNavigation(),
                page.goto(random_link, {waitUntil: "domcontentloaded"})
            ]);
          } else {
            break;
          }
        }
      }

      // Save all cookies
      log.cookies = []
      try {
        let cookies = (await client.send('Network.getAllCookies')).cookies
        for (let i = 0; i < cookies.length; i++) {
          if (log.cookies.indexOf(cookies[i]) == -1) {
            log.cookies.push(cookies[i])
          }
        }
      } catch {}
      for (const cdpClient of cdpClients) {
        try {
          let cookies = (await cdpClient.send('Network.getAllCookies')).cookies
          for (let i = 0; i < cookies.length; i++) {
            if (log.cookies.indexOf(cookies[i]) == -1) {
              log.cookies.push(cookies[i])
            }
          }
        } catch {}
      }

      try {
        await page.close()
      } catch  {}
    }
  } catch (error) {
    log.success = false
    log.msg = error.toString()
    logger.debug('\033[91mCaught error when crawling: for '+log.msg+'\033[0m')
  }

  try {
    logger.debug('Trying to shutdown')
    await browser.close()
  } catch (e) {
    logger.debug('\033[91mError when shutting down: '+e.toString()+'\033[0m')
  }

  log.timestamps.end = Date.now()
  return log
}

const timeoutPromise = async (promise, ms) => {
  let timeout = new Promise(function(resolve, reject) {
      setTimeout(resolve, ms, 1);
  });
  let result = Promise.race([promise, timeout]).then(function(value) {
      return value;
  });
  return result;
}

const click = async (elHandle, loginRegisterLinkAttrs, method = "method1", page) => {
  try {
      if (method === NATIVE_CLICK) {
          await elHandle.click();
      } else {
          await page.evaluate(el => el.click(), elHandle);
      }
  } catch (error) {
      console.log(`Error while ${method} clicking on ${await page.url()} ` +
          `${JSON.stringify(loginRegisterLinkAttrs)} ErrorMsg: `);
      return false;
  }
  return true;
}

module.exports = {
  crawl
}
