const { createTimer } = require('./timer');
const fs = require('fs');

const POST_CLICK_LOAD_TIMEOUT = 500;

const CONNECT_STRINGS = ["Connect to MetaMask", " Connect Wallet ", "Connect Wallet", "Connect wallet", "connect wallet", "Connect to a wallet", "Connect to wallet", "Connect your wallet", "Sign In", "Connect", "CONNECT WALLET", "CONNECT", "SIGN IN", "WALLET", "SIGN", "sign", "SIGNIN", "Sign Up", "Connect Your Wallet", "Wallet", "Connect a Wallet", "Connect a wallet", "Sign in", "sign in", "connect", "Log in via web3 wallet", "wallet", "account", "Account"]

const METAMASK_STRINGS = ["MetaMask", "MetaMask ", "metamask", "Connect Metamask", "Connect MetaMask", "Metamask", "Connect to MetaMask", "browser wallet", "Browser Wallet", "Browser wallet", "Metamask & Web3", "Metamask\n& Web3", "Metamask \n& Web3"]

const waitForNavigation = async (page, maxWaitTimeInMillisecs) => {
    if (maxWaitTimeInMillisecs <= POST_CLICK_LOAD_TIMEOUT) {
        maxWaitTimeInMillisecs = POST_CLICK_LOAD_TIMEOUT;
    }
    try {
        const clickLoadTimer = createTimer();
        await page.waitForNavigation({ 'timeout': maxWaitTimeInMillisecs, 'waitUntil': 'load' });
        await page.waitForTimeout(maxWaitTimeInMillisecs);
    } catch {}
  }

async function importMetaMaskWallet(logger, page) {
    logger.debug('\033[94mTrying to import MetaMask connect...\033[0m');

    const credentials = JSON.parse(fs.readFileSync('metamask_credentials.json'));

    // Click get started button
    const get_started_button = await page.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div/div/button');
    await page.evaluate($submit => $submit.click(), get_started_button);

    // Click no thanks button
    const no_thanks_button = await page.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div/div/div[5]/div[1]/footer/button[1]');
    await page.evaluate($submit => $submit.click(), no_thanks_button);

    // Click import button
    const import_connect_button = await page.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div/div[2]/div/div[2]/div[1]/button');
    await page.evaluate($submit => $submit.click(), import_connect_button);

    // Type passphrase
    for (let i = 0; i < 12; i++) {
        const fill_phrase = await page.waitForXPath('//*[@id="import-srp__srp-word-' + i + '"]');
        await fill_phrase.type(credentials.passphrase[i]);
    }

    // Type password
    const fill_password = await page.waitForXPath(' //*[@id="password"]');
    await fill_password.type(credentials.password);
    const fill_password2 = await page.waitForXPath(' //*[@id="confirm-password"]');
    await fill_password2.type(credentials.password);

    // Click agree button
    const click_agree_button = await page.waitForXPath('//*[@id="create-new-vault__terms-checkbox"]');
    await page.evaluate($submit => $submit.click(), click_agree_button);

    // Click submit button
    const submit_button = await page.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div/div[2]/form/button');
    await page.evaluate($submit => $submit.click(), submit_button);

    // Click all done button
    const all_done_button = await page.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div/button');
    await page.evaluate($submit => $submit.click(), all_done_button);

    logger.debug('\033[92mImporting MetaMask wallet was successful!\033[0m');
 }

 async function connectMetaMaskWallet(logger, page, browser, args) {
    await waitForNavigation(page, 10000);

    let connect = '';
    let metamask = '';

    let connected = false;
    let connect_label = '';
    let metamask_label = '';

    let url = page.url();
    let html = await page.content();

    // Close let's get started dialogs
    try {
      const button = await page.waitForXPath(`//*[text()="Maybe later"]`, {timeout: 200});
      await button.click();
    } catch {}
    try {
      const button = await page.waitForXPath(`//*[text()=" I Know "]`, {timeout: 200});
      await button.click();
    } catch {}

    // Click menu button
    try {
      const button = await page.waitForXPath(`//*[text()="account_cicle"]`, {timeout: 200});
      await button.click();
    } catch {}

    // Search for possible connect buttons in the html
    let connect_buttons = []
    for (const x of CONNECT_STRINGS) {
      if (html.includes(x)) {
        connect_buttons.push(x);
      }
    }
    logger.debug('Identified connect buttons: ');
    logger.debug(connect_buttons);

    // Try to click one of the possible connect buttons
    for (const connect_button_string of connect_buttons) {
      try {
        const connect_button = await page.waitForXPath(`//*[text()="${connect_button_string}"]`, {timeout: 200});
        await page.evaluate($submit => $submit.click(), connect_button);
        connect = `//*[text()="${connect_button_string}"]`;
        connect_label = connect_button_string;
        logger.debug(`Found connect button: ${connect_button_string}`);
        break;
      } catch {
        try {
          // Also try to click it via its coordinates
          const connect_button = await page.waitForXPath(`//*[normalize-space(text())="${connect_button_string}"]`, {timeout: 200});
          const rect = await page.evaluate(el => {
            const {x, y} = el.getBoundingClientRect();
            return {x, y};
          }, connect_button);
          await page.mouse.click(rect.x + 3, rect.y + 3);
          connect = `//*[normalize-space(text())="${connect_button_string}"]`;
          connect_label = connect_button_string;
          logger.debug(`Found connect button: ${connect_button_string}`);
          break;
        } catch {
          try {
            const title = await page.$x(`//*[@title="${connect_button_string}"]`);
            await title[0].click();
            connect_label = connect_button_string;
            logger.debug(`Found connect button: ${connect_button_string}`);
            break;
          } catch {}
        }
      }
    }

    // If no 'connect button' was found, we try the less precise 'contains method'
    if (connect == "") {
      for (const connect_button_string of connect_buttons) {
        try {
          let connect_button = await page.$x(`//button[contains(text(), "${connect_button_string}")]`);
          await connect_button[0].click();
          connect = `//button[contains(text(), "${connect_button_string}")]`;
          connect_label = connect_button_string;
          logger.debug(`Found connect button: ${connect_button_string}`);
          break;
        } catch {}
      }
    }

    // Close let's get started dialogs
    try {
      const button = await page.waitForXPath(`//*[text()="Get started"]`, {timeout: 200});
      await button.click();
    } catch {}

    let checkbox_clicked = false;
    let d = new Date();
    let start = d.getTime();

    let metamask_buttons = [];
    let reason = '';
    let scanned_for_metamask_buttons = false;

    while (true) {
      // Timeout for the while loop
      d = new Date();
      let now = d.getTime();
      if ((now-start) > 30000) {
        reason = 'timeout';
        logger.debug('Exiting while loop: Timeout!');
        break;
      }

      // We have a metamask popup open
      let pages = await browser.pages();
      if (pages.length > 2) {
        reason = "popup";
        logger.debug('Exiting while loop: MetaMask popup open!');
        break;
      }

      await waitForNavigation(page, 2000);
      html = await page.content();
      html = html.replace(/&amp;/g, '&');

      // Search for MetaMask button
      if (metamask == '') {
        if ((scanned_for_metamask_buttons == true) && (connect != '')) {
          for (const connect_button_string of connect_buttons) {
            try {
              let connect_button = await page.$x(`//button[contains(text(), "${connect_button_string}")]`);
              await connect_button[0].click();
            } catch {}
          }
        }

        // First we check for 'metamask connect' strings in the html
        for (const x of METAMASK_STRINGS) {
          if (html.includes(x)) {
            if (!metamask_buttons.includes(x)) {
              metamask_buttons.push(x);
            }
          }
        }
        logger.debug('Identified MetaMask buttons:');
        logger.debug(metamask_buttons);

        // We check for if we can click any of the metamask strings
        for (const metamask_button_string of metamask_buttons) {
          // First we try to find an explicit button with the metamask string
          await waitForNavigation(page, 400);
          try {
            const button = await page.$x(`//button[contains(text(), "${metamask_button_string}")]`);
            await button[0].click();
            metamask = button[0];
            metamask_label = metamask_button_string;
            logger.debug('Found MetaMask button: '+metamask_button_string);
            break;
          } catch {
            // Otherwise we try to find any other element with the mm string
            try {
              const metamask_button = await page.waitForXPath(`//*[(text())="${metamask_button_string}"]`, {timeout: 200});
              const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, metamask_button);
              await page.mouse.click(rect.x + 1, rect.y + 1);
              metamask = `//*[(text())="${metamask_button_string}"]`;
              metamask_label = metamask_button_string;
              logger.debug('Found MetaMask button: '+metamask_button_string);
              break;
            } catch {}
          }
        }
        scanned_for_metamask_buttons = true;
      // Already found MetaMask button previously
      } else {
        if (connect != '') {
          const connect_button = await page.waitForXPath(connect, {timeout: 200});
          const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, connect_button);
          await page.mouse.click(rect.x + 1, rect.y + 1);
        }
        try {
          if (typeof metamask === 'string' || metamask instanceof String) {
            const metamask_button = await page.waitForXPath(metamask, {timeout: 200});
            const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, metamask_button);
            await page.mouse.click(rect.x + 1, rect.y + 1);
          } else {
            await metamask.click();
          }
        } catch {}
      }

      await waitForNavigation(page, 2000);

      // Try to find a checkbox (e.g. agree to terms)
      // We also 'force click' this checkbox and do it after first checking the metamask strings
      // Since we might click some other unrelated checkbox
      // We only click this box once, otherwise we would unclick it for the loop iteration
      try {
        let checkbox = await page.waitForXPath('//input[@type="checkbox"]', {timeout: 500});
        logger.debug('Found checkbox!');
        if (checkbox_clicked == false) {
          const rect = await page.evaluate(el => {
            const {x, y} = el.getBoundingClientRect();
            return {x, y};
          }, checkbox);
          await page.mouse.click(rect.x + 1, rect.y + 1);
          checkbox_clicked = true;
          logger.debug('Checkbox clicked! Trying option 1...');
        } else {
          await page.evaluate($submit => $submit.click(), checkbox);
          await page.evaluate($submit => $submit.click(), checkbox);
          logger.debug('Checkbox clicked! Trying option 2...');
        }
        if (metamask != '') {
          try {
            if (typeof metamask === 'string' || metamask instanceof String) {
              const metamask_button = await page.waitForXPath(metamask, {timeout: 200});
              const rect = await page.evaluate(el => { const {x, y} = el.getBoundingClientRect(); return {x, y}; }, metamask_button);
              await page.mouse.click(rect.x + 1, rect.y + 1);
            } else {
              await metamask.click();
            }
          } catch {}
        }
      } catch {
        logger.debug('No checkbox found!');
      }

      await waitForNavigation(page, 2000);

    } // end while
    logger.debug("End of while loop: "+reason)

    let popup = null;
    let pages = await browser.pages();

    // Semi-good workaround for the non-visible mm buttons
    if ((reason == 'timeout') && (pages.length <= 2)) {
      try {
        logger.debug("Trying random clicks...")
        const dimensions = await page.evaluate(() => {
          return {
            width: document.documentElement.clientWidth,
            height: document.documentElement.clientHeight,
          };
        });
        logger.debug('Screen dimensions:');
        logger.debug(dimensions);

        await page.mouse.click(dimensions.width/2, dimensions.height/2);
        logger.debug('Random click at: '+(dimensions.width/2)+' '+(dimensions.height/2));

        await page.mouse.click(dimensions.width/2, dimensions.height/2-50);
        logger.debug('Random click at: '+(dimensions.width/2)+' '+(dimensions.height/2-50));

        await page.mouse.click(dimensions.width/2, dimensions.height/2-100);
        logger.debug('Random click at: '+(dimensions.width/2)+' '+(dimensions.height/2-100));

        await page.mouse.click(dimensions.width/2, dimensions.height/2-150);
        logger.debug('Random click at: '+(dimensions.width/2)+' '+(dimensions.height/2-150));

        await page.mouse.click(dimensions.width/2+150, dimensions.height/2+75);
        logger.debug('Random click at: '+(dimensions.width/2+150)+' '+(dimensions.height/2+75));

        await page.mouse.click(dimensions.width/2-100, dimensions.height/2-100);
        logger.debug('Random click at: '+(dimensions.width/2-100)+' '+(dimensions.height/2-100));

        await page.mouse.click(dimensions.width/2, dimensions.height/2+100);
        logger.debug('Random click at: '+(dimensions.width/2)+' '+(dimensions.height/2+100));

        // Close any accidentially openend pages that were opened due to the random clicks
        pages = await browser.pages();
        for (let i = 0; i < pages.length; i++) {
          const domain = url.split('//')[1].split('?')[0].split('/')[0];
          if ((!pages[i].url().startsWith('chrome-extension://')) && (!pages[i].url().includes(domain))) {
            pages[i].close();
          }
        }

        await waitForNavigation(page, 4000);
      } catch {
        logger.debug('Random click failed!');
      }
    }

    await waitForNavigation(page, 4000);

    if ((reason == 'timeout') && (connect != '') && (metamask != '')) {
      try {
        const buttons = await page.$x(connect);
        await buttons[0].click();
      } catch {}
      try {
        const button = await page.waitForXPath(metamask, {timeout: 200});
        await page.evaluate($submit => $submit.click(), button);
      } catch {}
      try {
        const button = await page.waitForXPath(`//*[normalize-space(text())="Select"]`, {timeout: 200});
        await page.evaluate($submit => $submit.click(), button);
      } catch {}
    }

    pages = await browser.pages();
    // Most metamask popups are opened as a new page
    if (pages.length > 2) {
      popup = pages[pages.length - 1];
    } else {
      // Sometimes a metamask popup is not visible to puppeteer as a new page and we force-open it ourselfs
      popup = pages[pages.length - 1];
      for (const p of pages) {
        if (p.url().includes('home.html')) {
          popup_url = p.url().slice(0, p.url().lastIndexOf('home.html'))+'notification.html';
          await popup.goto(popup_url);
          break;
        }
      }
      await popup.bringToFront();
    }

    // Connect metamask wallet
    try {
      const next_button = await popup.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div[3]/div[2]/button[2]');
      await popup.evaluate($submit => $submit.click(), next_button);
      logger.debug('Clicked next button!');
      const continue_button = await popup.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div[2]/div[2]/div[2]/footer/button[2]');
      await popup.evaluate($submit => $submit.click(), continue_button);
      logger.debug('Clicked continue button!');
      connected = true;
      logger.debug('\033[92mSuccessfully connected MetaMask wallet!\033[0m');
    } catch {
      logger.debug('No metamask popup found!');
    }

    try {
      pages = await browser.pages();
      if (pages.length > 2) {
        await page.bringToFront();
      }
    } catch {}

    // Some websites require to click on "Continue" after connecting
    try {
      const button = await page.waitForXPath(`//*[text()="Continue"]`, {timeout: 200});
      await button.click();
    } catch {}
    try {
      const button = await page.waitForXPath(`//*[text()="Continue"]`, {timeout: 200});
      await button.click();
    } catch {}

    // Provide signature or approve and switch network
    let signature_request = false;
    try {
      await waitForNavigation(page, 4000);
      pages = await browser.pages();
      let popup = pages[pages.length - 1];
      const sign_button = await popup.waitForXPath('//*[@id="app-content"]/div/div[2]/div/div[3]/button[2]');
      await popup.evaluate($submit => $submit.click(), sign_button);
      logger.debug('Clicked on sign button!');

    } catch {}
    let switch_network = false;
    try {
      const approve_button = await popup.waitForXPath(`//*[text()="Approve"]`, {timeout: 200});
      await approve_button.click();
      const switch_button = await popup.waitForXPath(`//*[text()="Switch network"]`, {timeout: 200});
      await switch_button.click();
      logger.debug('Clicked on approve and switch network button!');
    } catch {}

    if ((!signature_request) && (!switch_network)) {
      logger.debug('No sign or approve button found!');
      try {
        await page.reload({waitUntil: "domcontentloaded"});
      } catch {}
    }

    return [connected, connect_label, metamask_label, checkbox_clicked, signature_request, switch_network]
}

module.exports = {
    importMetaMaskWallet,
    connectMetaMaskWallet
};
