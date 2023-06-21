/* eslint-env browser */

// simple simulation of known web3-based wallets

module.exports = () => {
    Reflect.defineProperty(window, 'test', {
      get: () => (
        {
          test: 'test'
        }
      )
    });

    Reflect.defineProperty(window, 'cardano', {
      get: () => (
        {
          nami: {
            name: 'Nami Wallet'
          }
        }
      )
    });

    Reflect.defineProperty(window, 'solana', {
      get: () => (
        {
          isPhantom: true
        }
      )
    });

    Reflect.defineProperty(window, 'coinbaseSolana', {
      get: () => (
        {
          isCoinbaseWallet: true
        }
      )
    });

    Reflect.defineProperty(window, 'BinanceChain', {
      get: () => (
        {
          chainId: '0x38'
        }
      )
    });

    Reflect.defineProperty(window, 'ethereum', {
      get: () => (
        {
          isMetaMask: true,
          isCoinbaseWallet: true
        }
      )
    });

    Reflect.defineProperty(window, 'CoinbaseWalletSDK', {
      get: () => (
        {
          isCoinbaseWallet: true
        }
      )
    });
};
