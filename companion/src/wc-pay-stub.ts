// Stand-in for @walletconnect/pay (aliased in vite.config.ts). WalletKit only creates a Pay client
// when `WalletConnectPay.isAvailable()` is true; Phone Vault doesn't use WalletConnect Pay, so this
// keeps its ~290 KB wasm and its payment API endpoint out of the app.
export class WalletConnectPay {
  static isAvailable(): boolean { return false; }
}
