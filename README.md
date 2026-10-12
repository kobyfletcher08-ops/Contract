# Kintsugi BSC rescue contracts

Contracts for the Kintsugi Windows + BSC package, ready to compile and deploy through [Remix IDE](https://remix.ethereum.org/).

## Compiler settings

| Setting | Value |
| --- | --- |
| Solidity | 0.8.28 |
| Optimizer | Enabled, 200 runs |
| EVM target | Cancun |
| OpenZeppelin dependency | 5.6.1, pinned in Rescue.sol |

## Deploy on BNB Smart Chain

1. Load `NonceTracker.sol` and `Rescue.sol` into the same Remix folder.
2. Compile using the settings above.
3. In Deploy & Run, use Browser Extension or WalletConnect with a clean wallet on BSC, chain ID 56. Leave Value at 0.
4. Deploy **NonceTracker** first and copy its deployed address.
5. Deploy **Rescue**, supplying the NonceTracker address as its constructor argument.
6. Enter both public contract addresses in Kintsugi's BSC network screen.

Deployment requires native BNB for gas. Each deployment is approved in the connected wallet.

BSC settings: PancakeSwap MEV Guard New, RPC `https://bscrpc.pancakeswap.finance`, gas currency BNB, explorer [BscScan](https://bscscan.com).

## Source

From [ophelios-studio/kintsugi](https://github.com/ophelios-studio/kintsugi), version 0.9.4, commit `92b479b154dec7499396cb3cc7011de7230e7bfb`. The OpenZeppelin import is pinned for reproducible Remix compilation; contract behavior is unchanged. Both files have the upstream MIT SPDX license identifier.

The compiler settings and contracts were checked against the Windows package's BSC bytecode validation before publishing these source files.
