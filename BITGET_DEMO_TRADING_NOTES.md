# Bitget Demo Trading REST Notes

Date checked: 2026-06-23

Sources:

- Demo trading REST: https://www.bitget.com/api-doc/common/demotrading/restapi
- Futures place order: https://www.bitget.com/api-doc/contract/trade/Place-Order
- Futures contract list: https://www.bitget.com/api-doc/contract/market/Get-All-Symbols-Contracts
- Signature: https://www.bitget.com/api-doc/common/signature
- Demo pair reference: https://www.bitget.com/support/articles/12560603790031

## Confirmed API Boundary

Bitget demo trading uses a Demo API Key and the normal REST host. The demo REST
document requires the request header `paptrading: 1` for demo API calls.

The current futures v2 order endpoint is:

```text
POST https://api.bitget.com/api/v2/mix/order/place-order
```

The current futures v2 product type table lists:

```text
USDT-FUTURES
USDC-FUTURES
COIN-FUTURES
```

For this project the demo execution gate defaults to:

```text
symbol=BTCUSDT
productType=USDT-FUTURES
marginCoin=USDT
```

The current REST contract list queried with `paptrading: 1` exposes standard
contract symbols such as `BTCUSDT`, `ETHUSDT`, and `SOLUSDT`. `BTCUSDT` supports
`USDT` margin and a `minTradeNum` of `0.0001`; the project default order size is
`0.0001`. The REST demo mode is selected by the Demo API Key plus `paptrading: 1`,
not by changing the base URL.

Bitget also enforces a minimum order amount of `5 USDT`. A fresh demo account
with `0` available USDT will authenticate successfully but reject order placement
until virtual demo funds are added in the Bitget demo futures account.

## Authentication

Required REST headers:

```text
ACCESS-KEY
ACCESS-SIGN
ACCESS-TIMESTAMP
ACCESS-PASSPHRASE
Content-Type: application/json
locale: en-US
```

Signature input:

```text
timestamp + METHOD + requestPath + "?" + queryString + body
```

If there is no query string, omit the question mark and query string:

```text
timestamp + METHOD + requestPath + body
```

Signature algorithm:

```text
BASE64(HMAC-SHA256(secretKey, signature_input))
```

## Local Safety Rule

Playbook Redline execution is demo-only by default. Mainnet order placement must
remain blocked unless `REDLINE_ALLOW_MAINNET_ORDER=1` and the API call also
passes an explicit per-call confirmation flag.
