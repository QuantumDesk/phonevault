#!/usr/bin/env bash
# A REAL Bitcoin SIGNET round trip with the phone (signet coins have no value; never mainnet):
#   1. btc-account signet P2WPKH account 1 (shared on the phone if not yet)
#   2. btc-show receive address 0: shown on the phone, == the answer, == derived here from the xpub
#   3. print that address and wait for a coin (mempool.space signet Esplora). A PERSON funds it
#      from a signet faucet: this script never contacts a faucet (they have CAPTCHAs).
#   4. build a PSBT spending every coin at …/0/0: half to receive address …/0/1, change to …/1/0,
#      at the recommended half-hour fee rate; witness_utxo + non_witness_utxo + BIP-32 derivations
#   5. btc-sign on the phone ("Send … sBTC", "Your own address ✓", change ✓; the script ticks the
#      review box and signs)
#   6. verify on the host with embit (only our key signed each input, every signature verifies,
#      outputs and fee exactly as planned), finalize, broadcast (POST /signet/api/tx)
#   7. wait until mempool.space sees it and (up to PV_SIGNET_CONFIRM_WAIT s) until it confirms
#
# Resumable: everything is kept in $PV_SIGNET_DIR (default /root/pv-signet). A rerun skips what is
# done (account, address, broadcast txid) and continues; delete that directory to start over.
#   --address-only   stop after step 3's address (do not wait for funds)
#
# Needs the btctest.sh environment plus PV_SIGNET_TOOL (tools/btc_signet.py, default next to
# PV_BTC_TOOL) and HTTPS access to mempool.space from the host.
source "$(dirname "$0")/lib.sh"
require_throwaway
require_dev_appliance
require_pin
STATE="${PV_SIGNET_DIR:-/root/pv-signet}"
OUT="$STATE/log"
source "$(dirname "$0")/btclib.sh"
SIGNET="${PV_SIGNET_TOOL:-$(dirname "$TOOL")/btc_signet.py}"
[[ -s "$SIGNET" ]] || die "signet tool not staged ($SIGNET)"
FUND_WAIT="${PV_SIGNET_FUND_WAIT:-3600}"
CONFIRM_WAIT="${PV_SIGNET_CONFIRM_WAIT:-2400}"
ADDRESS_ONLY=0; [[ "${1:-}" == "--address-only" ]] && ADDRESS_ONLY=1
mkdir -p "$STATE"; chmod 700 "$STATE"
S() { "$PY" "$SIGNET" "$@"; }
wake  # a sleeping screen (e.g. after a reboot) has no window to read
unlock_if_locked

# ---- 1. the account (watch-only xpub)
step "1 account"
if [[ -s "$STATE/account.json" ]]; then
  pass "account kept from an earlier run: $(grep -o '"descriptor": "[^"]*' "$STATE/account.json" | cut -c16-60)…"
else
  ensure_account1
  start_client account btc-account --network signet --type p2wpkh --account 1
  share_if_asked
  finish_client account 0
  json_of "$OUT/account.out" > "$STATE/account.json"
  grep -q '"path": "m/84'"'"'/1'"'"'/0'"'"'"' "$STATE/account.json" || { rm -f "$STATE/account.json"; die "unexpected path"; }
  [[ "$SHARED_HOW" == asked ]] && leave_outcome
  pass "signet account 1 ($SHARED_HOW): $(grep -o '"descriptor": "[^"]*' "$STATE/account.json" | cut -c16-60)…"
fi
ADDR0="$(S derive --account "$STATE/account.json" --index 0)"
ADDR1="$(S derive --account "$STATE/account.json" --index 1)"

# ---- 2. receive address 0, shown on the phone
step "2 address"
if [[ -s "$STATE/address0" && "$(cat "$STATE/address0")" == "$ADDR0" ]]; then
  pass "address 0 confirmed on the phone in an earlier run"
else
  start_client show btc-show --network signet --type p2wpkh --account 1 --change 0 --index 0
  wait_screen "Compare with your Mac"
  expect_screen "Bitcoin SIGNET"
  SHOWN="$(uidump | grep -o 'text="tb1q[^"]*' | head -1 | sed 's/^text="//; s/&#10;//g; s/ //g' || true)"
  find_text "Done: it matches" || die "no Done button: $(texts 10)"
  tap_text "Done: it matches"; sleep 2
  finish_client show 0
  GOT="$(grep -o '"address": "[^"]*' "$OUT/show.out" | cut -c13- || true)"
  [[ -n "$SHOWN" && "$SHOWN" == "$GOT" && "$GOT" == "$ADDR0" ]] \
    || die "address mismatch: phone showed '$SHOWN', answered '$GOT', derived here '$ADDR0'"
  echo "$ADDR0" > "$STATE/address0"
  pass "address 0 on the phone == answered == derived from the xpub here"
fi

# ---- 3. funding (by a person)
step "3 funding"
if [[ -s "$STATE/txid" ]]; then
  pass "already broadcast in an earlier run"
else
  cat <<EOF

  ==================================================================================
    FUND THIS SIGNET ADDRESS (signet test coins only; any amount >= 2,000 sats):

        $ADDR0

    https://mempool.space/signet/address/$ADDR0
  ==================================================================================

EOF
  [[ $ADDRESS_ONLY -eq 1 ]] && { STEP="done"; echo "Stopping here (--address-only). Rerun without it once funded."; exit 0; }
  echo "   waiting up to ${FUND_WAIT}s for a coin (rerun to keep waiting)…"
  S wait-utxo --address "$ADDR0" --timeout "$FUND_WAIT" > "$STATE/utxos.json" \
    || die "no coin arrived at $ADDR0 within ${FUND_WAIT}s; fund it and rerun this script"
  pass "funded: $(cat "$STATE/utxos.json")"
fi

if [[ ! -s "$STATE/txid" ]]; then
  # ---- 4. the PSBT (fresh each attempt: coins, fee rate)
  step "4 build"
  S build --account "$STATE/account.json" --out "$STATE/unsigned.psbt" --plan "$STATE/plan.json" > "$OUT/plan.out" \
    || die "could not build the PSBT: $(tail -2 "$OUT/plan.out")"
  # The phone titles a payment to its own RECEIVE address "Send …" (marked "Your own address ✓");
  # only change-only transactions read "Move … within your wallet".
  TITLE="$("$PY" -c 'import json,sys; v=json.load(open(sys.argv[1]))["outputs"][0]["value"]; print("Send %d.%08d sBTC" % (v // 10**8, v % 10**8))' "$STATE/plan.json")"
  pass "PSBT built: $("$PY" -c 'import json,sys; p=json.load(open(sys.argv[1])); print("%d in, %s, fee %d (%d sat/vB)" % (p["total_in"], " + ".join("%d to %s" % (o["value"], o["path"]) for o in p["outputs"]), p["fee"], p["fee_rate"]))' "$STATE/plan.json")"

  # ---- 5. sign on the phone
  step "5 sign"
  rm -f "$STATE/signed.psbt"
  start_client sign btc-sign --network signet --psbt "$STATE/unsigned.psbt" --out "$STATE/signed.psbt"
  wait_screen "$TITLE"
  expect_below "Bitcoin SIGNET"
  expect_below "YOUR OWN ADDRESS ✓"
  if [[ "$("$PY" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["outputs"]))' "$STATE/plan.json")" == 2 ]]; then
    expect_below "CHANGE BACK TO YOUR WALLET"
  else
    echo "note: coin too small to split: whole coin sent to …/0/1, no change output"
  fi
  expect_below "NETWORK FEE"
  if [[ "$("$PY" -c 'import json,sys; p=json.load(open(sys.argv[1])); print(int(p["fee"] * 10 > p["outputs"][0]["value"]))' "$STATE/plan.json")" == 1 ]]; then
    # A tiny faucet coin: the fee is more than 10% of what is sent, so the phone must say so.
    expect_below "DANGER"
    echo "note: fee is over 10% of the amount sent; the phone flagged it as DANGER (correct)"
  else
    expect_not "DANGER"
  fi
  approve_review
  finish_client sign 0
  [[ -s "$STATE/signed.psbt" ]] || die "no signed PSBT written"
  pass "signed on the phone after review ($TITLE)"
  leave_outcome

  # ---- 6. verify, finalize, broadcast
  step "6 verify + broadcast"
  S finalize --account "$STATE/account.json" --plan "$STATE/plan.json" --unsigned "$STATE/unsigned.psbt" \
    --signed "$STATE/signed.psbt" --out "$STATE/tx.json" > "$OUT/finalize.out" || die "host verification failed: $(tail -2 "$OUT/finalize.out")"
  pass "verified on the host (embit): $(cat "$OUT/finalize.out")"
  TXID="$(S broadcast --tx "$STATE/tx.json")" || die "broadcast failed"
  echo "$TXID" > "$STATE/txid"
  pass "broadcast: $TXID"
fi

# ---- 7. seen / confirmed
step "7 confirm"
TXID="$(cat "$STATE/txid")"
S wait-confirm --txid "$TXID" --timeout "$CONFIRM_WAIT" | tee "$OUT/confirm.out" || die "mempool.space never saw $TXID"
if grep -q '"confirmed": true' "$OUT/confirm.out"; then pass "confirmed: $(tail -1 "$OUT/confirm.out")"
else echo "NOTE: seen in the mempool but not confirmed within ${CONFIRM_WAIT}s (signet blocks ~10 min); rerun to keep waiting"; fi
STEP="done"
echo "SIGNET ROUND TRIP: txid $TXID"
echo "  https://mempool.space/signet/tx/$TXID"
