import { Address, FeeBumpTransaction, TransactionBuilder, xdr, type Asset } from "@stellar/stellar-sdk";
import { emptyParsed, flag, parseUnits, type ParsedTx } from "./policy";

const QUIET_OPS = new Set(["changeTrust", "manageData", "endSponsoringFutureReserves", "bumpSequence"]);

const OP_LABELS: Record<string, string> = {
  setOptions: "Change the account's signers or thresholds",
  accountMerge: "Close the account and move its balance",
  beginSponsoringFutureReserves: "Pay reserves for another account",
};

/** Only operations sourced from the account can use its signature. */
export function parseStellarTransaction(
  envelope: string,
  networkPassphrase: string,
  account: string,
): ParsedTx {
  const parsed = emptyParsed();
  let tx = TransactionBuilder.fromXDR(envelope, networkPassphrase);
  if (tx instanceof FeeBumpTransaction) {
    if (tx.feeSource === account) flag(parsed, "Pay the network fee for another transaction");
    tx = tx.innerTransaction;
  }

  for (const op of tx.operations) {
    if ((op.source ?? tx.source) !== account) continue;
    switch (op.type) {
      case "payment":
        parsed.spends.push({ asset: assetId(op.asset), amount: stroops(op.amount), decimals: 7 });
        parsed.lines.push({ kind: "send", amount: trimAmount(op.amount), asset: assetCode(op.asset), to: op.destination });
        break;
      case "createAccount":
        parsed.spends.push({ asset: "XLM", amount: stroops(op.startingBalance), decimals: 7 });
        parsed.lines.push({ kind: "send", amount: trimAmount(op.startingBalance), asset: "XLM", to: op.destination });
        break;
      case "invokeHostFunction":
        readHostFunction(parsed, op.func);
        break;
      default:
        if (!QUIET_OPS.has(op.type)) flag(parsed, OP_LABELS[op.type] ?? `Stellar operation ${op.type}`);
    }
  }
  return parsed;
}

export function parseStellarAuthEntry(preimageXdr: Uint8Array): ParsedTx {
  const parsed = emptyParsed();
  const preimage = xdr.HashIdPreimage.fromXDR(Buffer.from(preimageXdr));
  if (preimage.switch() !== xdr.EnvelopeType.envelopeTypeSorobanAuthorization()) {
    flag(parsed, "Unknown authorization");
    return parsed;
  }
  readInvocation(parsed, preimage.sorobanAuthorization().invocation());
  return parsed;
}

function readInvocation(parsed: ParsedTx, invocation: xdr.SorobanAuthorizedInvocation): void {
  const fn = invocation.function();
  if (fn.switch() === xdr.SorobanAuthorizedFunctionType.sorobanAuthorizedFunctionTypeContractFn()) {
    const call = fn.contractFn();
    readContractCall(parsed, call.contractAddress(), call.functionName().toString());
  } else {
    flag(parsed, "Deploy a contract");
  }
  for (const sub of invocation.subInvocations()) readInvocation(parsed, sub);
}

function readHostFunction(parsed: ParsedTx, func: xdr.HostFunction): void {
  if (func.switch() !== xdr.HostFunctionType.hostFunctionTypeInvokeContract()) {
    flag(parsed, "Deploy or upload a contract");
    return;
  }
  const call = func.invokeContract();
  readContractCall(parsed, call.contractAddress(), call.functionName().toString());
}

function readContractCall(parsed: ParsedTx, address: xdr.ScAddress, method: string): void {
  flag(parsed, `Call ${method}`, Address.fromScAddress(address).toString());
}

function assetId(asset: Asset): string {
  return asset.isNative() ? "XLM" : `${asset.getCode()}:${asset.getIssuer()}`;
}

function assetCode(asset: Asset): string {
  return asset.isNative() ? "XLM" : asset.getCode();
}

function trimAmount(amount: string): string {
  return amount.includes(".") ? amount.replace(/\.?0+$/, "") : amount;
}

function stroops(amount: string): bigint {
  return parseUnits(amount, 7);
}
