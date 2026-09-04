package dev.phonevault.signer;

import org.json.JSONObject;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.utils.Numeric;

final class EvmSigner {
    private EvmSigner() {}

    static JSONObject sign(Eip1559Request request, Credentials credentials) throws Exception {
        RawTransaction transaction = RawTransaction.createTransaction(
                request.chainId,
                request.nonce,
                request.gasLimit,
                request.to,
                request.value,
                request.data,
                request.maxPriorityFeePerGas,
                request.maxFeePerGas);
        byte[] signed = TransactionEncoder.signMessage(transaction, credentials);
        String signedHex = Numeric.toHexString(signed);
        return new JSONObject()
                .put("id", request.id)
                .put("status", "approved")
                .put("address", credentials.getAddress())
                .put("signedTransaction", signedHex)
                .put("transactionHash", Numeric.toHexString(Hash.sha3(signed)));
    }
}
