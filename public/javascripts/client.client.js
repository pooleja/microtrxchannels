var bitcore = require('bitcore');
var Message = bitcore.Message;
var Base58 = bitcore.Base58;
var Address = bitcore.Address;
var Builder = bitcore.TransactionBuilder;
var Buffer = bitcore.Buffer;
var WalletKey = bitcore.WalletKey;
var Transaction = bitcore.Transaction;
var Script = bitcore.Script;
var coinUtil = bitcore.util;
var Bignum = bitcore.Bignum;
var buffertools = bitcore.buffertools;
var Key = bitcore.Key;
var Peer = bitcore.Peer;
var PeerManager = bitcore.PeerManager;


var network = bitcore.networks['testnet'];

var t1Transaction = null;
var t2Transaction = null;
var t3Transaction = null;

var ClientKey = null;

var serverPublicKey = null;
var serverPublicAddress = null;
var multisigScript = null;
var expireDate = 0;
var FEE_AMOUNT = 0.0001;

// Grabs the address in the browser and retrieves the balance (confirmed + unconfirmed)
function updateBalance() {

	var address = $("#generated-address").text();

	//console.log("Getting balance for " + address);
	getUnspentOutputs(address, function(error, res){
		if(error){
			console.log("Failed to get utxo for " + address);
			$("#balance").text("Failed to get balance for address: " + address);
			return;
		}

		var unspentAmount = 0;
		var arrayLength = res.length;
		for (var i = 0; i < arrayLength; i++) {
		 	unspentAmount += parseFloat(res[i].amount);
		}

		$("#balance").text(unspentAmount + " BTC");
	});

}

/**
 * Fails the channel and logs the message and updates the UI
 * @param  {[type]} errorMsg
 * @return {[type]}
 */
function failChannel(errorMsg){
	console.log(errorMsg);

	if(errorMsg)
		$("#channel-status").text(errorMsg);
}

function getUnspentOutputs(address, callback){
	$.ajax({url: "http://test-insight.bitpay.com/api/addr/" + address + "/utxo", dataType: 'jsonp'})
	.done(function(res){

		console.log("done ajax call to getUnspentOutputs");
		callback(null, res);
	})
	.fail(function(data){
		condole.log("Call Failed to getUnspentOutputs");
		console.log(data);
		callback(data, null);
	});
}


function createT1(channelObj){

	console.log("Building T1");

	var serverPublicKey = $("#channel-status").data("server-public-key");
	var clientPublicKey = $("#channel-status").data("client-public-key");

	var pubkeys = [new Buffer(clientPublicKey, 'hex'), new Buffer(serverPublicKey, 'hex')];
	console.log("Public Keys");
	console.log(pubkeys);

	getUnspentOutputs($("#generated-address").text(), function(err, outputs){

		if(err){
			failChannel("Failed to get unspent outputs for address:" + serverPublicKey);
			return;
		}

		var initialAmount = parseFloat($('#initial-payment-amount').val());

		console.log("Creating infoForP2sh");
		var infoForP2sh   = Builder.infoForP2sh({
			nreq    :2,
			pubkeys: pubkeys,
			amount  : initialAmount,
		}, network.name);

		var outs = [{
			address:infoForP2sh.address,
			amount: initialAmount,
		}];

		var map = {};
		map[infoForP2sh.address]=infoForP2sh.scriptBufHex;

		multisigScript = infoForP2sh.script;

		console.log("Creating Builder");
		var b = null;

		try{
			b = new Builder({spendUnconfirmed: true})
			.setUnspent(outputs)
			.setHashToScriptMap(map)
			.setOutputs(outs);
		} catch (exception){
			console.log(exception);
			failChannel(exception);
			return;
		}

		console.log("Signing T1");
		var clientPrivateKey = $("#channel-status").data("client-private-key");
		console.log("Client private key: " + clientPrivateKey);

		var s = new WalletKey({
			network: network
		});
		s.fromObj({ priv: clientPrivateKey});

		b.sign([s]);

		console.log("Calling build");
		t1Transaction = b.build();

		console.log("Finished creating T1");
		console.log(t1Transaction);

		createUnsignedT2();
	});
}

function createUnsignedT2(){

	var OUR_VOUT = 0;	// TODO: do not hardcode
	var refundTx = new Transaction();
	refundTx.version = 1;
	refundTx.lock_time = expireDate;

	// T2 input 0: T1's output 0
	var commitTxHash = t1Transaction.getHash();
	var outpt = new Buffer(32 + 4);
	commitTxHash.copy(outpt);
	outpt.writeUInt32LE(OUR_VOUT, 32);
	var txin = new Transaction.In({
		o: outpt,
		q: 0xffffffff,
	});
	refundTx.ins.push(txin);

	// T2 output 0: 100% to K1
	var scriptOut = Script.createPubKeyHashOut(new Address($("#generated-address").text()).payload());
	scriptOut.updateBuffer();

	// Calculate the value being sent (minus fee)
	var paymentAmtBn = coinUtil.valueToBigInt(t1Transaction.outs[OUR_VOUT].v);
	paymentAmtBn = paymentAmtBn.sub(FEE_AMOUNT);
	var txout = new Transaction.Out({
		v: coinUtil.bigIntToValue(paymentAmtBn),
		s: scriptOut.getBuffer(),
	});
	refundTx.outs.push(txout);

	// T2 output 1: 0% to K2
	var k2_addr = new Address(serverPublicAddress);
	scriptOut = Script.createPubKeyHashOut(k2_addr.payload());
	scriptOut.updateBuffer();
	var txout2 = new Transaction.Out({
		v: coinUtil.bigIntToValue(Bignum(0)),
		s: scriptOut.getBuffer(),
	});
	refundTx.outs.push(txout2);

	t2Transaction = refundTx;

	console.log("Finished creating unsigned T2 transaction refunding all money back to client after X time.");
	console.log("T2 Transaction Hex: " + buffertools.toHex(t2Transaction.serialize()));

	sendUnsignedT2();
}

function sendUnsignedT2(){
	console.log('sendUnsignedT2');

	$.ajax({
		type: "PUT",
		url: "/api/v1/channels/" + serverPublicAddress,
		data: {  transactionT2Hex : buffertools.toHex(t2Transaction.serialize()) },
		dataType: "json"
	})
	.done(function(res){

		console.log("Send T2 call complete");
		console.log(res);

		// Verify the API call succeeded
		if(res.success != "true"){
			failChannel("Response to send unsigned T2 Failed");
			return;
		}

		// Verify the server signature of T2 and save the transaction in case we need it later (server dies)
		var k2_sig = new Buffer(res.result.t2Signature, 'hex');

		var k2_pubkeyBuf = new Buffer(serverPublicKey, 'hex');
		var k2_pubkey = new Key();
		k2_pubkey.public = k2_pubkeyBuf;


		// verify server signature for T2
		var sigHash = t2Transaction.hashForSignature(multisigScript, 0, Transaction.SIGHASH_ALL);

		console.log("Verifying t1Script:" + multisigScript);
		console.log("Verifying hash:" + buffertools.toHex(sigHash));
		console.log("With public key: " + serverPublicKey);

		if (!k2_pubkey.verifySignatureSync(sigHash, k2_sig)) {
			failChannel("Failed to validate T2 signature");
			return;
		}

		// sign TX ourselves
		var k1_sig_raw = ClientKey.signSync(sigHash);
		var sigType = new Buffer(1);
		sigType[0] = Transaction.SIGHASH_ALL;
		var k1_sig = Buffer.concat([k1_sig_raw, sigType]);

		// build P2SH multi-sig signature script. update TX input.
		var scriptSig = new Script();
		scriptSig.prependOp0();
		scriptSig.writeBytes(k1_sig);
		scriptSig.writeBytes(k2_sig);
		scriptSig.writeBytes(multisigScript.getBuffer());
		scriptSig.updateBuffer();

		// update TX input with signatures
		t2Transaction.ins[0].s = scriptSig.getBuffer();

		// Now that we have a valid refund t2Transaction we can safely fund the channel
		finalizeChannel();

	})
	.fail(function(data){
		failChannel("Failed to get response for sending Unsigned T2.");
		return;
	});

}

// Send T1 and T3 to the server to finalize channel
function finalizeChannel(){

	// Create T3  - payment TX begins life as refund TX, without signatures, new seq#
	t3Transaction = new Transaction(t2Transaction);
	t3Transaction.ins[0].s = coinUtil.EMPTY_BUFFER;
	t3Transaction.ins[0].q = 0;

	// Set up T3 with 0 amount going to server to start with
	updateT3(0);

	// Send transactions T1 and T3 to the server.  Server will broadcast T1 and hold on to T3 until the channel is closed (and then broadcast).
	$.ajax({
		type: "PUT",
		url: "/api/v1/channels/" + serverPublicAddress,
		data: {  transactionT1Hex : buffertools.toHex(t1Transaction.serialize()),
					transactionT3Hex : buffertools.toHex(t3Transaction.serialize()) },
		dataType: "json"
	})
	.done(function(res){

		console.log("Send T1 and T3 call complete");
		console.log(res);

		// Verify the API call succeeded
		if(res.success != "true"){
			failChannel("Response to send T1 and T3 Failed");
			return;
		}

		$("#channel-status").text("Channel Open");

		// Enable the pay and close channel buttons
		$("#pay-channel-button").removeAttr('disabled');
		$("#close-channel-button").removeAttr('disabled');
		$("#micro-payment-amount").removeAttr('disabled');

	})
	.fail(function(data){
		failChannel("Failed to get response for sending T1 and T3.");
		return;
	});

}

function updateT3(paymentVal)
{
	// update TX input sequence number
	t3Transaction.ins[0].q++;

	// test payment amount < channel amount
	var paymentAmtBn = Bignum(parseInt(paymentVal * coinUtil.COIN));
	var channelAmtBn = coinUtil.valueToBigInt(t3Transaction.outs[0].v);
	if (channelAmtBn.cmp(paymentAmtBn) < 0)
		return undefined;

	// remainder = channel - payment
	var remainderAmtBn = channelAmtBn.sub(paymentAmtBn);

	// update output #0 with remaining refund (unpaid) value
	t3Transaction.outs[0].v = coinUtil.bigIntToValue(remainderAmtBn);

	// calculate the new amount to be sent to payment channel
	var newPaymentAmountToServerBn = coinUtil.valueToBigInt(t3Transaction.outs[1].v);
	newPaymentAmountToServerBn = newPaymentAmountToServerBn.add(paymentAmtBn);

	// update output #1 with payment value
	t3Transaction.outs[1].v = coinUtil.bigIntToValue(newPaymentAmountToServerBn);

	$("#initial-payment-amount").val(remainderAmtBn.toNumber() / coinUtil.COIN);
	$("#sent-payment-amount").val(newPaymentAmountToServerBn.toNumber() / coinUtil.COIN);

	// sign payment transaction
	var sigHash = t3Transaction.hashForSignature(multisigScript, 0, Transaction.SIGHASH_ALL);

	console.log("Signing T3 Hash: " + buffertools.toHex(sigHash));

	var k1_sig_raw = ClientKey.signSync(sigHash);
	var sigType = new Buffer(1);
	sigType[0] = Transaction.SIGHASH_ALL;
	var k1_sig = Buffer.concat([k1_sig_raw, sigType]);

	// build P2SH multi-sig signature script. update TX input.
	var scriptSig = new Script();
	scriptSig.prependOp0();
	scriptSig.writeBytes(k1_sig);
	scriptSig.writeBytes(coinUtil.EMPTY_BUFFER);
	scriptSig.writeBytes(multisigScript.getBuffer());
	scriptSig.updateBuffer();

	// update TX input with signatures
	t3Transaction.ins[0].s = scriptSig.getBuffer();

	return k1_sig;
}

function updatePayment(){
	var amountToSend = parseFloat($("#micro-payment-amount").val());

	var sig = updateT3(amountToSend);

	$.ajax({
		type: "PUT",
		url: "/api/v1/channels/" + serverPublicAddress,
		data: { signature : sig.toString('hex'), paymentAmount : parseInt(amountToSend * coinUtil.COIN) },
		dataType: "json"
	})
	.done(function(res){

		console.log("Update T3 call complete");
		console.log(res);

		// Verify the API call succeeded
		if(res.success != "true"){
			failChannel("Response to update T3 Failed");
			return;
		}

	})
	.fail(function(data){
		failChannel("Failed to get response for updating T3.");
		return;
	});
}

function closeChannel(){
	$.ajax({
		type: "DELETE",
		url: "/api/v1/channels/" + serverPublicAddress,
		dataType: "json"
	})
	.done(function(res){

		console.log("Update T3 call complete");
		console.log(res);

		$("#channel-status").text("Channel Closed");

		// Enable the pay and close channel buttons
		$("#pay-channel-button").attr('disabled', 'disabled');
		$("#close-channel-button").attr('disabled', 'disabled');
		$("#micro-payment-amount").attr('disabled', 'disabled');

	})
	.fail(function(data){
		failChannel("Failed to get response for closing channel.");
		return;
	});
}

$( document ).ready(function() {

	$( "#create-key-form" ).submit(function( event ) {
		var secret = $("#secret-key-password").val();

		if(!secret){
			alert("Please enter a secret.");
		}else{
			var privateKey = bitcore.util.sha256(secret);

			ClientKey = new Key();
			ClientKey.private = privateKey;
			ClientKey.regenerateSync();

			console.log("Client Public key: " + ClientKey.public.toString('hex'));

			$("#channel-status").data("client-private-key", ClientKey.private.toString('hex'));
			$("#channel-status").data("client-public-key", ClientKey.public.toString('hex'));

			var hash = bitcore.util.sha256ripe160(ClientKey.public);
			var version = network.addressVersion;

			var addr = new bitcore.Address(version, hash);

			$("#generated-address").text(addr.toString());
			$("#qr-code").empty();
			$("#qr-code").qrcode({width: 96,height: 96,text: addr.toString()});

			console.log("Brain wallet address: " + addr.toString());
		}
		event.preventDefault();

		updateBalance();
		window.setInterval(updateBalance, 1000);
	});

	$( "#open-channel-button" ).click(function() {
		console.log("Opening Channel");
		event.preventDefault();

		var status = $("#channel-status").text();
		if(status != "CLOSED"){
			alert("Payment channel must be closed in order to open a new one.");
			failChannel(null);
			return;
		}

		// disable open channel button
		$("#open-channel-button").attr('disabled', 'disabled');
		$('#initial-payment-amount').attr('disabled', 'disabled');

		$("#channel-status").text("INITIALIZING");

		$.ajax({
			type: "POST",
			url: "/api/v1/channels",
			data: { clientPublicKey : ClientKey.public.toString('hex') },
			dataType: "json"
		})
		.done(function(res){

			console.log("channel call complete");
			console.log(res);

			// Verify the API call succeeded
			if(res.success != "true"){
				console.log("Channel response failed.");
				failChannel("Failure response for creating a new channel.");
				return;
			}

			// Verify the servers public key
			serverPublicKey = res.result.serverPublicKey;
			expireDate = res.result.expireDate;
			serverPublicAddress = res.result.id;

			$("#channel-status").text("Recieved public key from server: " + serverPublicKey);


			var serverAddr = Address.fromPubKey(new Buffer(serverPublicKey, 'hex'));
			if(!serverAddr.isValid()){
				failChannel("Server public key is invalid");
				return;
			}

			$("#channel-status").data("server-public-key", serverPublicKey);

			createT1(res.result);

		})
		.fail(function(data){
			console.log("Call to get new channel Failed");
			failChannel("Failed to get response for creating a new channel.");
			return;
		});
	});

	$( "#pay-channel-button" ).click(function() {
		console.log("Pay button clicked.");
		updatePayment();
	});

	$('#close-channel-button').click(function() {
		console.log("Close button clicked.");
		closeChannel();
	});

});
