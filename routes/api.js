var express = require('express');
var router = express.Router();

var bitcore = require('bitcore');
var WalletKey = bitcore.WalletKey;
var RpcClient = bitcore.RpcClient;
var Transaction = bitcore.Transaction;
var Wallet = bitcore.Wallet;
var Script = bitcore.Script;
var buffertools = bitcore.buffertools;
var coinUtil = bitcore.util;
var Address = bitcore.Address;
var Key = bitcore.Key;
var bignum = bitcore.Bignum;

var rpcConfig = require('../config/rpc.js');
var RpcClient = bitcore.RpcClient;
var rpc = new RpcClient(rpcConfig);


var ChannelStates = require('../defines/ChannelStates.js');
var config = require('../config/config.js');
var rpcConfig = require('../config/rpc.js');

var mongoose = require('mongoose');
var Channel = require('../models/channel.js');

function broadcastTransaction(trx){

	console.log("Sending trx");
	console.log(JSON.stringify(trx));
	rpc.sendRawTransaction(buffertools.toHex(trx.serialize()), function(err, ret){
		if(err){
			console.log("Failed to send transaction.");
			console.log(err);
		}else{
			console.log("Successfully sent trx");
		}
	});

}

function decodeHexTx(hexStr)
{
	var reHex = /^[0-9a-zA-Z]+$/;
	if (!reHex.test(hexStr))
		return undefined;
	if ((hexStr.length % 2) == 1)
		return undefined;

	var txbuf = new Buffer(hexStr, 'hex');
	var tx = new Transaction();
	tx.parse(txbuf);

	return tx;
}

function getScriptAddressString(script){
	var buf = script.getBuffer();
	var hash = coinUtil.sha256ripe160(buf);
	var addr = new Address(config.NETWORK.P2SHVersion, hash);
	return addr.as('base58');
}

function validateT2(req, res, channel){

	var transactionT2Hex = 0;
	if(req.body.transactionT2Hex && req.body.transactionT2Hex !== null){
		transactionT2Hex = req.body.transactionT2Hex;
		console.log("transactionT2Hex :" + transactionT2Hex);
	}
	else{
		res.json ( {success : "false", error: "Required \'transactionT2Hex\' params parameter missing."});
		return;
	}

	var t2Transaction = decodeHexTx(transactionT2Hex);

	// build scriptPubKey according to standard protocol
	var pubkeys = [new Buffer(channel.clientPublicKey, 'hex'), new Buffer(channel.serverPublicKey, 'hex')];
	var scriptPubKey = Script.createMultisig(2, pubkeys);
	scriptPubKey.updateBuffer();

	// Create a Key for the servier's private key
	var serverKey = new bitcore.Key();
	serverKey.private = new Buffer(channel.serverPrivateKey, 'hex');
	serverKey.regenerateSync();

	// sign T1, paying to T2, without having ever seen T1
	var txSigHash = t2Transaction.hashForSignature(scriptPubKey, 0, Transaction.SIGHASH_ALL);

	console.log("Signing scriptPubKey: " + scriptPubKey);
	console.log("Signing txSigHash: " + buffertools.toHex(txSigHash));

	var sigRaw = serverKey.signSync(txSigHash);
	var sigType = new Buffer(1);
	sigType[0] = Transaction.SIGHASH_ALL;
	var sig = Buffer.concat([sigRaw, sigType]);
	var sigHex = buffertools.toHex(sig);

	var multisigAddress = getScriptAddressString(scriptPubKey);
	console.log("Address for multisig is " + multisigAddress);

	channel.multisigAddress = multisigAddress;
	channel.t2Transaction = transactionT2Hex;
	channel.state = ChannelStates.STATE_WAITING_FOR_FUNDING;
	channel.t2Signature = sigHex;

	channel.save(function (err) {
		if(err){
			res.json ( {success : "false", error: "Failed to update channel."});
			return;
		}

		var resultSubset = {
			id : channel.id,
			expireDate : channel.expireDate,
			state : channel.state,
			clientPublicKey : channel.clientPublicKey,
			serverPublicKey : channel.serverPublicKey,
			t2Signature : channel.t2Signature
		};

		console.log("Successfully updated T2 signature for channel " + channel.id);

		res.json({success : "true", result: resultSubset });
	});
}

function fundChannel(req, res, channel){

	// Get T1
	var transactionT1Hex = 0;
	if(req.body.transactionT1Hex && req.body.transactionT1Hex !== null){
		transactionT1Hex = req.body.transactionT1Hex;
		console.log("transactionT1Hex :" + transactionT1Hex);
	}
	else{
		res.json ( {success : "false", error: "Required \'transactionT1Hex\' params parameter missing."});
		return;
	}
	var t1Transaction = decodeHexTx(transactionT1Hex);

	// Get T3
	var transactionT3Hex = 0;
	if(req.body.transactionT3Hex && req.body.transactionT3Hex !== null){
		transactionT3Hex = req.body.transactionT3Hex;
		console.log("transactionT3Hex :" + transactionT3Hex);
	}
	else{
		res.json ( {success : "false", error: "Required \'transactionT3Hex\' params parameter missing."});
		return;
	}
	var t3Transaction = decodeHexTx(transactionT3Hex);

	// Validate T1
	var ctxInfo = validCommitTx(t1Transaction, channel.multisigAddress);
	if (!ctxInfo.result){
		res.json ( {success : "false", error: "commit tx invalid"});
		return;
	}

	// Validate T3
	var ptxInfo = validFirstPay(channel, ctxInfo, t1Transaction, t3Transaction);
	if (!ptxInfo.result){
		res.json ( {success : "false", error: "firstPayment tx invalid"});
		return;
	}

	// Broadcast the T1 transaction to lock in the payment
	broadcastTransaction(t1Transaction);

	channel.state = ChannelStates.STATE_OPEN;
	channel.t1Transaction = transactionT1Hex;
	channel.t3Transaction = transactionT3Hex;
	channel.valueToClientSat = ptxInfo.val_cli;
	channel.valueToServerSat = ptxInfo.val_srv;
	channel.t3TransactionInputIndex = ptxInfo.inIdx;
	channel.t3TransactionClientOutputIndex = ptxInfo.cliOutIdx;
	channel.t3TransactionServerOutputIndex = ptxInfo.srvOutIdx;

	channel.save(function (err) {
		if(err){
			res.json ( {success : "false", error: "Failed to open channel."});
			return;
		}

		var resultSubset = {
			id : channel.id,
			expireDate : channel.expireDate,
			state : channel.state,
			clientPublicKey : channel.clientPublicKey,
			serverPublicKey : channel.serverPublicKey,
		};

		console.log("Successfully updated T1 and T3 transactions for channel " + channel.id);

		res.json({success : "true", result: resultSubset });
	});
}

function validCommitTx(tx, msigAddrStr)
{
	var msigAddr = new Address(msigAddrStr);
	var scriptHashStr = msigAddr.payload().toString();

	var match = -1;
	for (var i = 0; i < tx.outs.length; i++){
		if (matchScript(tx.outs[i].s, scriptHashStr))
			match = i;
	}

	if (match < 0) {
		return { result: false };
	}

	var curtime = new Date();
	if (tx.lock_time > curtime.getTime()) {
		return { result: false };
	}

	return { result: true, idx: match };
}

function matchScript(scriptBuf, scriptHashStr)
{
	var script = new Script(scriptBuf);
	return (script.isP2SH() &&
		script.chunks[1].toString() == scriptHashStr);
}

function validFirstPay(channel, ctxInfo, txCommit, txFirstPay)
{
	// ensure txFirstPay is connected to txCommit's matched output
	var outpt = { hash: txCommit.getHash(), n: ctxInfo.idx };
	var inIdx = findTxOutpt(txFirstPay, outpt);
	if (inIdx < 0) {
		console.log("vfp: txoutpt");
		return { result: false };
	}

	console.log("In index: " + inIdx);

	var txin = txFirstPay.ins[inIdx];
	if (txin.q > 0xffffff) {
		console.log("vfp: seq");
		return { result: false };
	}

	// load K1
	var k1_pubkeyBuf = new Buffer(channel.clientPublicKey, 'hex');
	var k1_pubkey = new Key();
	k1_pubkey.public = k1_pubkeyBuf;

	// load K2
	var k2_pubkeyBuf = new Buffer(channel.serverPublicKey, 'hex');
	var k2_pubkey = new Key();
	k2_pubkey.public = k2_pubkeyBuf;

	// sig empty-sig p2sh-script
	var scriptSig = new Script(txin.s);
	if (scriptSig.chunks.length != 4) {
		console.log("vfp: ssiglen");
		return { result: false };
	}
	var k1_sig = scriptSig.chunks[1];
	console.log(scriptSig);

	// locate the outputs directed to us, and to the client
	var cliOutIdx = findOutByAddr(txFirstPay, k1_pubkey.public);
	var srvOutIdx = findOutByAddr(txFirstPay, k2_pubkey.public);
	if ((cliOutIdx < 0) || (srvOutIdx < 0) || (cliOutIdx == srvOutIdx)) {
		console.log("vfp: outidx");
		console.dir(cliOutIdx);
		console.dir(srvOutIdx);
		return { result: false };
	}

	var val_in = coinUtil.valueToBigInt(txCommit.outs[ctxInfo.idx].v);
	var val_cli = coinUtil.valueToBigInt(txFirstPay.outs[cliOutIdx].v);
	var val_srv = coinUtil.valueToBigInt(txFirstPay.outs[srvOutIdx].v);
	var fee = bignum(0);

	var val_out = val_cli.add(val_srv);
	val_out = val_out.add(fee);

	if (val_in.lt(val_out)) {
		console.log("vfp: val i/o");
		return { result: false };
	}


	var inScript = new Script(scriptSig.chunks[3]);
	var sigHash = txFirstPay.hashForSignature(inScript, inIdx, Transaction.SIGHASH_ALL);

	console.log("Verifying t1Script:" + inScript);
	console.log("Verifying hash:" + buffertools.toHex(sigHash));
	console.log("With public key: " + channel.clientPublicKey);

	// check client signature
	if (!k1_pubkey.verifySignatureSync(sigHash, k1_sig)) {
		console.log("vfp: cli sig");
		return { result: false };
	}

	return {
		result: true,
		inIdx: inIdx,
		cliOutIdx: cliOutIdx,
		srvOutIdx: srvOutIdx,
		val_in: val_in.toString(),
		val_cli: val_cli.toString(),
		val_srv: val_srv.toString(),
		fee: fee.toString(),
	};
}

function findOutByAddr(tx, pubkey)
{
	var pkh = coinUtil.sha256ripe160(pubkey);
	var pkhStr = pkh.toString();
	for (var i = 0; i < tx.outs.length; i++) {
		var txout = tx.outs[i];
		var script = new Script(txout.s);
		if (script.isPubkeyHash() &&
			script.chunks[2].toString() == pkhStr)
			return i;
	}

	return -1;
}

function findTxOutpt(tx, outpt)
{
	var hashStr = outpt.hash.toString();
	for (var i = 0; i < tx.ins.length; i++) {
		var txin = tx.ins[i];
		if ((txin.getOutpointIndex() == outpt.n) &&
			(txin.getOutpointHash().toString() == hashStr))
			return i;
	}

	return -1;
}

function updateChannel(req, res, channel){

	var clientSignature = null;
	if(req.body.signature && req.body.signature !== null){
		clientSignature = new Buffer(req.body.signature, 'hex');
		console.log("req.body.signature :" + req.body.signature);
	}
	else{
		res.json ( {success : "false", error: "Required \'signature\' params parameter missing."});
		return;
	}

	var paymentAmount = null;
	if(req.body.paymentAmount && req.body.paymentAmount !== null){
		paymentAmount = parseInt(req.body.paymentAmount);
		console.log("req.body.paymentAmount :" + req.body.paymentAmount);
	}
	else{
		res.json ( {success : "false", error: "Required \'signature\' params parameter missing."});
		return;
	}

	// load K1
	var k1_pubkeyBuf = new Buffer(channel.clientPublicKey, 'hex');
	var k1_pubkey = new Key();
	k1_pubkey.public = k1_pubkeyBuf;

	// move value cli -> srv
	var val_cli = bignum(channel.valueToClientSat);
	val_cli = val_cli.sub(paymentAmount);
	var val_srv = bignum(channel.valueToServerSat);
	val_srv = val_srv.add(paymentAmount);

	var buf = new Buffer(channel.t3Transaction, 'hex');
	var tx = new Transaction();
	tx.parse(buf);


	var txin = tx.ins[channel.t3TransactionInputIndex];

	// update input sequence number
	txin.q++;

	// update signature in scriptSig
	var scriptSig = new Script(txin.s);
	scriptSig.chunks[1] = clientSignature;
	scriptSig.updateBuffer();

	// reduce client's output
	var txout = tx.outs[channel.t3TransactionClientOutputIndex];
	txout.v = coinUtil.bigIntToValue(val_cli);

	// increase server's output
	var txout2 = tx.outs[channel.t3TransactionServerOutputIndex];
	txout2.v = coinUtil.bigIntToValue(val_srv);

	// check client signature on updated TX. TODO: update this post-test
	var inScript = new Script(scriptSig.chunks[3]);
	var sigHash = tx.hashForSignature(inScript, 0, Transaction.SIGHASH_ALL);
	if (!k1_pubkey.verifySignatureSync(sigHash, clientSignature)){
		res.json ( {success : "false", error: "\'signature\' param invalid."});
		return;
	}

	// update TX input with signatures
	tx.ins[channel.t3TransactionInputIndex].s = scriptSig.getBuffer();

	// store updated payment TX
	channel.t3Transaction = buffertools.toHex(tx.serialize());
	channel.valueToClientSat = val_cli.toString();
	channel.valueToServerSat = val_srv.toString();

	channel.save(function (err) {
		if(err){
			res.json ( {success : "false", error: "Failed to save payment channel."});
			return;
		}

		var resultSubset = {
			id : channel.id,
			state : channel.state,
			valueToClientSat : channel.valueToClientSat,
			valueToServerSat : channel.valueToServerSat
		};

		console.log("Successfully updated payment amounts for channel " + channel.id);

		res.json({success : "true", result: resultSubset });
	});
}

function closeChannel(req, res, channel){

	// Get the latest T3 transaction
	var buf = new Buffer(channel.t3Transaction, 'hex');
	var tx = new Transaction();
	tx.parse(buf);

	// Get the input transaction
	var txin = tx.ins[channel.t3TransactionInputIndex];
	var scriptSig = new Script(txin.s);

	// Get the script to sign
	var inScript = new Script(scriptSig.chunks[3]);
	var sigHash = tx.hashForSignature(inScript, 0, Transaction.SIGHASH_ALL);

	// Create a Key for the server's private key
	var serverKey = new bitcore.Key();
	serverKey.private = new Buffer(channel.serverPrivateKey, 'hex');
	serverKey.regenerateSync();

	// Sign the script
	var sigRaw = serverKey.signSync(sigHash);
	var sigType = new Buffer(1);
	sigType[0] = Transaction.SIGHASH_ALL;
	var sig = Buffer.concat([sigRaw, sigType]);

	// Update the sig and save it back to the tx buffer
	scriptSig.chunks[2] = sig;
	scriptSig.updateBuffer();

	tx.ins[channel.t3TransactionInputIndex].s = scriptSig.getBuffer();

	// Broadcast the finalized payment
	broadcastTransaction(tx);

	// Update the latest transaction and state
	channel.t3Transaction = buffertools.toHex(tx.serialize());
	channel.state = ChannelStates.STATE_CLOSED;

	// Save it off
	channel.save(function (err) {
		if(err){
			res.json ( {success : "false", error: "Failed to save payment channel for close."});
			return;
		}

		var resultSubset = {
			id : channel.id,
			state : channel.state
		};

		console.log("Successfully closed channel " + channel.id);

		res.json({success : "true", result: resultSubset });
	});

}

router.put('/channels/:id', function(req, res) {

	// The request param ID is the channel ID
	var channelId = req.params.id;

	// Find the referenced channel
	Channel.findOne({id: channelId}, function(err, currentChannel){
		if(err || !currentChannel ){
			res.json ( {success : "false", error: "Failed to find valid channel."});
			return;
		} else {

			// The channel was found in the DB, now check the current state
			if(currentChannel.state == ChannelStates.STATE_WAITING_FOR_T2){
				// We are waiting for T2 to sign
				validateT2(req, res, currentChannel);

			} else if(currentChannel.state == ChannelStates.STATE_WAITING_FOR_FUNDING){
				// We are waiting for T1 and T3 to finalize the channel
				fundChannel(req, res, currentChannel);

			} else if(currentChannel.state == ChannelStates.STATE_OPEN){
				// The channel is open... update the payment amount
				updateChannel(req, res, currentChannel);

			}else{
				res.json ( {success : "false", error: "Channel is in invalid state."});
			}
		}
	});
});

router.delete('/channels/:id', function(req, res) {

	// The request param ID is the channel ID
	var channelId = req.params.id;
	console.log("Close channel requested for " + channelId);

	// Find the referenced channel
	Channel.findOne({id: channelId}, function(err, currentChannel){
		if(err || !currentChannel ){
			res.json ( {success : "false", error: "Failed to find valid channel."});
			return;
		} else {

			if(currentChannel.state == ChannelStates.STATE_OPEN){
				closeChannel(req, res, currentChannel);
			}else{
				res.json ( {success : "false", error: "Channel must be open."});
			}

		}
	});
});

router.post('/channels', function(req, res) {

	console.log("Creating new channel");
	//console.log(req);

	var clientPublicKey = 0;
	if(req.body.clientPublicKey && req.body.clientPublicKey !== null){
		clientPublicKey = req.body.clientPublicKey;
		console.log("Client public key:" + clientPublicKey);
	}
	else{
		res.json ( {success : "false", error: "Required \'clientPublicKey\' params parameter missing."});
		return;
	}

	// generate a new key
	var newKey = new WalletKey({network: config.NETWORK});
	newKey.generate();

	// get obj
	var obj = newKey.storeObj();

	// get creation date
	var birthday = obj.created;

	// derive channel id (aka bitcoin address) from new key
	var channelId = obj.addr;

	// Get the expiration date for the channel
	var timelock = birthday + config.TIMELOCK_PREFER;

	var createdChannel = {
		id : channelId,
		creationDate : birthday,
		state : ChannelStates.STATE_WAITING_FOR_T2,
		clientPublicKey : clientPublicKey,
		serverPrivateKey : buffertools.toHex(newKey.privKey.private),
		serverPublicKey : obj.pub,
		expireDate : timelock
	};

	// Add the new Channel to Mongo DB
	Channel(createdChannel)
	.save(function (err, tempChannel) {
		if (err){
			res.json({success : "false", error: err});
		}else{

			var resultSubset = {
				id : tempChannel.id,
				expireDate : tempChannel.expireDate,
				state : tempChannel.state,
				clientPublicKey : tempChannel.clientPublicKey,
				serverPublicKey : tempChannel.serverPublicKey
			};

			console.log("Successfully created channel id: " + tempChannel.id);

			res.json({success : "true", result: resultSubset });
		}
	});

});


module.exports = router;
