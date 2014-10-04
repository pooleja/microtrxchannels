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
var Builder = bitcore.TransactionBuilder;
var Bignum = bitcore.Bignum;

var rpcConfig = require('./config/rpc.js');
var RpcClient = bitcore.RpcClient;
var rpc = new RpcClient(rpcConfig);


var ChannelStates = require('./defines/ChannelStates.js');
var config = require('./config/config.js');
var rpcConfig = require('./config/rpc.js');

var mongoose = require('mongoose');
var Channel = require('./models/channel.js');

var opts = {
   network: config.NETWORK
};

var request = require('request');

var t1Transaction = null;
var t2Transaction = null;
var multisigScript = null;

var ClientKey;
var serverWalletKey;
var originalAddr;

var FEE_AMOUNT = 0.0001;

function getUnspentOutputs(address, callback){

   request("http://test-insight.bitpay.com/api/addr/" + address + "/utxo", function (error, response, body) {
      if (!error && response.statusCode == 200) {

      var info = JSON.parse(body);
      console.log("done ajax call to getUnspentOutputs");
      console.log(info);
      callback(null, info);

     }else{
      condole.log("Call Failed to getUnspentOutputs");
      console.log(error);
      callback(data, null);
     }

   });

}

var serverPublicAddress;

function buildT2(){

   var OUR_VOUT = 0; // TODO: do not hardcode
   var refundTx = new Transaction();
   refundTx.version = 1;
   refundTx.lock_time = 0;

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
   var scriptOut = Script.createPubKeyHashOut(originalAddr.payload());
   scriptOut.updateBuffer();

   // Calculate the value being sent (minus fee)
   var paymentAmtBn = coinUtil.valueToBigInt(t1Transaction.outs[OUR_VOUT].v);
   paymentAmtBn = paymentAmtBn.sub(2 * FEE_AMOUNT * coinUtil.COIN);
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
      v: coinUtil.bigIntToValue(Bignum(FEE_AMOUNT * coinUtil.COIN)),
      s: scriptOut.getBuffer(),
   });
   refundTx.outs.push(txout2);

   t2Transaction = refundTx;

   console.log("Finished creating unsigned T2 transaction refunding all money back to client after X time.");
   console.log("T2 Transaction Hex: " + buffertools.toHex(t2Transaction.serialize()));

   var sigHash = t2Transaction.hashForSignature(multisigScript, 0, Transaction.SIGHASH_ALL);

   console.log("Sighash: " + buffertools.toHex(sigHash));

   // sign TX ourselves
   var k1_sig_raw = ClientKey.signSync(sigHash);
   var sigType = new Buffer(1);
   sigType[0] = Transaction.SIGHASH_ALL;
   var k1_sig = Buffer.concat([k1_sig_raw, sigType]);
   console.log("k1_sig");
   console.log(buffertools.toHex(k1_sig));

   var k2_sig_raw = serverWalletKey.privKey.signSync(sigHash);
   sigType = new Buffer(1);
   sigType[0] = Transaction.SIGHASH_ALL;
   var k2_sig = Buffer.concat([k2_sig_raw, sigType]);
   console.log("k2_sig");
   console.log(buffertools.toHex(k2_sig));

   // build P2SH multi-sig signature script. update TX input.
   var scriptSig = new Script();
   scriptSig.prependOp0();
   scriptSig.writeBytes(k1_sig);
   scriptSig.writeBytes(k2_sig);
   scriptSig.writeBytes(multisigScript.getBuffer());
   scriptSig.updateBuffer();

   console.log("finishedMultiSig:");
   console.log(scriptSig.finishedMultiSig());

   console.log("ScriptSig:");
   console.log(scriptSig.toString());

   console.log("multi chunks len: " + multisigScript.chunks.length);
   console.log("scriptSig chunks len: " + scriptSig.chunks.length);

   console.log("multisigScript");
   console.log(buffertools.toHex(multisigScript.getBuffer()));

   console.log("k1_sig");
   console.log(buffertools.toHex(scriptSig.chunks[0]));

   console.log("k2_sig");
   console.log(buffertools.toHex(scriptSig.chunks[1]));


   // update TX input with signatures
   t2Transaction.ins[0].s = scriptSig.getBuffer();
   t2Transaction.ins[0].q = 0;

   console.log("Hash");
   console.log(t2Transaction.checkHash());
   t2Transaction.calcHash();
   console.log(t2Transaction.checkHash());

   console.log(t2Transaction.verifyInput(0, multisigScript, null, function(error, results){
      console.log(error);
      console.log(results);
   }));
   //broadcastTransaction(t1Transaction);
   //setTimeout(broadcastTransaction(t2Transaction), 5000);

   console.log("T1:");
   console.log(buffertools.toHex(t1Transaction.serialize()));

   console.log("T2:");
   console.log(buffertools.toHex(t2Transaction.serialize()));

}

function createT1(){

   console.log("Building T1");

   var privateKey = bitcore.util.sha256("my secret");

   ClientKey = new Key();
   ClientKey.private = privateKey;
   ClientKey.regenerateSync();

   // generate a new key
   serverWalletKey = new WalletKey({network: config.NETWORK});
   serverWalletKey.generate();

   // get obj
   var obj = serverWalletKey.storeObj();
   serverPublicAddress = obj.addr;

   serverPublicKey = obj.pub;
   var clientPublicKey = ClientKey.public.toString('hex');

   var pubKeyHash = coinUtil.sha256ripe160(ClientKey.public);
   originalAddr = new Address(config.NETWORK.addressVersion, pubKeyHash);

   var pubkeys = [new Buffer(clientPublicKey, 'hex'), new Buffer(serverPublicKey, 'hex')];
   console.log("Public Keys");
   console.log(pubkeys);



   getUnspentOutputs(originalAddr, function(err, outputs){

      if(err){
         console.log("Failed to get unspent outputs for address:" + serverPublicKey);
         return;
      }

      var initialAmount = 0.001;

      console.log("Creating infoForP2sh");
      var infoForP2sh   = Builder.infoForP2sh({
         nreq    :2,
         pubkeys: pubkeys,
         amount  : initialAmount,
      }, config.NETWORK);

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
         console.log(exception);
         return;
      }

      console.log("Signing T1");

      var s = new WalletKey({
         network: config.NETWORK
      });
      s.fromObj({ priv: ClientKey.private.toString('hex')});

      b.sign([s]);

      console.log("Calling build");
      t1Transaction = b.build();

      console.log("Finished creating T1");
      console.log(t1Transaction);

      console.log(t1Transaction.ins[0].s);

      buildT2();
   });
}

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

createT1();
