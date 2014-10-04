// The Address model

var mongoose = require('mongoose');

var channelSchema = mongoose.Schema({

	id: {type: String, required: true, unique: true},

	state: String,

	clientPublicKey: String,

	serverPrivateKey : String,
	serverPublicKey : String,

	creationDate: Number,
	expireDate: Number,

	t1Transaction: String,
	t2Transaction: String,
	t3Transaction: String,

	multisigAddress: String,
	t2Signature: String,

	valueToServerSat: String,
	valueToClientSat: String,

	t3TransactionInputIndex: Number,
	t3TransactionClientOutputIndex: Number,
	t3TransactionServerOutputIndex: Number
});

module.exports = mongoose.model('Channel', channelSchema);

