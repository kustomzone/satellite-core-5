const assert = require('assert');
const ganache = require('ganache-cli');
const Web3 = require('web3');

const abi = require('../abi.json');
const bytecode = require('../bytecode.json');

const web3 = new Web3(ganache.provider({ gasLimit: 8000000 }));
const { utf8ToHex, hexToUtf8 } = web3.utils;

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const DEFAULT_GAS = '1000000';

const utf8ToBytes20 = (utf8) => {
	const zeros = '0000000000000000000000000000000000000000';
	const hex = utf8ToHex(utf8);
	return hex + zeros.substring(0, 42 - hex.length);
};

let accounts;
let contract;

describe('contract', () => {

	it('deployed test contract', async () => { // Deploy local version for testing
		accounts = await web3.eth.getAccounts();
		contract = await new web3.eth.Contract(abi).deploy({
			data: bytecode
		}).send({
			from: accounts[0],
			gas: '8000000'
		});
	});


	///////////////////////////////////////////////////////
	/****************** createID() ******************/

	const createID = (params) => {
		const {
			name,
			recovery
		} = {
			name: 'user0',
			recovery: ZERO_ADDRESS,
			...params // Specified params override defaults
		}

		return contract.methods.createID(
			utf8ToHex(name),
			recovery
		);
	};

	it('creates user accounts with recovery address', async () => {
		let ok = true;
		try {
			await createID({
				recovery: accounts[9]
			}).send({
				from: accounts[0],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it('prevents creation of user id using same recovery address', async () => {
		let ok = false;
		try {
			await createID({
				name: 'user1',
				recovery: accounts[9]
			}).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('creates user id without recovery address (user1)', async () => {
		let ok = true;
		try {
			await createID({
				name: 'user1'
			}).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it('creates user id without recovery address (user2)', async () => {
		let ok = true;
		try {
			await createID({
				name: 'user2'
			}).send({
				from: accounts[2],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it('checks if accounts exist', async () => {
		const isNotAvailable = await contract.methods.nameAvailable(utf8ToHex('user0')).call();
		const isAvailable = await contract.methods.nameAvailable(utf8ToHex('not_a_user')).call();
		assert(!isNotAvailable && isAvailable);
	});

	it('prevents registration of existing id name', async () => {
		let ok = false;
		try {
			await createID({
				name: 'user0'
			}).send({
				from: accounts[2],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('prevents registering id with an address that has already been linked', async () => {
		let ok = false;
		try {
			await createID({
				name: 'not_a_user' // name has not been used
			}).send({
				from: accounts[0], // Address has already been used
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('prevents registering id with empty name', async () => {
		let ok = false;
		try {
			await createID({
				name: ''
			}).send({
				from: accounts[3],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('prevents registering an id where the primary address and recovery address are the same', async () => {
		let ok = false;
		try {
			await createID({
				name: 'not_a_user',
				recovery: accounts[4]
			}).send({
				from: accounts[4],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});


	/////////////////////////////////////////////////////////
	/****************** setPrimary() ******************/

	it ('prevents non-owners from changing primary address', async () => {
		let ok = false;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				accounts[4]
			).send({
				from: accounts[1], // Not the primary address of user0
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it ('prevents setting zero address as primary address', async () => {
		let ok = false;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				ZERO_ADDRESS
			).send({
				from: accounts[0],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it ('prevents setting the same address as primary address', async () => {
		let ok = false;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				accounts[0]
			).send({
				from: accounts[0],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it ('allows user to change primary address', async () => {
		let ok = true;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				accounts[4]
			).send({
				from: accounts[0],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it ('prevents changing primary address to an address that has ever been linked', async () => {
		let ok = false;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				accounts[0] // Previous primary address
			).send({
				from: accounts[4], // New primary address
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it ('prevents changing primary address to an address that has ever been used as recovery address', async () => {
		let ok = false;
		try {
			await contract.methods.setPrimary(
				utf8ToHex('user0'),
				accounts[9] // Previous primary address
			).send({
				from: accounts[4], // New primary address
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});


	////////////////////////////////////////////////////////////
	/****************** setRecovery() ******************/

	it('prevents setting an address that has ever been linked as recovery address on existing account', async () => {
		let ok = false;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user1'),
				accounts[0]
			).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('prevents setting zero address as recovery address on existing account', async () => {
		let ok = false;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user1'),
				ZERO_ADDRESS
			).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('prevents setting current address as recovery address on existing account', async () => {
		let ok = false;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user1'),
				accounts[1]
			).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('allows user to set recovery address on existing id without recovery address', async () => {
		let ok = true;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user1'),
				accounts[8]
			).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it ('prevents user from setting recovery address on existing id that already has recovery address', async () => {
		let ok = false;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user1'),
				accounts[7]
			).send({
				from: accounts[1],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});


	/////////////////////////////////////////////////
	/****************** recover() ******************/

	it ('prevents address other than recovery address from calling recover', async () => {
		let ok = false;
		try {
			await contract.methods.recover(
				utf8ToHex('user0')
			).send({
				from: accounts[0], // Not the recovery address
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = true;
		}
		assert(ok);
	});

	it('allows user to recover their id', async () => {
		let ok = true;
		try {
			await contract.methods.recover(
				utf8ToHex('user0'),
				ZERO_ADDRESS
			).send({
				from: accounts[9],
				gas: DEFAULT_GAS
			});
			const acct = await contract.methods.directory(accounts[9]).call()
			ok = hexToUtf8(acct) === 'user0';
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});

	it('allows user to set the recovery address', async () => {
		let ok = true;
		try {
			await contract.methods.setRecovery(
				utf8ToHex('user0'),
				accounts[7]
			).send({
				from: accounts[9],
				gas: DEFAULT_GAS
			});
		} catch (err) {
			ok = false;
		}
		assert(ok);
	});
});
