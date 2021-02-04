const Directory = require('@satellite-earth/directory');
const Clock = require('@satellite-earth/clock');
const State = require('@satellite-earth/state');
const utils = require('@satellite-earth/utils');
const axios = require('axios');


/* Contract Constants */

const abi = require('./abi.json');

const Contract = {
	address: { '1': '0x7C9ed09cCb6723Fc42FBd9c5a83420a3D8fFCbE4' },
	deployed: { '1': 9975903 }
};


/* Helpers */

const defaults = {
	updateOnNetworkChange: true,
	useOwnProvider: false,
	network: 1 // As per EIP-155
};

const _tx = async (web3, tx, event) => {
	let checkConfirmed; // Interval to manually check confirmation
	let check = 0; // Number of times confirmation checked
	let limit = 10; // Max number of times to check confirmation
	tx.on('transactionHash', (hash) => {
		checkConfirmed = setInterval(async () => {
			if (check > limit) {
				clearInterval(checkConfirmed);
				event({ name: 'slow' });
			} else {
				check += 1;
				try { // Silently catch network errors on interval
					const receipt = await web3.eth.getTransactionReceipt(hash);
					if (receipt && receipt.blockNumber) { // Transaction mined
						clearInterval(checkConfirmed);
						event({
							name: receipt.status ? 'confirmed' : 'failed',
							data: receipt
						});
					}
				} catch (err) {
					console.log(err);
				}
			}
		}, 20000); // Assume 20 secs / block
		event({ name: 'hash', data: hash });
	}).on('error', () => {
		event({ name: 'error' });
	});
};


/* Nameserver Interface */

class Nameserver {

	constructor (endpoint) {
		this.endpoint = endpoint;
		this.map = { name: {}, addr: {} };
	}

	// Select address from records at block number
	getAddress (who, which, at) {
		const records = this.map.name[who] || [];
		for (let record of records) {
			const value = record[which];
			const match = at >= record.block;
			if (match && typeof value !== 'undefined') {
				return value;
			}
		}
	};

	getAlias (primary, options = {}) {

		// Alias that the address was linked to at some point
		const addr = primary.toLowerCase();
		const name = this.map.addr[addr];

		// If address has never been linked, return undefined
		if (typeof name === 'undefined') { return; }

		// If address matches address linked to alias at block number, return alias
		const _addr = this.getAddress(name, 'primary', options.at);
		if (_addr && _addr === addr) {
			return options.hex ? utils.utf8ToHex(name).slice(2) : name;
		}
	}

	// Make request to query data from remote
	// namespace server, for use client-side
	// e.g. displaying ID based on address.
	async query (fn, params = {}) {

		let uri = `${this.endpoint}/query?fn=${fn}`;
		for (let key of Object.keys(params)) {
			uri += `&${key}=${params[key]}`;
		}

		const res = await axios.get(uri);
		return res.data;
	}

	// Request multiple queries
	async batch (queries = []) {

		if (queries.length === 0) {
			return;
		}

		const res = await axios.put(`${this.endpoint}/batch`, queries);
		if (res.data.length !== queries.length) {
			throw Error('Nameserver returned invalid response');
		}

		return res.data;
	}

	// Build local data mapping of alias records
	async synchronize (names, toBlock) {

		const data = await this.batch(names.map(name => {

			const query = { fn: 'records', name };
			const existing = this.map.name[name];

			if (typeof existing !== 'undefined') {
				query.since = existing[0].block + 1;
			}

			return query;
		}));

		for (let z = 0; z < names.length; z++) {

			const records = data[z];
			const name = names[z]

			if (data.length > 0) {

				if (typeof this.map.name[name] === 'undefined') {
					this.map.name[name] = [];
				}

				this.map.name[name] = records.concat(this.map.name[name]);

				for (let record of records) {
					for (let item of [ 'primary', 'recovery' ]) {
						if (typeof record[item] !== 'undefined') {
							this.map.addr[record[item].toLowerCase()] = name;
						}
					}
				}
			}
		}
	}
}


/* High Level API */

class Earth {

	constructor () {

		// Create Ethereum clock
		this.clock = new Clock();

		// Create the alias directory
		this.directory = new Directory();

		// Nameserver endpoints
		this.nameserver = {};
	}

	// Create interface to namespace
	async addNameserver (endpoint) {

		// Contact the nameserver to get current signer
		const response = await axios.get(`${endpoint}/world/contact?signals=false&history=false&initial=false`);
		const { name } = response.data.current.epoch;

		if (typeof this.nameserver[name] !== 'undefined') {
			throw Error(`Namespace "${name}" has already been initialized`);
		}

		// Construct a new namespace interface
		this.nameserver[name] = new Nameserver(endpoint);
	}

	async connect (web3, options = {}) {

		const _options = { ...defaults, ...options };
		this.network = _options.network;
		this.web3 = web3;

		// By default, use injected provider when in browser
		if (typeof window !== 'undefined' && !_options.useOwnProvider) {
			
			if (window.ethereum) { // Provider detected

				this.provider = window.ethereum; // Use in-window provider

				if (!this.network) { // Network code not specified
					this.network = window.ethereum.networkVersion; // Detect from provider
					//this.network = utils.getActiveNetwork(); 
				}

				if (_options.updateOnNetworkChange) { // When user switches network
					this.provider.on('networkChanged', (code) => {
						this.network = code; // Update network code
					});
				}

			} else { // No injected provider
				console.warn('Ethereum wallet not detected');
			}

		}

		// If web3 instance was provided, create a model
		// of the contract for top level names
		if (this.web3) {

			// Web3 contract instance
			this.contract = await getContractInstance(this.web3);
		}
	}


	/* Identity API */

	// Create a new top level ID
	async createID ({ alias, primary, recovery }, event) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (!alias) {
			throw Error('Must provide alias');
		}

		if (utils.utf8ByteLength(alias) > 64) {
			throw Error('Alias length limited to 32 bytes');
		}

		if (!primary) {
			throw Error('Must provide primary address');
		}

		_tx(this.web3, this.contract.methods.createID(
			utils.utf8ToBytes32(alias),
			recovery ? recovery : utils.ZERO_ADDRESS
		).send({ from: primary }), event);
	}

	// Set a new primary address for top level ID
	async setPrimary ({ alias, newPrimary, from }, event) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		let _from = from;

		if (!_from) {
			_from = await this.getActiveAddress();
		}

		if (!alias) {
			throw Error('Must provide alias');
		}

		if (!newPrimary) {
			throw Error('Must provide \'newPrimary\'');
		}

		if (!utils.isAddress(newPrimary)) {
			throw Error('Value for \'newPrimary\' is not a valid Ethereum address');
		}

		if (!_from) {
			throw Error('Failed to detect sender address, please specify \'from\'');
		}

		_tx(this.web3, this.contract.methods.setPrimary(
			utils.utf8ToBytes32(alias),
			newPrimary
		).send({ from: _from }), event);
	}

	// Set a new recovery address for top level ID
	async setRecovery ({ alias, recovery, from }, event) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		let _from = from;

		if (!_from) {
			_from = await this.getActiveAddress();
		}

		if (!alias) {
			throw Error('Must provide alias');
		}

		if (!recovery) {
			throw Error('Must provide recovery');
		}

		if (!utils.isAddress(recovery)) {
			throw Error('Value for \'recovery\' is not a valid Ethereum address');
		}

		if (!_from) {
			throw Error('Failed to detect sender address, please specify \'from\'');
		}

		_tx(this.web3, this.contract.methods.setRecovery(
			utils.utf8ToBytes32(alias),
			recovery
		).send({ from: _from }), event);
	}

	// Recover top level ID (current recovery address becomes primary address)
	async recover ({ alias, recovery, newRecovery }, event) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (!alias) {
			throw Error('Must provide alias');
		}

		if (!recovery) {
			throw Error('Must provide recovery');
		}

		if (!utils.isAddress(recovery)) {
			throw Error('Value for \'recovery\' is not a valid Ethereum address');
		}

		_tx(this.web3, this.contract.methods.recover(
			utils.utf8ToBytes32(alias),
			(newRecovery || utils.ZERO_ADDRESS)
		).send({ from: recovery }), event);
	}

	// Check if a top level name is available for registration
	async nameAvailable (alias) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (!alias) {
			throw Error('Must provide alias');
		}

		return await this.contract.methods.nameAvailable(
			utils.utf8ToBytes32(alias)
		).call();
	}

	// Check if an address may be associated with a top level name
	async addressAvailable (address) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		return await this.contract.methods.addressAvailable(address).call();
	}

	// Lookup top level info by alias ID
	async lookupName (alias, options = {}) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (!alias) {
			throw Error('Must specify alias');
		}

		const citizen = await this.contract.methods.citizens(
			utils.utf8ToBytes32(alias)
		).call();

		return citizen[0] === utils.ZERO_ADDRESS ? null : {
			primary: citizen[0],
			recovery: citizen[1] === utils.ZERO_ADDRESS ? '' : citizen[1],
			joined: parseInt(citizen[2]),
			number: parseInt(citizen[3])
		};
	}

	// Lookup top level name by address
	async lookupAddress (address, options = {}) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (!address) {
			throw Error('Must specify address');
		}

		let hex;

		try {	// Verify directory directly from current state of blockchain

			if (options.includePast) {
				hex = await this.contract.methods.associate(address).call();
			} else {
				hex = await this.contract.methods.directory(address).call();
			}

		} catch (err) {
			throw Error('Failed to reach Ethereum provider');
		}

		return options.hex ? utils.zcut(hex) : utils.hexToUtf8(hex);
	}

	// Lookup top level name info by number
	async lookupNumber (number, options = {}) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		if (typeof number === 'undefined') {
			throw Error('Must specify number');
		}

		const info = await this.contract.methods.lookupNumber(String(number)).call();

		return info[0] === utils.ZERO_ADDRESS ? null : {
			primary: info[0],
			recovery: info[1] === utils.ZERO_ADDRESS ? '' : info[1],
			joined: parseInt(info[2]),
			name: options.hex ? utils.zcut(info[3]) : utils.hexToUtf8(info[3])
		};
	};


	/* Message API */

	async verifyData (message, domain) {

		const address = utils.addressData(message._signed_, message._params_.sig, domain);
		const namespace = message._params_.namespace;
		const author = { address };

		if (typeof namespace !== 'undefined') {
			
			if (namespace === null) { // Top level

				try {

					if (!this.contract) {
						throw Error('Missing Ethereum provider');
					}

					// Verify alias against Ethereum blockchain
					const hex = await this.contract.methods.directory(address).call();
					author.alias = utils.zcut(hex); // Strip hex prefix and trailing zeros
				
				} catch (networkErr) {
					throw Error('Failed to verify data from blockchain');
				}

			} else { // Federated

				if (typeof this.nameserver[namespace] === 'undefined') {
					throw Error(`Missing nameserver for '${namespace}'`);
				}

				try {

					// Verify alias against nameserver
					const utf8 = await this.nameserver[namespace].query('name', { address });
					if (typeof utf8 !== 'undefined') {
						author.alias = utils.utf8ToHex(utf8).slice(2);
					}
					
				} catch (networkErr) {
					throw Error('Failed to verify data from nameserver');
				}
			}

			if (typeof author.alias === 'undefined' || author.alias.length === 0) { // Alias not found
				throw Error('Failed to find alias linked to signing address');
			}
		}

		return author;
	};

	verifyDataSync (message, domain) {

		// The directory takes a blockNumber parameter, in order to
		// allow historical verification of "timestamped" messages by
		// checking that address was linked to alias at signed blockhash
		if (typeof message._params_.blockNumber === 'undefined') {
			throw Error('Must provide \'blockNumber\'');
		}
		
		const address = utils.addressData(message._signed_, message._params_.sig, domain);
		const blockNumber = parseInt(message._params_.blockNumber);
		const namespace = message._params_.namespace;
		const author = { address };

		if (typeof namespace !== 'undefined') {

			if (namespace === null) { // Top level

				try {

					// Get alias that was linked to address at the given block
					author.alias = this.directory.getAlias(address, { at: blockNumber });

				} catch (dirErr) {
					console.log(dirErr);
					throw Error('Failed to find alias in directory');
				}

			} else {

				if (typeof this.nameserver[namespace] === 'undefined') {
					throw Error(`Missing nameserver for '${namespace}'`);
				}

				author.alias = this.nameserver[namespace].getAlias(address, {
					at: blockNumber,
					hex: true
				});
			}

			if (typeof author.alias === 'undefined' || author.alias.length === 0) { // Alias not found
				throw Error('Failed to find alias linked to signing address');
			}
		}

		return author;
	};

	async signData (_signed_, domain = [], options = {}) {

		// Throw an error if _signed_ is empty
		if (Object.keys(_signed_).length === 0) {
			throw Error('_signed_ must contained at least one key');
		}

		// Detect user's address if not sspecified
		let address = options.address;
		if (typeof address === 'undefined') {
			address = await this.getActiveAddress();
		}

		if (!address) {
			throw Error('Failed to resolve signing address');
		}

		const data = JSON.stringify(utils.packData(_signed_, domain));

		return new Promise((resolve, reject) => {
			this.provider.sendAsync({
				method: 'eth_signTypedData_v3',
				params: [ address, data ],
				from: address
			}, (err, { result }) => {
				if (err) {
					reject(err);
				} else {
					resolve({
						_signed_,
						_params_: {
							sig: result.slice(2),
							address
						}
					});
	      }
	    });
		});
	}


	/* Read Contract History */

	// Build alias directory from contract event logs
	async getDirectoryLog (options = {}) {

		if (!this.contract) {
			throw Error('Missing Ethereum provider');
		}

		const { fromBlock, toBlock } = options;
		const _fromBlock = !fromBlock || fromBlock < this.deployed ? this.deployed : fromBlock;
		const _toBlock = toBlock || 'latest';

		// Get all contract events
		const logs = await this.contract.getPastEvents('allEvents', {
			fromBlock: _fromBlock,
			toBlock: _toBlock
		});

		// Return updates to directory mapping
		return logs.map(item => {

			const data = {};

			if (item.event === 'CreateID') {
				data.name = item.returnValues[0];
				data.primary = item.returnValues[1];
				data.recovery = item.returnValues[2];
				data.number = item.returnValues[3];
				if (data.recovery === utils.ZERO_ADDRESS) {
					data.recovery = null;
				}
			} else if (item.event === 'SetPrimary') {
				data.name = item.returnValues[0];
				data.primary = item.returnValues[1];
			} else if (item.event === 'SetRecovery') {
				data.name = item.returnValues[0];
				data.recovery = item.returnValues[1];
			} else if (item.event === 'Recover') {
				data.name = item.returnValues[0];
				data.primary = item.returnValues[1];
				data.recovery = item.returnValues[2];
				if (data.recovery === utils.ZERO_ADDRESS) {
					data.recovery = null;
				}
			}

			return {
				transactionIndex: item.transactionIndex,
				transactionHash: item.transactionHash,
				blockNumber: item.blockNumber,
				blockHash: item.blockhash,
				timestamp: item.timestamp,
				event: item.event,
				data
			};
		});
	}

	// Synchronize namespace instance
	async synchronizeNamespace(signals, toBlock) {

		const names = {};

		for (let signal of signals) {

			// Skip anonymous and top level signers
			if (!signal.namespace) { continue; }

			if (typeof names[signal.namespace] === 'undefined') {
				names[signal.namespace] = [];
			}

			const name = signal.authorAlias;
			if (names[signal.namespace].indexOf(name) === -1) {
				names[signal.namespace].push(name);
			}
		}
		
		for (let namespace of Object.keys(names)) {
			await this.nameserver[namespace].synchronize(
				names[namespace],
				toBlock
			);
		}
	}

	// Synchronize alias directory
	async synchronizeDirectory (toBlock) {
		return await this.directory.synchronize({
			getBlockNumber: this.web3.eth.getBlockNumber,
			getDirectoryLog: this.getDirectoryLog.bind(this),
		}, toBlock);
	}

	// Synchronize Ethereum clock
	async synchronizeClock (options) {
		return await this.clock.synchronize(this.web3.eth, options);
	}


	/* Browser Helpers */

	// Get currently selected address from browser Ethereum provider
	async getActiveAddress () {
		const accounts = await window.ethereum.request({ method: 'eth_accounts' });
		return accounts[0];
	}

 	// Get alias info for active address in browser. Useful for
 	// implementing UI showing a user that their alias name has
 	// been recognized. Returns empty object if currently selected
 	// address does not exist or is not linked to any alias.
 	async identify (options = {}) {

		let address = options.address;

		if (!address) {
			address = await this.getActiveAddress();
		}

		const info = { primary: address };

		// If namespace is specified, fetch the alias name
		// from the local state instance if available, or
		// asynchronously from the remote namespace server
		if (typeof options.namespace === 'string') {

			const ns = this.nameserver[options.namespace];

			if (!ns) { return; }

			const _info = await ns.query('info', { address });
			return { ...info, ...(_info || {}) }

		} else {

			const hex = await this.contract.methods.directory(address).call();
			info.name = utils.hexToUtf8(hex);
			return info;
		}
	}


	/* Contract Constants */

	get deployed () {
		return Contract.deployed[this.network];
	}

	get address () {
		return Contract.address[this.network];
	}
}


/* Low Level API */

// Get web3 contract instance
const getContractInstance = async (web3, options = {}) => { // Return web3 contract instance

	if (!web3) {
		throw Error('Must provide web3 object');
	}

	const { network } = { ...defaults, ...options };
	return await new web3.eth.Contract(abi, Contract.address[network]);
}

module.exports = {
	abi,
	Earth,
	Contract,
	getContractInstance
};

