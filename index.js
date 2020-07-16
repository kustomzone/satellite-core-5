const Directory = require('@satellite-earth/directory');
const Clock = require('@satellite-earth/clock');
const utils = require('@satellite-earth/utils');
const sigUtil = require('eth-sig-util');
const Web3 = require('web3');


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

const _ensureMetaMask = async () => {
	if (typeof window !== 'undefined') {
		await window.ethereum.enable();
	}
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


/* High Level API */

class Earth {

	constructor () {

		// Create Ethereum clock
		this.clock = new Clock();

		// Create the alias directory
		this.directory = new Directory();
	}

	async connect (options = {}) {

		const _options = { ...defaults, ...options };
		this.provider = _options.provider;
		this.network = _options.network;

		// Detect if operating in a browser environment
		if (typeof window !== 'undefined' && !_options.useOwnProvider) {
			
			if (window.ethereum) { // Provider detected

				this.provider = window.ethereum; // Use in-window provider

				if (!this.network) { // Network code not specified
					this.network = utils.getActiveNetwork(); // Detect from provider
				}

				if (_options.updateOnNetworkChange) { // When user switches network
					this.provider.on('networkChanged', (code) => {
						this.network = code; // Update network code
					});
				}

			} else { // No injected provider
				console.warn('Ethereum wallet not detected');
			}

		} else { // Not in browser, use default provider

			if (!options.httpProviderUrl) {
				throw Error('Missing Ethereum provider url');
			}

			// Create HttpProvider with optional basic auth params
			if (options.httpBasicAuthParams) {
				const { username, password } = options.httpBasicAuthParams;
				const value = `Basic ${Buffer.from(`${username || ''}:${password}`).toString('base64')}`;
				this.provider = new Web3.providers.HttpProvider(
					options.httpProviderUrl,
					{ headers: [ { name: 'Authorization', value } ] }
				);
			} else {
				this.provider = new Web3.providers.HttpProvider(options.httpProviderUrl);
			}
		}

		if (!this.provider) { // Sanity check
			throw Error('Ethereum provider not found');
		}

		// Expose web3 for general blockchain ops
		this.web3 = new Web3(this.provider);

		// Web3 contract instance
		this.contract = await getContractInstance(this.web3);
	}


	/* Identity API */

	// Create a new ID
	async createID ({ alias, primary, recovery }, event) {

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

	// Set a new primary address
	async setPrimary ({ alias, newPrimary, from }, event) {

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

		if (!this.web3.utils.isAddress(newPrimary)) {
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

	// Set a new recovery address
	async setRecovery ({ alias, recovery, from }, event) {

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

		if (!this.web3.utils.isAddress(recovery)) {
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

	// Recover user's ID (current recovery address becomes primary address)
	async recover ({ alias, recovery, newRecovery }, event) {

		if (!alias) {
			throw Error('Must provide alias');
		}

		if (!recovery) {
			throw Error('Must provide recovery');
		}

		if (!this.web3.utils.isAddress(recovery)) {
			throw Error('Value for \'recovery\' is not a valid Ethereum address');
		}

		_tx(this.web3, this.contract.methods.recover(
			utils.utf8ToBytes32(alias),
			(newRecovery || utils.ZERO_ADDRESS)
		).send({ from: recovery }), event);
	}

	// Check if a name is available for registration
	async nameAvailable (alias) {

		if (!alias) {
			throw Error('Must provide alias');
		}

		return await this.contract.methods.nameAvailable(
			utils.utf8ToBytes32(alias)
		).call();
	}

	// Check if an address may be associated with an ID
	async addressAvailable (address) {
		return await this.contract.methods.addressAvailable(address).call();
	}

	// Lookup user info by alias ID
	async lookupName (alias) {

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

	// Lookup user info by number
	async lookupNumber (number, options = {}) {

		if (typeof number === 'undefined') {
			throw Error('Must specify number');
		}

		const info = await this.contract.methods.lookupNumber(String(number)).call();

		return info[0] === utils.ZERO_ADDRESS ? null : {
			primary: info[0],
			recovery: info[1] === utils.ZERO_ADDRESS ? '' : info[1],
			joined: parseInt(info[2]),
			name: options.hex ? utils.zcut(info[3]) : this.web3.utils.hexToUtf8(info[3])
		};
	};

	async lookupAddress (address, options = {}) {

		if (!address) {
			throw Error('Must specify address');
		}

		let hex;
		if (options.includePast) {
			hex = await this.contract.methods.associate(address).call();
		} else {
			hex = await this.contract.methods.directory(address).call();
		}

		return options.hex ? utils.zcut(hex) : this.web3.utils.hexToUtf8(hex);
	}


	/* Message API */

	// Make data EIP-712 friendly
	packData (message, _domain = []) {

		const EIP712Domain = [{ name: 'chainId', type: 'uint256' }];
		const domain = { chainId: 1 };

		for (let item of _domain) {
			domain[item.name] = item.value;
			EIP712Domain.push({
				name: item.name,
				type: item.type
			});
		}

		return {
			domain,
			message,
			primaryType: 'Message',
			types: {
				EIP712Domain,
				Message: Object.keys(message).map(name => {
					return { name, type: 'string' };
				}).sort((a, b) => {

					// Prevent verification from failing due to the
					// object properties being in a different order.
					// Sorting special chars is unstandardized, so
					// using the hex representation is a safer bet.
					const _a = utils.utf8ToHex(a.name);
					const _b = utils.utf8ToHex(b.name);
					return _a.localeCompare(_b);
				})
			}
		};
	}

	// Compute the address that signed data
	addressData (data, domain = []) {

		const { _params_, _signed_ } = data;
		let address;

		if (!data || !data._params_ || !data._signed_) {
			throw Error('Failed to parse data');
		}

		if (!_params_.sig) {
			throw Error('Required \'sig\' parameter not provided');
		}

		try { // Get Ethereum address that signed data

			const signature = _params_.sig.substring(0, 2) === '0x' ? _params_.sig : '0x' + _params_.sig;
			address = sigUtil.recoverTypedSignature({
				data: this.packData(_signed_, domain),
				sig: signature
			});

		} catch (decodeErr) {
			throw Error('Failed to recover signing address');
		}

		return address;
	}

	async verifyData (data, domain = []) {

		const address = this.addressData(data, domain);
		let alias;

		try {	// Verify directory directly from current state of blockchain
			const hex = await this.contract.methods.directory(address).call();
			alias = utils.zcut(hex); // Strip hex prefix and trailing zeros
		} catch (networkErr) {
			throw Error('Failed to verify data from blockchain. This is most likely a network error.');
		}

		if (!alias || alias.length === 0) { // Alias not found
			throw Error('Failed to find alias linked to signing address');
		}

		return { address, alias };
	};

	verifyDataSync (data, blockNumber, domain = []) {

		// The directory takes a blockNumber parameter, in order to
		// allow historical verification of "timestamped" messages by
		// checking that address was linked to alias at signed blockhash
		if (typeof blockNumber === 'undefined') {
			throw Error('Must also provide \'blockNumber\'');
		}

		// Ensure that the call to build the directory
		// from event log data was made sucessfully
		if (!this.directory.initialized) {
			throw Error('Must first call synchronizeDirectory() to get build address <=> alias mapping from event logs');
		}

		if (blockNumber > this.directory.blockNumber) {
			throw Error('Provided \'blockNumber\' greater than block number of latest synced block');
		}

		const address = this.addressData(data, domain);
		let alias;

		try {

			// Get alias that was linked to address at the given block
			alias = this.directory.getAlias(address, { at: blockNumber });

		} catch (dirErr) {
			console.log(dirErr);
			throw Error('Failed to find alias in directory');
		}

		if (!alias || alias.length === 0) { // Alias not found
			throw Error('Failed to find alias linked to signing address');
		}

		return { address, alias };
	};

	async signData (_signed_, domain = []) {

		// Throw an error if _signed_ is empty
		if (Object.keys(_signed_).length === 0) {
			throw Error('_signed_ must contained at least one key');
		}

		// Detect user's address and corresponding alias name from wallet
		const address = await this.getActiveAddress();
		const alias = await this.getActiveAlias({ hex: true });

		if (!alias) {
			throw Error('Signing address must be linked to an alias');
		}

		return new Promise((resolve, reject) => {
			const data = JSON.stringify(this.packData(_signed_, domain));
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
							address,
							alias
						}
					});
	      }
	    });
		});
	}


	/* Read Contract History */

	// Build alias directory from contract event logs
	async getDirectoryLog (options = {}) {

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

	// Synchronize alias directory
	async synchronizeDirectory (toBlock) {
		return await this.directory.synchronize(this, toBlock);
	}

	// Synchronize Ethereum clock
	async synchronizeClock (options) {
		return await this.clock.synchronize(this.web3, options);
	}


	/* Browser Helpers */

	// Get currently selected address from browser Ethereum provider
	async getActiveAddress () {
		await _ensureMetaMask();

		if (!this.web3) {
			throw Error('Must call connect() before using this method');
		} 

		const accounts = await this.web3.eth.getAccounts();
		return accounts[0];
	}

 	// Get alias linked to active address in browser. Useful for
 	// implementing UI showing a user that their alias name has
 	// been recognized. Returns empty string if currently selected
 	// address does not exists or is not linked to any alias.
	async getActiveAlias (options = {}) {
		await _ensureMetaMask();
		const address = await this.getActiveAddress();
		const hex = await this.contract.methods.directory(address).call();
		return options.hex ? utils.zcut(hex) : this.web3.utils.hexToUtf8(hex);
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

// Get a web3 contract instance
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
