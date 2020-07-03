const path = require('path');
const solc = require('solc');
const fs = require('fs-extra');

try {

	// Get path to files for interface and bytecode
	const interfacePath = path.resolve(__dirname, '../', 'abi.json');
	const bytecodePath = path.resolve(__dirname, '../', 'bytecode.json');

	// Remove any previous builds
	fs.removeSync(interfacePath);
	fs.removeSync(bytecodePath);

	// Compile the solidity code
	const contractPath = path.resolve(__dirname, '../', 'earth.sol');
	const source = fs.readFileSync(contractPath, 'utf8');
	const output = JSON.parse(solc.compile(JSON.stringify({
		language: 'Solidity',
		sources: {
			'earth.sol': {
				content: source
			}
		},
		settings: {
			outputSelection: {
				'*': {
					'*': [ '*' ]
				}
			}
		}
	})));

	const out = output.contracts['earth.sol']['Earth'];
	const { abi, evm } = output.contracts['earth.sol']['Earth'];

	fs.outputJsonSync(interfacePath, abi);
	fs.outputJsonSync(bytecodePath, evm.bytecode.object);

} catch (err) {
	console.log(err);
}
