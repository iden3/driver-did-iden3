package eth

// StateABI signatures of functions from smart contract.
const StateABI = `[{
  "inputs":[
	 {
		"internalType":"uint256",
		"name":"id",
		"type":"uint256"
	 }
  ],
  "name":"getState",
  "outputs":[
	 {
		"internalType":"uint256",
		"name":"",
		"type":"uint256"
	 }
  ],
  "stateMutability":"view",
  "type":"function"
}]`
