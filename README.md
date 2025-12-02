# driver-did-iden3
Driver for the iden3 DID method

## How to run locally:
1. Create file `resolvers.settings.yaml` with resolver settings:
    ```yaml
    polygon:
        amoy:
            contractAddress: "0xf6..."
            networkURL: "https://polygon-amoy..."
    ```
2. Build docker container:
    ```bash
    docker build -t driver-did-iden3:local
    ```
3. Run docker conainer:
    ```bash
    docker run -p 8080:8080 driver-did-iden3:local
    ```
    
    `ADDITIONAL_RESOLUTION_SOURCE` provides an optional extra DID resolution source used to merge data into the final DID document.

    `WALLET_KEY` is only needed for the resolver if it's a trusted resolver that includes signature of EIP712 message when requested in the resolution with `signature=EthereumEip712Signature2021`.
    In this case you have to run:
    ```bash
    docker run -p 8080:8080 \
        -e WALLET_KEY=<your_wallet_key> \
        -e ADDITIONAL_RESOLUTION_SOURCE=<additional_resolver_url> \
        driver-did-iden3:local
    ```

   