# driver-did-iden3
Driver for the iden3 DID method

## How to run locally:
1. Create file `resolvers.settings.yaml` with resolver settings:
    ```yaml
    iden3:
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
