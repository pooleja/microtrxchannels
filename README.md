# README

MicroTrxChannels is a bitcoin micro-payment channel example.

Do not use this code for anything production related, since there is almost no error condition checking.

https://www.youtube.com/watch?v=HmYP-7pcdhM&spfreload=10

## Quick setup

1. Clone repository and change to `microtrxchannels` directory
2. Run `npm install`
3. Create config by copying `*_template` files to their respective `*.js` files and adjust config
4. Run `bin/www` to start application (use `DEBUG=microtrxchannels bin/www` or `DEBUG=* bin/www` for different levels of debug output)
5. Point browser to http://localhost:3000/client

## Requirements

1. [Bitcoin Core](https://bitcoin.org/en/download) running on testnet, example `bitcoin.conf`:

    ```
    testnet=1
    daemon=1
    server=1
    rpcuser=your_user
    rpcpassword=your_pass
    ```
2. [node.js](http://nodejs.org/)
3. [MongoDB](www.mongodb.org)
