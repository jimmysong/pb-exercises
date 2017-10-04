### Problems

Helpful reminder:

https://api.blockcypher.com/v1/btc/main/txs/<tx_hash>
https://api.blockcypher.com/v1/btc/test3/txs/<tx_hash>

1. What is the value and scriptPubKey of the 0th output of this transaction?

d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81


### Make this test pass

in tx.py:

    def test_input_value(self):
    
    def test_input_pubkey(self):
    
Bonus:

Cache the requests so that you don't hit blockcypher.com multiple times for the same transaction output