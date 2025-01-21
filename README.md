# Quick Start

This single Python file has everything you need to build the most advanced
trading bot and to use the most advanced social features of the DeSo
blockchain. See docs.deso.org for more documentation.

The sdk works by first CONSTRUCTING a transaction, then SIGNING, then 
SUBMITTING the transaction to the DeSo blockchain (via node.deso.org
or test.deso.org by default, though you can select your own nodes if you prefer).

To get started, simply run the file and follow its instructions:
```
python3 -m venv myenv

source myenv/bin/activate

pip install -r requirements.txt

python3 deso_sdk.py
```

The first thing you should see is an ERROR that tells you to set SEED\_PHRASE\_OR\_HEX.
Simply do as it says and go from there.

Once you've done everything the main tells you to do, you should see SUCCESS
for all of the txn examples. Once you've gotten this far, it's time to read the
main top to bottom and see how it's doing what it's doing. Here are some tips:
- Every account on the DeSo blockchain can have a fully on-chain SOCIAL PROFILE, and every
  account with an on-chain profile can launch a DeSo Token, which is like an ERC-20 token
attached to the account. DeSo Tokens can be minted by the account owner and
traded on the DeSo DEX using clients like openfund.com or focus.xyz.
- If you run into an error constructing a transaction, always look toward the
  end for the RuleError. The RuleError usually explains in plain English what
went wrong and how to fix it. Eg RuleErrorInsufficientDeSoBalance.
- Uncomment the transaction construction responses to see what useful information they provide
- 1e18 means "10 to the power of 18". 1 DESO = 1e9 "nanos" while 1 "DeSo Token"
  = 1e18 "base units". All tokens other than DESO are "DeSo Tokens" and use
"base units" rather than nanos. Still, some functions reference "nanos" when
they should reference "base units." In addition, some transaction construction endpoints
require values to be hex-encoded rather than decimal-encoded. If you use the provided functions
`coins_to_base_units` and `base_units_to_coins` you'll never go wrong.
- Some functions refer to "DeSo Tokens" as "DAO Coins." This is an old
  terminology that unfortunately still exists in the node's API. Just remember
that anywhere you see "DAO Coin," it is simply referring to a "DeSo Token."
- When placing orders, it's important to note that the DeSo blockchain doesn't
  natively have a concept of a "base currency" and a "quote currency" for a particular market.
Practically, what this means is that you can have an ASK where you "sell DESO
for USDC" and a BID where you "buy USDC for DESO" that do the exact same thing.
This is an important consideration when looking at the output of
get\_limit\_orders, as you may need to "flip" some responses.
- Some functions of the DeSo blockchain are not in this sdk yet, but you can
  trivially add them! Simply use your web inspector on test.deso.org,
dev.openfund.com, or beta.focus.xyz to get the transaction construction
parameters, and then use sign\_and\_submit\_txn to submit them to the
blockchain.
- The library provides a clear example to construct and submit ATOMIC
  transactions to the DeSo blockchain. This can be an invaluable resource when
performing complex operations, such as quickly submitting and then cancelling
orders if they don't execute, among many other things.

# Exercises

Once you've read through the file, you can challenge yourself with the following fun (and potentially very lucrative) exercises.

## Write Blockchain Bots with AI

You may have noticed that the sdk is a single Python file. There is tremendous
value in this because it means you can simply "drop" the entire sdk into your
favorite AI and ask it to write new functions for you, or to put together the
existing functions in novel ways. Keep this in mind as you do the other
exercises in this section. It may help to load the sdk into an AI before you
begin so you're ready to ask it questions!

## Become a Professional Market-Maker in One Day
1. Get the market mid-price of \$openfund on the openfund/deso market by using the get\_limit\_orders function. Beware of ASKs that look like BIDs, and vice versa!
2. Place a market order to buy 0.000001 DESO worth of \$openfund. You should be able to do this with just your starter DESO.
3. Check your \$openfund balance after doing the market order to confirm that you have the amount of \$openfund that you expect to have.
4. Place a LIMIT order to BUY \$openfund just below the market mid price, and a LIMIT order to SELL \$openfund just above the market mid price. You should be able to do this now that you have both \$openfund and \$DESO from the previous step! The orders should "rest" on the book, without executing immediately. Save the order\_id from the transaction so you can manage the state of your order! The order\_id is simply the signed txn hash of the transaction you used to place the order.
5. Use get\_limit\_orders to tell if your order has been filled or not. An order will be filled when it no longer appears on the book.
6. Practice cancelling and replacing one of your orders using the sdk, and passing the order\_id from when you placed the order.
6. Write a simple routine to "flip" your buy into a sell once it's been filled (at a slightly higher price so you earn a "spread"). Do the same for your other limit order.
7. ADVANCED: Acquire \$100 worth of \$openfund and \$100 worth of \$DESO. Place 10 bids and 10 asks for \$10 each around the market mid using an ATOMIC transaction.
8. ADVANCED: Write a routine to "flip" your asks to bids when they're filled (with a spread so you make some money on the volatility!). Do the same for your bids.
9. CONGRATS! If you made it this far, you are officially a market-maker on the DeSo DEX! The AMMs that power Focus and Openfund are essentially a highly-sophisticated and scaled-up version of what you just did.

## Social Bots
1. Use the sdk to create a post from your account.
2. Use the sdk to follow @nadertheory on testnet and @nader on mainnet.
3. Use the sdk to repost something from your account. A repost uses the same submit\_post but with RepostedPostHashHex set.
4. Use the sdk to comment on someone's post. A comment is just a post with a ParentPostHash set.
5. ADVANCED: Use the sdk to write a bot that queries an AI API to automatically reply to all of your posts with something meaningful and useful.
6. ADVANCED: Use the sdk to write a bot that auto-replies to anyone who comments on your post with something meaningful from your personal account.
7. ADVANCED: Use the sdk to send a paid message to someone.

## Learn to Inspect Like the Best
1. Navigate to the "DAO Coin" tab on node.deso.org for Openfund [here](https://node.deso.org/u/openfund?feedTab=Following&tab=dao). Remember that "DAO Coin" is just an old term for "DeSo Token"!
2. Open the web inspector on your browser and navigate to the Network tab.
3. Filter the requests to get-hodlers-for-public-key. Click "Copy as CURL" to get the params used by the request. In addition, note "Copy Response" as we'll be using that too.
4. With the sdk loaded into your favorite AI tool, paste the result of "Copy as CURL" and the result of "Copy Response" into the chat, and ask it to add a function to get all the holders for a given token.
5. CONGRATS! You've just added a NEW FUNCTION to the sdk! You can use this process to automate anything you do on openfund.com, focus.xyz, and any DeSo app!

# Useful Links
If you get stuck or need help, you can always message the [DeSo PoS Discussion Telegram Channel](https://t.me/deso_pos_discussion) for help. 

Other useful links:
- Block explorer:
   - Testnet: [explorer-testnet.deso.com](https://explorer-testnet.deso.com)
   - Mainnet: [explorer.deso.com](https://explorer.deso.com)
- Reference nodes:
   - Testnet: [test.deso.org](https://test.deso.org)
   - Mainnet: [node.deso.org](https://node.deso.org)
- Openfund:
   - Testnet: [dev.openfund.com](https://dev.openfund.com)
   - Mainnet: [beta.focus.xyz](https://beta.focus.xyz)
- Focus:
   - Testnet: [beta.focus.xyz](https://beta.focus.xyz)
   - Mainnet: [focus.xyz](https://focus.xyz)
- Docs:
   - [docs.deso.org](https://docs.deso.org)
   - [deso.com](https://deso.com)
   - [Running a DeSo Validator](https://docs.deso.org/deso-validators/run-a-validator)
   - [Revolution Proof of Stake](https://revolution.deso.com)
   - [DeSo Architecture Overview (old)](https://docs.deso.org/deso-repos/architecture-overview)
   - [Algorithmic Trading Docs](TODO)
