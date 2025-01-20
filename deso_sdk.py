import hashlib
import json

import requests
from typing import Optional, Dict, Any, List, Union
from pprint import pprint
import sys

from typing import Tuple, Optional
import binascii
from bip32 import BIP32, base58
from mnemonic import Mnemonic
from coincurve import PrivateKey

import hashlib
from typing import Optional
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der

import time
from requests.exceptions import RequestException

class DeSoDexClient:
    """
    A Python client for interacting with the DeSo DEX endpoints on a DeSo node.
    """

    def __init__(self, is_testnet: bool=False, seed_phrase_or_hex=None, passphrase=None, index=0, node_url=None):
        self.is_testnet = is_testnet

        desoKeyPair, err = create_key_pair_from_seed_or_seed_hex(
            seed_phrase_or_hex, passphrase, index, is_testnet,
        )
        if desoKeyPair is None:
            raise ValueError(err)
        self.deso_keypair = desoKeyPair

        if node_url is None:
            if is_testnet:
                node_url = "https://test.deso.org"
            else:
                node_url = "https://node.deso.org"
        self.node_url = node_url.rstrip("/")

    def sign_single_txn(self, unsigned_txn_hex: str) -> str:
        try:
            # Decode hex transaction to bytes
            txn_bytes = bytes.fromhex(unsigned_txn_hex)

            # Double SHA256 hash of the transaction bytes
            first_hash = hashlib.sha256(txn_bytes).digest()
            txn_hash = hashlib.sha256(first_hash).digest()

            # Create signing key from private key bytes
            signing_key = SigningKey.from_string(self.deso_keypair.private_key, curve=SECP256k1)

            # Sign the hash
            signature = signing_key.sign_digest(txn_hash, sigencode=sigencode_der)

            # Convert signature to hex
            signature_hex = signature.hex()

            return signature_hex

        except Exception as e:
            return None

    def submit_txn(self, unsigned_txn_hex: str, signature_hex: str) -> dict:
        """
        Submit a transaction with signature to the specified node URL.

        Args:
            node_url: Base URL of the node
            unsigned_txn_hex: Hex string of unsigned transaction
            signature_hex: Hex string of transaction signature

        Returns:
            dict: Parsed response from the server

        Raises:
            requests.exceptions.RequestException: If request fails
            json.JSONDecodeError: If response parsing fails
            ValueError: If server returns non-200 status code
        """
        submit_url = f"{self.node_url}/api/v0/submit-transaction"

        payload = {
            "UnsignedTransactionHex": unsigned_txn_hex,
            "TransactionSignatureHex": signature_hex
        }

        headers = {
            "Origin": self.node_url,
            "Content-Type": "application/json"
        }

        response = requests.post(
            submit_url,
            data=json.dumps(payload),
            headers=headers
        )

        if response.status_code != 200:
            raise ValueError(
                f"Error status returned from {submit_url}: "
                f"{response.status_code}, {response.text}"
            )

        return response.json()

    from typing import Dict, List, Any

    def submit_atomic_txn(
            self,
            incomplete_atomic_txn_hex: str,
            unsigned_inner_txn_hexes: List[str],
            txn_signatures_hex: List[str]
    ) -> Dict[str, Any]:
        """
        Submit an atomic transaction using the designated endpoint.

        Args:
            node_url: Base URL of the node
            transaction_hex: Hex string of the incomplete atomic transaction
            unsigned_inner_txn_hexes: List of unsigned inner transaction hex strings
            txn_signatures_hex: List of transaction signatures in hex

        Returns:
            dict: Parsed JSON response

        Raises:
            requests.exceptions.RequestException: If request fails
            json.JSONDecodeError: If response parsing fails
            ValueError: If server returns non-200 status code
        """
        endpoint = "/api/v0/submit-atomic-transaction"
        url = f"{self.node_url}{endpoint}"

        payload = {
            "IncompleteAtomicTransactionHex": incomplete_atomic_txn_hex,
            "UnsignedInnerTransactionsHex": unsigned_inner_txn_hexes,
            "TransactionSignaturesHex": txn_signatures_hex
        }

        response = requests.post(url, json=payload)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            try:
                error_json = response.json()
            except ValueError:
                error_json = response.text
            raise requests.exceptions.HTTPError(
                f"Error status returned from {url}: {response.status_code}, {error_json}"
            )

        return response.json()

    def sign_and_submit_txn(self, resp):
        unsigned_txn_hex = resp.get('TransactionHex')
        if unsigned_txn_hex is None:
            raise ValueError("TransactionHex not found in response")
        if 'InnerTransactionHexes' in resp:
            unsigned_inner_txn_hexes = resp.get('InnerTransactionHexes')
            signature_hexes = []
            for unsigned_inner_txn_hex in unsigned_inner_txn_hexes:
                signature_hex = self.sign_single_txn(unsigned_inner_txn_hex)
                signature_hexes.append(signature_hex)
            return self.submit_atomic_txn(
                unsigned_txn_hex, unsigned_inner_txn_hexes, signature_hexes
            )
        signature_hex = self.sign_single_txn(unsigned_txn_hex)
        return self.submit_txn(unsigned_txn_hex, signature_hex)

    def create_unsigned_atomic_txn(self, unsigned_transaction_hexes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Creates an unsigned atomic transaction from a list of transactions.

        Args:
            unsigned_transaction_hexes (List[Dict[str, Any]]): A list of transactions represented as dictionaries.

        Returns:
            Dict[str, Any]: The parsed response containing the atomic transaction details.

        Raises:
            Exception: If the request fails or the response cannot be parsed.
        """
        route_path = "/api/v0/create-atomic-txns-wrapper"
        url = f"{self.node_url}{route_path}"

        payload = {
            "UnsignedTransactionHexes": unsigned_transaction_hexes
        }

        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            try:
                error_json = response.json()
            except ValueError:
                error_json = response.text
            raise requests.exceptions.HTTPError(
                f"CreateUnsignedAtomicTxn: Error status returned from {url}: {response.status_code}, {error_json}"
            )

        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise Exception(f"CreateUnsignedAtomicTxn: Error parsing JSON response: {str(e)}")

        if "InnerTransactionHexes" not in response_data:
            raise Exception("CreateUnsignedAtomicTxn: Missing 'InnerTransactionHexes' in response")

        return response_data

    def get_transaction(self, txn_hash_hex: str, committed_txns_only: bool) -> Dict[str, Any]:
        """
        Fetch a transaction by its hash with an optional filter for committed transactions.

        Args:
            txn_hash_hex (str): The hex string of the transaction hash.
            committed_txns_only (bool): If True, fetch only committed transactions;
                                        otherwise, fetch transactions in mempool.

        Returns:
            Dict[str, Any]: The JSON response containing transaction details.

        Raises:
            requests.exceptions.RequestException: If the request fails.
            json.JSONDecodeError: If the response parsing fails.
            ValueError: If the server returns a non-200 status code.
        """
        url = f"{self.node_url}/api/v0/get-txn"

        # Determine the transaction status based on the argument
        txn_status = "Committed" if committed_txns_only else "InMempool"

        payload = {
            "TxnHashHex": txn_hash_hex,
            "TxnStatus": txn_status,
        }

        headers = {
            "Origin": self.node_url,
            "Content-Type": "application/json",
        }

        response = requests.post(url, json=payload, headers=headers)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = response.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")

        return response.json()

    def wait_for_commitment_with_timeout(self, txn_hash_hex: str, timeout_seconds: float) -> None:
        """
        Waits for a transaction to commit within a specified timeout period. DeSo txns commit
        within two blocks, with 1s block times, so within 3s. Note you don't necessarily need
        to wait for commitment. You can "fire and forget" your txns if best-effort is OK, or
        use get_transaction to check that it entered the mempool, which is sufficient for most
        use-cases (and mempool txns almost always commit within a few seconds).

        Args:
            txn_hash_hex (str): The transaction hash in hex format.
            timeout_seconds (float): The maximum time to wait for confirmation, in seconds.

        Raises:
            TimeoutError: If the transaction does not confirm within the timeout period.
            Exception: If there is an error fetching the transaction from the node.
        """
        start_time = time.time()

        while True:
            try:
                txn_response = self.get_transaction(txn_hash_hex, committed_txns_only=True)
                if txn_response.get("TxnFound", False):
                    return  # Transaction is confirmed
            except RequestException as e:
                raise Exception(f"Error getting txn from node: {str(e)}")

            if time.time() - start_time > timeout_seconds:
                raise TimeoutError(f"Timeout waiting for txn to confirm: {txn_hash_hex}")

            time.sleep(0.1)  # Sleep for 100 milliseconds before retrying

    def coins_to_base_units(self, coin_amount: float, is_deso: bool, hex_encode: bool = False) -> str:
        if is_deso:
            base_units = int(coin_amount * 1e9)
        else:
            base_units = int(coin_amount * 1e18)
        if hex_encode:
            return hex(base_units)
        return str(base_units)

    def base_units_to_coins(self, coin_base_units: str | int, is_deso: bool) -> float:
        # Decode hex if needed
        if str(coin_base_units).startswith("0x"):
            coin_base_units = int(coin_base_units, 16)
        if is_deso:
            return float(coin_base_units) / 1e9
        return float(coin_base_units) / 1e18

    def mint_or_burn_tokens(
        self,
        updater_pubkey_base58check: str,
        profile_pubkey_base58check: str,
        operation_type: str,            # 'mint' or 'burn'
        coins_to_mint_or_burn_nanos: str,
        min_fee_rate_nanos_per_kb: int = 1000,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/dao-coin"

        payload = {
            "UpdaterPublicKeyBase58Check": updater_pubkey_base58check,
            "ProfilePublicKeyBase58CheckOrUsername": profile_pubkey_base58check,
            "OperationType": operation_type,
        }

        if operation_type.lower() == "mint":
            payload["CoinsToMintNanos"] = coins_to_mint_or_burn_nanos
        elif operation_type.lower() == "burn":
            payload["CoinsToBurnNanos"] = coins_to_mint_or_burn_nanos
        else:
            raise ValueError('operation_type must be "mint" or "burn".')

        payload["MinFeeRateNanosPerKB"] = min_fee_rate_nanos_per_kb

        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")

        return resp.json()

    def send_deso(
            self,
            sender_pubkey_base58check: str,
            recipient_pubkey_or_username: str,
            amount_nanos: int,
            min_fee_rate_nanos_per_kb: int = 1000,
            extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Sends DESO from one account to another.

        Args:
            sender_pubkey_base58check: Public key of the sender in Base58Check format.
            recipient_pubkey_or_username: Public key or username of the recipient.
            amount_nanos: Amount to send in nanos.
            min_fee_rate_nanos_per_kb: Minimum fee rate in nanos per KB.
            extra_headers: Optional headers to include in the request.

        Returns:
            dict: Parsed response from the API.
        """
        url = f"{self.node_url}/api/v0/send-deso"
        payload = {
            "SenderPublicKeyBase58Check": sender_pubkey_base58check,
            "RecipientPublicKeyOrUsername": recipient_pubkey_or_username,
            "AmountNanos": amount_nanos,
            "MinFeeRateNanosPerKB": min_fee_rate_nanos_per_kb
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        response = requests.post(url, json=payload, headers=headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = response.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")

        return response.json()

    def transfer_tokens(
        self,
        sender_pubkey_base58check: str,
        profile_pubkey_base58check: str,
        receiver_pubkey_base58check: str,
        token_to_transfer_base_units: str,
        min_fee_rate_nanos_per_kb: int = 1000,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/transfer-dao-coin"
        payload = {
            "SenderPublicKeyBase58Check": sender_pubkey_base58check,
            "ProfilePublicKeyBase58CheckOrUsername": profile_pubkey_base58check,
            "ReceiverPublicKeyBase58CheckOrUsername": receiver_pubkey_base58check,
            "DAOCoinToTransferNanos": token_to_transfer_base_units,
            "MinFeeRateNanosPerKB": min_fee_rate_nanos_per_kb,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")

        return resp.json()

    def update_transfer_restriction_status(
        self,
        updater_pubkey_base58check: str,
        profile_pubkey_base58check: str,
        transfer_restriction_status: str,  # e.g. "profile_owner_only"
        min_fee_rate_nanos_per_kb: int = 1000,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/dao-coin"
        payload = {
            "TransferRestrictionStatus": transfer_restriction_status,
            "UpdaterPublicKeyBase58Check": updater_pubkey_base58check,
            "ProfilePublicKeyBase58CheckOrUsername": profile_pubkey_base58check,
            "OperationType": "update_transfer_restriction_status",
            "MinFeeRateNanosPerKB": min_fee_rate_nanos_per_kb,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")
        return resp.json()

    def create_limit_order_with_fee(
        self,
        transactor_public_key: str,
        quote_currency_public_key: str,
        base_currency_public_key: str,
        operation_type: str,  # "BID" or "ASK"
        price: str,
        price_currency_type: str,
        quantity: str,
        fill_type: str,
        quantity_currency_type: str,
        min_fee_rate_nanos_per_kb: int = 0,
        extra_fees: Optional[List[Dict[str, Any]]] = None,
        optional_preceding_txs: Optional[List[Dict[str, Any]]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/create-dao-coin-limit-order-with-fee"
        payload = {
            "OperationType": operation_type,
            "TransactorPublicKeyBase58Check": transactor_public_key,
            "QuoteCurrencyPublicKeyBase58Check": quote_currency_public_key,
            "BaseCurrencyPublicKeyBase58Check": base_currency_public_key,
            "Price": price,
            "PriceCurrencyType": price_currency_type,
            "Quantity": quantity,
            "FillType": fill_type,
            "MinFeeRateNanosPerKB": min_fee_rate_nanos_per_kb,
            "TransactionFees": extra_fees,
            "OptionalPrecedingTransactions": optional_preceding_txs,
            "QuantityCurrencyType": quantity_currency_type,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")
        return resp.json()

    def cancel_limit_order(
        self,
        transactor_public_key: str,
        cancel_order_id: str,
        min_fee_rate_nanos_per_kb: int = 1000,
        extra_fees: Optional[List[Dict[str, Any]]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/cancel-dao-coin-limit-order"
        payload = {
            "TransactorPublicKeyBase58Check": transactor_public_key,
            "CancelOrderID": cancel_order_id,
            "MinFeeRateNanosPerKB": min_fee_rate_nanos_per_kb,
            "TransactionFees": extra_fees,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")
        return resp.json()

    def get_token_balances(
            self,
            user_public_key: str,
            creator_public_keys: List[str],
            txn_status: str = "Committed",
            extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetches token balances for a given user public key and a list of creator public keys.

        Args:
            user_public_key (str): The base58 public key of the user.
            creator_public_keys (List[str]): List of creator public keys to query balances for.
            txn_status (str): The transaction status filter. Default is 'Committed'.
            extra_headers (Optional[Dict[str, str]]): Additional headers for the HTTP request.

        Returns:
            Dict[str, Any]: The token balances in a structured dictionary format.

        Raises:
            requests.exceptions.RequestException: If the request fails.
            json.JSONDecodeError: If the response is not valid JSON.
            ValueError: If the server returns a non-200 status code.
        """
        url = f"{self.node_url}/api/v0/get-token-balances-for-public-key"

        payload = {
            "UserPublicKey": user_public_key,
            "CreatorPublicKeys": creator_public_keys,
            "TxnStatus": txn_status,
        }

        headers = {
            "Content-Type": "application/json",
            "Origin": self.node_url,
        }
        if extra_headers:
            headers.update(extra_headers)

        response = requests.post(url, json=payload, headers=headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = response.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")

        return response.json()

    def get_single_profile(
            self,
            public_key_base58check: Optional[str] = None,
            username: Optional[str] = None,
            extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any] | None:
        """
        Fetches a single profile from the DeSo node.

        Args:
            public_key_base58check (str, optional): The public key of the user to fetch.
            username (str, optional): The username of the user to fetch.
            no_error_on_missing (bool): If true, suppresses errors when the profile is missing.
            extra_headers (dict, optional): Additional headers to include in the request.

        Returns:
            dict: The profile data from the node.

        Raises:
            requests.exceptions.RequestException: If the request fails.
            json.JSONDecodeError: If response parsing fails.
            ValueError: If the server returns a non-200 status code.
        """
        url = f"{self.node_url}/api/v0/get-single-profile"

        payload = {
            "PublicKeyBase58Check": public_key_base58check or "",
            "Username": username or "",
            "NoErrorOnMissing": False,
        }

        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            # Handle 404 gracefully.
            # TODO: This is a hack but fine for now...
            if "404" in str(err):
                return None
            raise ValueError(f"get_single_profile: Error making request to node: {err}")

        try:
            response_data = response.json()
        except json.JSONDecodeError as err:
            raise ValueError(f"get_single_profile: Error unmarshalling response: {err}")

        return response_data.get("Profile")

    def get_limit_orders(
        self,
        coin1_creator_pubkey: str,
        coin2_creator_pubkey: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/get-dao-coin-limit-orders"
        payload = {
            "DAOCoin1CreatorPublicKeyBase58Check": coin1_creator_pubkey,
            "DAOCoin2CreatorPublicKeyBase58Check": coin2_creator_pubkey,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")
        return resp.json()

    def get_transactor_limit_orders(
        self,
        transactor_pubkey_base58check: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.node_url}/api/v0/get-transactor-dao-coin-limit-orders"
        payload = {
            "TransactorPublicKeyBase58Check": transactor_pubkey_base58check,
        }
        headers = {
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        resp = requests.post(url, json=payload, headers=headers)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_json = resp.json()  # Get the error response JSON
            raise requests.exceptions.HTTPError(f"HTTP Error: {e}, Response: {error_json}")
        return resp.json()

class DeSoKeyPair:
    def __init__(self, public_key: bytes, private_key: bytes):
        self.public_key = public_key
        self.private_key = private_key

def create_key_pair_from_seed_or_seed_hex(
    seed: str,
    passphrase: str,
    index: int,
    is_testnet: bool
) -> Tuple[Optional[DeSoKeyPair], Optional[str]]:
    """
    Creates a key pair from either a seed phrase or seed hex.

    Args:
        seed (str): Either a BIP39 mnemonic seed phrase or a hex string
        passphrase (str): Optional passphrase for BIP39 seed
        index (int): Account index for derivation path
        is_testnet (bool): Whether to use testnet or mainnet parameters

    Returns:
        Tuple[DeSoKeyPair, Optional[str]]: Returns the key pair and any error message
    """
    if not seed:
        return None, "Seed must be provided"

    # First try to decode as hex to determine if it's a seed hex
    try:
        seed_bytes = binascii.unhexlify(seed.lower())
        # If we get here, it's a valid hex string
        if passphrase or index != 0:
            return None, "Seed hex provided, but passphrase or index params were also provided"

        # Convert the seed hex directly to keys
        privkey = PrivateKey(seed_bytes)
        pubkey = privkey.public_key
        return DeSoKeyPair(pubkey.format(), privkey.secret), None

    except binascii.Error:
        # Not a valid hex string, treat as mnemonic
        try:
            # Validate and convert mnemonic to seed
            mnemo = Mnemonic("english")
            if not mnemo.check(seed):
                return None, "Invalid mnemonic seed phrase"

            seed_bytes = mnemo.to_seed(seed, passphrase)

            # Initialize BIP32 with appropriate network
            network = "test" if is_testnet else "main"
            bip32 = BIP32.from_seed(seed_bytes, network=network)

            # Derive the key path: m/44'/0'/index'/0/0
            # Note: in BIP32, hardened keys are represented with index + 0x80000000
            path = f"m/44'/0'/{index}'/0/0"
            derived_key = bip32.get_privkey_from_path(path)

            # Convert to coincurve keys for consistent interface
            privkey = PrivateKey(derived_key)
            pubkey = privkey.public_key

            return DeSoKeyPair(pubkey.format(), privkey.secret), None

        except Exception as e:
            return None, f"Error converting seed to key pair: {str(e)}"

def base58_check_encode(input_bytes: bytes, is_testnet: bool) -> str:
     """
     Encode input bytes using Base58Check encoding with a specific prefix.

     Args:
         input_bytes: The bytes to encode
         prefix: 3-byte prefix to prepend

     Returns:
         Base58Check encoded string
     """
     prefix = b"\x11\xc2\x00" if is_testnet else  b"\xcd\x14\x00"

     # Combine prefix and input bytes
     combined = prefix + input_bytes

     # Calculate double SHA256 checksum
     first_hash = hashlib.sha256(combined).digest()
     second_hash = hashlib.sha256(first_hash).digest()
     checksum = second_hash[:4]

     final_bytes = combined + checksum

     # Encode using Base58
     return base58.b58encode(final_bytes).decode()

def main():
    """
    A simple main function that exercises each endpoint and prints the response.

    NOTE: The parameters here are example placeholders. 
    If you don't have valid keys or a valid environment, these calls may fail.
    """
    # This is very important: If you want to run on mainnet, you must switch this to false.
    # This will switch several other params to the right values.
    IS_TESTNET = True
    # You can set any DeSo node you want. The nodes here are the canonical testnet and mainnet
    # ones that a lot of people use for testing. If you don't pass a node_url to the DesoDexClient
    # it will default to one of these depending on the value of is_testnet. We specify them here
    # explicitly just to make you aware that you can set it manually if you want.
    NODE_URL = "https://test.deso.org"
    if not IS_TESTNET:
       NODE_URL = "https://node.deso.org"

    # This pubkey is used for token-related things, such as buying or selling a token where
    # DESO is the quote currency. You can see how it's used in the txn construction endpoints below.
    DESO_TOKEN_PUBKEY = ('tBCKQud934akEwsr8AfG9BzHDWhi6CaDmjBsxGsSgfGsoxXHfVEfxP' if IS_TESTNET else
                         'BC1YLbnP7rndL92x7DbLp6bkUpCgKmgoHgz7xEbwhgHTps3ZrXA6LtQ')

    # You can get your seed phrase OR your seed hex from the DeSo wallet. Just find
    # your account and hit "Backup" to copy either you seed phrase or seed hex.
    #
    # Replace the below with your seed phrase. If you have "passphrase" or a different
    # index you can specify it below as well.
    SEED_PHRASE_OR_HEX = ""
    PASSPHRASE = ""
    INDEX = 0
    # Testnet public key: tBCKV1NauX3S59wFxcZrWujDNeu2FufVhjK4PMVGAtBhJnU9wioaBU
    # Mainnet public key: BC1YLft8ZjF61yF1X43FQUKVQyLsdwPtZczF8fgZXAWNeMsWiicue9X

    explorer_link = "explorer-testnet.deso.com" if IS_TESTNET else "explorer.deso.com"
    wallet_link = "wallet-testnet.deso.com" if IS_TESTNET else "wallet.deso.com"
    openfund_link = "dev.openfund.com" if IS_TESTNET else "openfund.com"
    focus_link = "beta.focus.xyz" if IS_TESTNET else "focus.xyz"
    error_msg_SET_SEED = (f"ERROR: You must set SEED_PHRASE_OR_HEX to a seed that has DESO in it, or else nothing will "
                          f"work. Use {NODE_URL} to create an account and get starter DESO since IS_TESTNET={IS_TESTNET}. Change IS_TESTNET to switch "
                          f"between mainnet and testnet. See the top of main for other arguments. Read through main to see "
                          f"a bunch of useful transaction types. Other useful links: "
                          f"docs.deso.org {explorer_link}, {wallet_link}, {openfund_link}, {focus_link}. "
                          f"Message https://t.me/deso_pos_discussion for more help.")
    if SEED_PHRASE_OR_HEX == "":
        print(error_msg_SET_SEED)
        sys.exit(1)

    client = DeSoDexClient(
        is_testnet=IS_TESTNET,
        seed_phrase_or_hex=SEED_PHRASE_OR_HEX,
        passphrase=PASSPHRASE,
        index=INDEX,
        node_url=NODE_URL)

    string_pubkey = base58_check_encode(client.deso_keypair.public_key, IS_TESTNET)
    print(f'Public key for seed: {string_pubkey}')

    openfund_pubkey = ("tBCKWUK6mKhWpT4quLZjM2iPqPMwEWnHuj4Q99vSS4jFRLGeFJ3G3p" if IS_TESTNET else
                       "BC1YLj3zNA7hRAqBVkvsTeqw7oi4H6ogKiAFL1VXhZy6pYeZcZ6TDRY")
    nader_pubkey = ("tBCKWkMW7SNyA4kuAHLtvFgdPRDgqS3gPfH5UWoeGZbxftkzUqpiKF" if IS_TESTNET else
                    "BC1YLhyuDGeWVgHmh3UQEoKstda525T1LnonYWURBdpgWbFBfRuntP5")

    print(f"Get $openfund and $DESO balances for pubkey: {string_pubkey}")
    try:
        balances = client.get_token_balances(
            user_public_key=string_pubkey,
            creator_public_keys=[openfund_pubkey, "DESO", string_pubkey],
        )
        # pprint(balances)
    except Exception as e:
        print(f"ERROR: Get token balances call failed: {e}")

    deso_balance_nanos = int(balances['Balances']['DESO']['BalanceBaseUnits'])
    if deso_balance_nanos == 0:
        print(error_msg_SET_SEED)
        sys.exit(1)

    openfund_balance_base_units = int(balances['Balances'][openfund_pubkey]['BalanceBaseUnits'])
    print(f'DESO balance: {deso_balance_nanos} nanos (1e9 = 1 coin) = {client.base_units_to_coins(deso_balance_nanos, is_deso=True)} coins')
    print(f'OPENFUND balance: {openfund_balance_base_units} base units (1e18 = 1 coin) = {client.base_units_to_coins(openfund_balance_base_units, is_deso=False)} tokens')

    try:
        single_profile = client.get_single_profile(
            public_key_base58check=string_pubkey,
            username=None, # Use this if you want to fetch by username!
        )
        if single_profile is None:
            print(f"ERROR: Create a profile for your account so that you can mint tokens and other fun things. "
                  f"Use {client.node_url}/update-profile since IS_TESTNET={IS_TESTNET}. Change IS_TESTNET to switch "
                  f"between mainnet and testnet. See the top of main for other arguments. Other useful links: "
                  f"docs.deso.org {explorer_link}, {wallet_link}, {openfund_link}, {focus_link}. "
                  f"Message https://t.me/deso_pos_discussion for more help.")
            sys.exit(1)
        pprint(single_profile)
    except Exception as e:
        print(f"ERROR: Get profile failed: {e}")

    def print_balances():
        balances = client.get_token_balances(
            user_public_key=string_pubkey,
            creator_public_keys=[openfund_pubkey, "DESO", string_pubkey],
        )
        print('Balances: ', balances)
        deso_balance_nanos = int(balances['Balances']['DESO']['BalanceBaseUnits'])
        openfund_balance_base_units = int(balances['Balances'][openfund_pubkey]['BalanceBaseUnits'])
        print(f'DESO balance: {deso_balance_nanos} nanos (1e9 = 1 coin) = {client.base_units_to_coins(deso_balance_nanos, is_deso=True)} coins')
        print(f'OPENFUND balance: {openfund_balance_base_units} base units (1e18 = 1 coin) = {client.base_units_to_coins(openfund_balance_base_units, is_deso=False)} tokens')
        your_token_balance_base_units = int(balances['Balances'][string_pubkey]['BalanceBaseUnits'])
        print(f'${single_profile['Username']} balance: {your_token_balance_base_units} base units (1e18 = 1 coin) = {client.base_units_to_coins(your_token_balance_base_units, is_deso=False)} tokens')

    print("\n---- Transfer DESO ----")
    try:
        pprint('Constructing txn...')
        send_deso_response = client.send_deso(
            sender_pubkey_base58check=string_pubkey,
            recipient_pubkey_or_username=nader_pubkey,
            amount_nanos=1,
        )
        print('Txn constructed. Response is below. The txn construction response often has useful information in it:')
        pprint(send_deso_response)
        print('Signing and submitting txn...')
        submitted_txn_response = client.sign_and_submit_txn(send_deso_response)
        txn_hash = submitted_txn_response['TxnHashHex']
        print(f'Waiting for commitment... Hash = {txn_hash}. Find on {explorer_link}/txn/{txn_hash}. Sometimes it takes a minute to show up on the block explorer.')
        client.wait_for_commitment_with_timeout(txn_hash, 30.0)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Transfer tokens call failed: {e}")

    print("---- Mint Tokens (sign & submit - requires profile) ----")
    try:
        print_balances()
        coins_to_mint = client.coins_to_base_units(1.0, is_deso=False, hex_encode=True)
        mint_response = client.mint_or_burn_tokens(
            updater_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey, # Since you are minting your own token
            operation_type="mint",
            coins_to_mint_or_burn_nanos=coins_to_mint,
        )
        submitted_txn_response = client.sign_and_submit_txn(mint_response)
        txn_hash = submitted_txn_response['TxnHashHex']
        print(f'Waiting for commitment... Hash = {txn_hash}. Find on {explorer_link}/txn/{txn_hash}. Sometimes it takes a minute to show up on the block explorer.')
        client.wait_for_commitment_with_timeout(txn_hash, 30.0)
        print_balances()
        print('SUCCESS!')

    except Exception as e:
        print(f"ERROR: Mint tokens call failed: {e}")

    print("\n---- Atomic txn example (sign and submit - requires profile) ----")
    try:
        # Print the balance
        balances = client.get_token_balances(
            user_public_key=string_pubkey,
            creator_public_keys=[string_pubkey],
        )
        print('Balance before two mints: ', balances)
        mint_response_01 = client.mint_or_burn_tokens(
            updater_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey, # Since you are minting your own token
            operation_type="mint",
            coins_to_mint_or_burn_nanos="0xde0b6b3a7640000",
        )
        mint_response_02 = client.mint_or_burn_tokens(
            updater_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey, # Since you are minting your own token
            operation_type="mint",
            coins_to_mint_or_burn_nanos="0xde0b6b3a7640000",
        )
        atomic_txn_response = client.create_unsigned_atomic_txn(
            unsigned_transaction_hexes=[mint_response_01.get('TransactionHex'), mint_response_02.get('TransactionHex')],)
        submitted_txn_response = client.sign_and_submit_txn(atomic_txn_response)
        txn_hash = submitted_txn_response['TxnHashHex']
        print(f'Waiting for commitment... Hash = {txn_hash}. Find on {explorer_link}/txn/{txn_hash}. Sometimes it takes a minute to show up on the block explorer.')
        client.wait_for_commitment_with_timeout(txn_hash, 30.0)
        balances = client.get_token_balances(
            user_public_key=string_pubkey,
            creator_public_keys=[string_pubkey],
        )
        print('Balance after two mints: ', balances)
        print('SUCCESS!')

    except Exception as e:
        print(f"ERROR: Atomic txn example failed: {e}")

    print("\n---- Burn Tokens (construction of txn only) ----")
    try:
        burn_response = client.mint_or_burn_tokens(
            updater_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey, # Since you are burning your own token
            operation_type="burn",
            coins_to_mint_or_burn_nanos="0xde0b6b3a7640000",
        )
        pprint(burn_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Burn tokens call failed: {e}")

    print("\n---- Transfer Tokens (construction of txn only) ----")
    try:
        transfer_response = client.transfer_tokens(
            sender_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey,
            receiver_pubkey_base58check=nader_pubkey,
            token_to_transfer_base_units="0xde0b6b3a7640000",
        )
        pprint(transfer_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Transfer tokens call failed: {e}")

    print("\n---- Update Transfer Restriction Status (example construction of txn only) ----")
    try:
        update_status_response = client.update_transfer_restriction_status(
            updater_pubkey_base58check=string_pubkey,
            profile_pubkey_base58check=string_pubkey,
            transfer_restriction_status="profile_owner_only",
        )
        pprint(update_status_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Update restriction status call failed: {e}")

    print("\n---- Create Market Sell (construction of txn only) ----")
    try:
        market_sell_response = client.create_limit_order_with_fee(
            transactor_public_key=string_pubkey,
            quote_currency_public_key=DESO_TOKEN_PUBKEY,
            base_currency_public_key=string_pubkey,
            operation_type="ASK",
            price="0.000000000",
            price_currency_type="quote",
            quantity="0.000000001",
            fill_type="IMMEDIATE_OR_CANCEL",
            quantity_currency_type="base",
        )
        pprint(market_sell_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Market sell call failed: {e}")

    print("\n---- Create Limit Buy (construction of txn only) ----")
    try:
        limit_buy_response = client.create_limit_order_with_fee(
            transactor_public_key=string_pubkey,
            quote_currency_public_key=DESO_TOKEN_PUBKEY,
            base_currency_public_key=string_pubkey,
            operation_type="BID",
            price="1",
            price_currency_type="usd",
            quantity="0.000000001",
            quantity_currency_type="quote",
            fill_type="GOOD_TILL_CANCELLED",
        )
        pprint(limit_buy_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Limit buy call failed: {e}")

    print("\n---- Create Limit Sell (construction of txn only) ----")
    try:
        limit_sell_response = client.create_limit_order_with_fee(
            transactor_public_key=string_pubkey,
            quote_currency_public_key=DESO_TOKEN_PUBKEY,
            base_currency_public_key=string_pubkey,
            operation_type="ASK",
            price="0.01",
            price_currency_type="usd",
            quantity="0.000000001",
            quantity_currency_type="quote",
            fill_type="GOOD_TILL_CANCELLED",
        )
        pprint(limit_sell_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Limit sell call failed: {e}")

    print("\n---- Cancel an Order (construction of txn only) ----")
    try:
        cancel_response = client.cancel_limit_order(
            transactor_public_key="tBCKWkMW7SNyA4kuAHLtvFgdPRDgqS3gPfH5UWoeGZbxftkzUqpiKF",
            cancel_order_id="b3996cee436b5ddcea11b65047ddc26c5fdb6b34a947fd1d3a43c4212045b3ef",  # Example
        )
        pprint(cancel_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Cancel order call failed; this will fail on mainnet but not testnet: {e}")

    print("\n---- Get Open Orders for Market ($openfund vs DESO) ----")
    try:
        # Example: fetch the market for DESO and $openfund
        market_orders_response_1 = client.get_limit_orders(
            coin1_creator_pubkey=DESO_TOKEN_PUBKEY,
            coin2_creator_pubkey=openfund_pubkey,
        )
        pprint(market_orders_response_1)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Get open orders call 1 failed: {e}")

    print("\n---- Get Open Orders for Market ($openfund vs DESO, reversed) ----")
    try:
        market_orders_response_2 = client.get_limit_orders(
            coin1_creator_pubkey=openfund_pubkey,
            coin2_creator_pubkey=DESO_TOKEN_PUBKEY,
        )
        pprint(market_orders_response_2)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Get open orders call 2 failed: {e}")

    print("\n---- Get Open Orders for Transactor ----")
    try:
        user_orders_response = client.get_transactor_limit_orders(
            transactor_pubkey_base58check=nader_pubkey
        )
        pprint(user_orders_response)
        print('SUCCESS!')
    except Exception as e:
        print(f"ERROR: Get user open orders call failed: {e}")


if __name__ == "__main__":
    main()
