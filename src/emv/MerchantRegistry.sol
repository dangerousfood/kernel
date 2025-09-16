// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {Ownable} from "lib/solady/src/auth/Ownable.sol";

/**
 * @title MerchantRegistry
 * @dev Registry for approved merchants with their corresponding payment recipients
 * @notice Only the owner can add/remove merchants, ensuring secure merchant validation
 */
contract MerchantRegistry is Ownable {
    
    // Struct to represent a payment recipient
    struct PaymentRecipient {
        address recipient;     // Address to receive payment
        uint256 basisPoints;   // Percentage in basis points (e.g., 5000 = 50%)
    }
    
    // Mapping from merchant ID (15 bytes) to their payment recipients (max 2)
    mapping(bytes15 => PaymentRecipient[]) public merchantPayments;
    
    // Events
    event MerchantRegistered(bytes15 indexed merchantId, PaymentRecipient[] recipients);
    event MerchantRemoved(bytes15 indexed merchantId);
    
    // Errors
    error InvalidMerchantId();
    error TooManyRecipients();
    error InvalidBasisPoints();

    constructor() {
        _initializeOwner(msg.sender);
    }

    /**
     * @dev Set payment recipients for a merchant (register, update, or remove)
     * @param merchantId The 15-byte merchant ID from EMV data (9F16)
     * @param recipients Array of payment recipients (max 2, empty array to remove)
     */
    function setMerchantPayments(bytes15 merchantId, PaymentRecipient[] calldata recipients) external onlyOwner {
        if (merchantId == bytes15(0)) revert InvalidMerchantId();
        if (recipients.length > 2) revert TooManyRecipients();
        
        // Clear existing recipients
        delete merchantPayments[merchantId];
        
        if (recipients.length == 0) {
            // Removing merchant
            emit MerchantRemoved(merchantId);
            return;
        }
        
        // Validate and set new recipients
        for (uint256 i = 0; i < recipients.length; i++) {
            if (recipients[i].recipient == address(0)) revert InvalidBasisPoints();
            if (recipients[i].basisPoints == 0 || recipients[i].basisPoints > 10000) {
                revert InvalidBasisPoints();
            }
            merchantPayments[merchantId].push(recipients[i]);
        }
        
        emit MerchantRegistered(merchantId, recipients);
    }

    /**
     * @dev Get the payment recipients for a merchant ID
     * @param merchantId The merchant ID to look up
     * @return recipients Array of payment recipients (empty if not registered)
     */
    function getMerchantPayments(bytes15 merchantId) external view returns (PaymentRecipient[] memory recipients) {
        return merchantPayments[merchantId];
    }
    
    /**
     * @dev Get the registered address for a merchant ID (backward compatibility)
     * @param merchantId The merchant ID to look up
     * @return merchantAddress The first registered address (address(0) if not registered)
     */
    function getMerchantAddress(bytes15 merchantId) external view returns (address) {
        PaymentRecipient[] memory recipients = merchantPayments[merchantId];
        return recipients.length > 0 ? recipients[0].recipient : address(0);
    }

    /**
     * @dev Check if a merchant is registered
     * @param merchantId The merchant ID to check
     * @return isRegistered True if the merchant is registered
     */
    function isMerchantRegistered(bytes15 merchantId) external view returns (bool) {
        return merchantPayments[merchantId].length > 0;
    }

    /**
     * @dev Batch set multiple merchants with single recipient each
     * @param merchantIds Array of merchant IDs
     * @param addresses Array of corresponding addresses (use address(0) to remove)
     * @param basisPoints Array of basis points for each address
     */
    function batchSetMerchants(bytes15[] calldata merchantIds, address[] calldata addresses, uint256[] calldata basisPoints) external onlyOwner {
        require(merchantIds.length == addresses.length && addresses.length == basisPoints.length, "MerchantRegistry: array length mismatch");
        
        for (uint256 i = 0; i < merchantIds.length; i++) {
            bytes15 merchantId = merchantIds[i];
            address merchantAddress = addresses[i];
            uint256 bp = basisPoints[i];
            
            if (merchantId == bytes15(0)) revert InvalidMerchantId();
            
            // Clear existing recipients
            delete merchantPayments[merchantId];
            
            if (merchantAddress == address(0)) {
                // Removing merchant
                emit MerchantRemoved(merchantId);
            } else {
                if (bp == 0 || bp > 10000) revert InvalidBasisPoints();
                
                PaymentRecipient[] memory recipients = new PaymentRecipient[](1);
                recipients[0] = PaymentRecipient(merchantAddress, bp);
                
                merchantPayments[merchantId].push(PaymentRecipient(merchantAddress, bp));
                emit MerchantRegistered(merchantId, recipients);
            }
        }
    }

    /**
     * @dev Get multiple merchant payment recipients at once
     * @param merchantIds Array of merchant IDs to look up
     * @return paymentsArray Array of payment recipient arrays
     */
    function getBatchMerchantPayments(bytes15[] calldata merchantIds) external view returns (PaymentRecipient[][] memory paymentsArray) {
        paymentsArray = new PaymentRecipient[][](merchantIds.length);
        for (uint256 i = 0; i < merchantIds.length; i++) {
            paymentsArray[i] = merchantPayments[merchantIds[i]];
        }
        return paymentsArray;
    }
    
    /**
     * @dev Get multiple merchant addresses at once (backward compatibility)
     * @param merchantIds Array of merchant IDs to look up
     * @return addresses Array of corresponding first addresses
     */
    function getMerchantAddresses(bytes15[] calldata merchantIds) external view returns (address[] memory addresses) {
        addresses = new address[](merchantIds.length);
        for (uint256 i = 0; i < merchantIds.length; i++) {
            PaymentRecipient[] memory recipients = merchantPayments[merchantIds[i]];
            addresses[i] = recipients.length > 0 ? recipients[0].recipient : address(0);
        }
        return addresses;
    }
}
