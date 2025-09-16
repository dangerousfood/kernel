// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {MerchantRegistry} from "./MerchantRegistry.sol";
import {
    MODULE_TYPE_EXECUTOR
} from "../types/Constants.sol";
import {EMVTransactionData} from "./EMVValidator.sol";
import {SafeTransferLib} from "lib/solady/src/utils/SafeTransferLib.sol";
import {Ownable} from "lib/solady/src/auth/Ownable.sol";

/**
 * @title EMVSettlement
 * @dev Handles EMV transaction settlement and ERC20 token transfers
 * @notice Processes EMV transaction data and executes corresponding token transfers
 */
contract EMVSettlement is Ownable {
    // ========== EVENTS ==========
    
    event EMVTransferExecuted(
        address indexed from,
        address indexed to,
        address indexed token,
        uint256 amount,
        bytes4 unpredictableNumber,
        uint16 atc
    );
    
    event EMVMultiTransferExecuted(
        address indexed from,
        address indexed token,
        uint256 totalAmount,
        bytes4 unpredictableNumber,
        uint16 atc,
        uint256 recipientCount
    );
    event EMVSettlementConfigured(address indexed account, address token, address recipient);
    event NetworkFeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    // ========== STORAGE ==========
    
    // Immutable configuration - accessible in both regular call and delegate call contexts
    address public immutable configuredToken;      // ERC20 token address for this settlement instance
    MerchantRegistry public immutable merchantRegistry; // Registry for merchant address validation
    uint8 public immutable decimals;                   // Token decimals for amount conversion
    uint256 public immutable networkFeeRate;             // Network fee rate in basis points (e.g., 250 = 2.5%)
    
    // Mutable configuration
    address public networkFeeRecipient;                 // Address to receive network fees

    // ========== CONSTRUCTOR ==========
    
    constructor(
        address _tokenAddress, 
        address _merchantRegistryAddress, 
        uint8 _decimals, 
        uint256 _networkFeeRateBasisPoints,
        address _networkFeeRecipient,
        address _owner
    ) {
        if (_tokenAddress == address(0) || _merchantRegistryAddress == address(0)) {
            revert InvalidConfig();
        }
        
        if (_decimals < 2) {
            revert InvalidDecimals();
        }
        
        if (_networkFeeRateBasisPoints > 10000) {
            revert InvalidNetworkFeeRate();
        }
        
        configuredToken = _tokenAddress;
        merchantRegistry = MerchantRegistry(_merchantRegistryAddress);
        decimals = _decimals;
        
        // Store basis points directly - we'll calculate the actual fee during execution
        // This preserves precision and allows proper percentage calculation
        // Example: 250 basis points = 2.5%
        networkFeeRate = _networkFeeRateBasisPoints;
        
        networkFeeRecipient = _networkFeeRecipient;
        
        // Initialize Ownable
        _initializeOwner(_owner);
    }

    // ========== ERRORS ==========
    
    error InvalidAmount();
    error MerchantNotRegistered(bytes15 merchantId);
    error MerchantRegistryNotSet();
    error InvalidConfig();
    error InvalidDecimals();
    error InvalidNetworkFeeRate();
    error InvalidNetworkFeeRecipient();
    error TotalTransfersExceedAmount();



    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module
     * @param data Installation data (not used - configuration is set in constructor)
     */
    function onInstall(bytes calldata data) external payable {
        // Configuration is set in constructor as immutable values
        // This function is called during module installation but config is already set
        emit EMVSettlementConfigured(msg.sender, configuredToken, address(0));
    }

    /**
     * @dev Uninstall the module
     * @param data Uninstallation data (not used for this contract)
     */
    function onUninstall(bytes calldata data) external payable {
        // Configuration is immutable, nothing to clean up
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        // Configuration is immutable and set in constructor, so always initialized
        return configuredToken != address(0) && address(merchantRegistry) != address(0) && decimals >= 2;
    }

    // ========== SETTLEMENT FUNCTIONS ==========

    /**
     * @dev Main entry point: Execute EMV-based ERC20 transfer using validated EMV data
     * @param emvData Packed EMV transaction data (should be same as from UserOp signature)
     */
    function execute(bytes calldata emvData) external payable {
        // Extract only the fields we need directly from packed data
        // Amount is at offset 14: ARQC(8) + UnpredictableNumber(4) + ATC(2) = 14
        bytes calldata amountBytes = emvData[14:20]; // 6 bytes for amount
        
        // MerchantId is at offset 42: ARQC(8) + UnpredictableNumber(4) + ATC(2) + Amount(6) + Currency(2) + Date(3) + TxnType(1) + TVR(5) + CVMResults(3) + TerminalId(8) = 42
        bytes15 merchantId = bytes15(emvData[42:57]); // 15 bytes for merchantId

        // Extract amount from EMV BCD format (6 bytes) using immutable decimals
        uint256 transferAmount = _extractAmountFromBCD(amountBytes, decimals);

        if (transferAmount == 0) {
            revert InvalidAmount();
        }
        
        // Get payment recipients from merchant registry
        MerchantRegistry.PaymentRecipient[] memory recipients = merchantRegistry.getMerchantPayments(merchantId);
        
        if (recipients.length == 0) {
            revert MerchantNotRegistered(merchantId);
        }

        // Expand recipients array by one using Yul to add network fee recipient
        if (networkFeeRate > 0 && networkFeeRecipient != address(0)) {
            assembly {
                // Load current length
                let len := mload(recipients)
                
                // Compute pointer for new element (each PaymentRecipient is 64 bytes = 0x40)
                let newElemPtr := add(add(recipients, 0x20), mul(len, 0x40))
                
                // Increase length by 1
                mstore(recipients, add(len, 1))
            }
            
            // Add network fee recipient in Solidity
            recipients[recipients.length - 1] = MerchantRegistry.PaymentRecipient({
                recipient: networkFeeRecipient,
                basisPoints: networkFeeRate
            });
        }

        // Extract unpredictable number and ATC for events
        bytes4 unpredictableNumber = bytes4(emvData[8:12]);
        uint16 atc = uint16(bytes2(emvData[12:14]));
        
        // Process payments to all recipients
        _processMultiplePayments(recipients, transferAmount, unpredictableNumber, atc);
    }



    // ========== CONFIGURATION FUNCTIONS ==========

    /**
     * @dev Get the configured token, merchant registry, and decimals
     * @return tokenAddress The configured ERC20 token address
     * @return registry The merchant registry address
     * @return tokenDecimals The configured token decimals
     */
    function getSettlementConfig() external view returns (address tokenAddress, address registry, uint8 tokenDecimals) {
        return (configuredToken, address(merchantRegistry), decimals);
    }
    
    /**
     * @dev Set the network fee recipient address (only owner)
     * @param _newRecipient New network fee recipient address
     */
    function setNetworkFeeRecipient(address _newRecipient) external onlyOwner {
        if (_newRecipient == address(0)) {
            revert InvalidNetworkFeeRecipient();
        }
        
        address oldRecipient = networkFeeRecipient;
        networkFeeRecipient = _newRecipient;
        
        emit NetworkFeeRecipientUpdated(oldRecipient, _newRecipient);
    }
    
    /**
     * @dev Get the network fee rate for validation purposes
     * @return The network fee rate in basis points
     */
    function getNetworkFeeRate() external view returns (uint256) {
        return networkFeeRate;
    }

    // ========== INTERNAL FUNCTIONS ==========

    /**
     * @dev Process payments to multiple recipients (including network fee as last recipient)
     * @param recipients Array of payment recipients with basis points (network fee included if applicable)
     * @param totalAmount Total amount to distribute
     * @param unpredictableNumber EMV unpredictable number for events
     * @param atc EMV application transaction counter for events
     */
    function _processMultiplePayments(
        MerchantRegistry.PaymentRecipient[] memory recipients,
        uint256 totalAmount,
        bytes4 unpredictableNumber,
        uint16 atc
    ) internal {
        uint256 totalTransferred = 0;
        
        // Distribute to each recipient based on their basis points from the total amount
        for (uint256 i = 0; i < recipients.length; i++) {
            uint256 recipientAmount = (totalAmount * recipients[i].basisPoints) / 10000;
            
            if (recipientAmount > 0) {
                totalTransferred += recipientAmount;
                SafeTransferLib.safeTransfer(configuredToken, recipients[i].recipient, recipientAmount);
            }
        }
 
        if (totalTransferred > totalAmount) {
            revert TotalTransfersExceedAmount();
        }
    }
    
    /**
     * @dev Calculate network fee for a given amount
     * @param amount The amount to calculate fee for
     * @return The network fee amount
     */
    function _calculateNetworkFee(uint256 amount) internal view returns (uint256) {
        // Calculate fee: (amount * networkFeeRate) / 10000
        // This preserves precision by doing multiplication first
        return (amount * networkFeeRate) / 10000;
    }

    /**
     * @dev Extract amount from EMV BCD format
     * @param bcdAmount 6-byte BCD encoded amount
     * @param tokenDecimals Number of decimals for the token
     * @return Amount in token units based on provided decimals
     */
    function _extractAmountFromBCD(bytes calldata bcdAmount, uint8 tokenDecimals) internal pure returns (uint256) {
        if (bcdAmount.length != 6) {
            return 0;
        }

        uint256 amount = 0;
        for (uint256 i = 0; i < 6; i++) {
            uint8 byte_val = uint8(bcdAmount[i]);
            uint8 high_nibble = byte_val >> 4;
            uint8 low_nibble = byte_val & 0x0F;
            
            // Validate BCD digits (0-9)
            if (high_nibble > 9 || low_nibble > 9) {
                return 0;
            }
            
            amount = amount * 100 + high_nibble * 10 + low_nibble;
        }
        
        // Convert from cents to token units using provided decimals
        // EMV amounts are typically in cents (2 decimal places)
        // So we need to convert: cents -> token units
        // Example: If token has 18 decimals, multiply by 10^(18-2) = 10^16
        return amount * 10**(tokenDecimals - 2);
    }
}
