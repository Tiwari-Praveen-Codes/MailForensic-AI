// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EmailThreatRegistry
 * @author Praveen Tiwari
 * @dev Immutable threat intelligence and forensic evidence ledger on Monad Testnet.
 * High-throughput, low-latency logging of forensic hashes, risk scores, and threat indicators.
 */
contract EmailThreatRegistry {

    struct ThreatRecord {
        bytes32 emailHash;        // SHA-256 hash of email headers + body
        string senderDomain;     // e.g. spoofed-bank.com
        string threatType;       // Phishing, BEC, Malware, Spoofing, Quishing
        uint8 riskScore;         // 0 to 100 risk score from AI & Forensic Engine
        string ipfsReportHash;   // IPFS hash or CID of full forensic JSON/PDF report
        string originIp;         // Originating IP address of the mail hop
        address reporter;        // Address that submitted the threat report
        uint256 timestamp;       // Block timestamp when threat was recorded
        bool exists;
    }

    // Mapping from email SHA-256 hash to ThreatRecord
    mapping(bytes32 => ThreatRecord) public threats;
    
    // List of all recorded email hashes for indexing
    bytes32[] public recordedHashes;

    // Organization / SOC node permissions
    address public owner;
    address public constant DEFAULT_ADMIN = 0xa898e4C6FF1060cA00B4747B1d7343c86C724C2a;
    mapping(address => bool) public authorizedReporters;

    // Events for real-time monitoring and indexing
    event ThreatRecorded(
        bytes32 indexed emailHash,
        string senderDomain,
        string threatType,
        uint8 riskScore,
        string originIp,
        address indexed reporter,
        uint256 timestamp
    );

    event ReporterAuthorized(address indexed reporter);
    event ReporterRevoked(address indexed reporter);

    modifier onlyOwner() {
        require(msg.sender == owner || msg.sender == DEFAULT_ADMIN, "Only owner can perform this action");
        _;
    }

    modifier onlyAuthorized() {
        require(msg.sender == owner || msg.sender == DEFAULT_ADMIN || authorizedReporters[msg.sender], "Not authorized to record threat");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedReporters[msg.sender] = true;
        authorizedReporters[DEFAULT_ADMIN] = true;
    }

    /**
     * @notice Authorize a new SOC analyst or automated detection node
     */
    function authorizeReporter(address _reporter) external onlyOwner {
        authorizedReporters[_reporter] = true;
        emit ReporterAuthorized(_reporter);
    }

    /**
     * @notice Revoke authorization for a reporter
     */
    function revokeReporter(address _reporter) external onlyOwner {
        authorizedReporters[_reporter] = false;
        emit ReporterRevoked(_reporter);
    }

    /**
     * @notice Record a single forensic threat intelligence report
     * @param _emailHash SHA-256 hash of email headers + content
     * @param _senderDomain Extracted sender domain or spoofed identity
     * @param _threatType Classification label (e.g. "Phishing", "BEC")
     * @param _riskScore Composite score (0-100)
     * @param _ipfsReportHash Decentralized storage pointer or report ID
     * @param _originIp First external hop IP address
     */
    function recordThreat(
        bytes32 _emailHash,
        string calldata _senderDomain,
        string calldata _threatType,
        uint8 _riskScore,
        string calldata _ipfsReportHash,
        string calldata _originIp
    ) external onlyAuthorized {
        require(_emailHash != bytes32(0), "Invalid email hash");
        require(!threats[_emailHash].exists, "Threat already recorded on-chain");

        threats[_emailHash] = ThreatRecord({
            emailHash: _emailHash,
            senderDomain: _senderDomain,
            threatType: _threatType,
            riskScore: _riskScore,
            ipfsReportHash: _ipfsReportHash,
            originIp: _originIp,
            reporter: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        recordedHashes.push(_emailHash);

        emit ThreatRecorded(
            _emailHash,
            _senderDomain,
            _threatType,
            _riskScore,
            _originIp,
            msg.sender,
            block.timestamp
        );
    }

    /**
     * @notice Verify whether an email hash has been logged as a malicious threat
     * @param _emailHash SHA-256 hash to check
     */
    function verifyThreat(bytes32 _emailHash) external view returns (
        bool exists,
        string memory senderDomain,
        string memory threatType,
        uint8 riskScore,
        string memory ipfsReportHash,
        string memory originIp,
        address reporter,
        uint256 timestamp
    ) {
        ThreatRecord memory record = threats[_emailHash];
        return (
            record.exists,
            record.senderDomain,
            record.threatType,
            record.riskScore,
            record.ipfsReportHash,
            record.originIp,
            record.reporter,
            record.timestamp
        );
    }

    /**
     * @notice Total number of immutable threats logged
     */
    function getTotalThreats() external view returns (uint256) {
        return recordedHashes.length;
    }

    /**
     * @notice Retrieve paginated hashes
     */
    function getRecentHashes(uint256 offset, uint256 limit) external view returns (bytes32[] memory) {
        uint256 total = recordedHashes.length;
        if (offset >= total) {
            return new bytes32[](0);
        }

        uint256 count = limit;
        if (offset + count > total) {
            count = total - offset;
        }

        bytes32[] memory result = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = recordedHashes[total - 1 - (offset + i)];
        }
        return result;
    }
}
