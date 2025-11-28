// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

abstract contract ChainPermissionManager is AccessControlDefaultAdminRules {
    // Permission identifiers
    bytes32 public constant BLOCKLIST_ADMIN_ROLE =
        keccak256("BLOCKLIST_ADMIN_ROLE");

    // Storage for wallet address -> blocked status
    mapping(address => bool) private _blocked;

    // Notifications
    event AddedToBlocklist(address indexed account);
    event RemovedFromBlocklist(address indexed account);

    // Access restrictions
    modifier rejectBlocked(address account) {
        require(!isBlocked(account), "Account is blocked");
        _;
    }

    modifier rejectBlockedSender() {
        require(!isBlocked(_msgSender()), "Sender is blocked");
        _;
    }

    constructor(
        uint48 _delay,
        address _owner
    ) AccessControlDefaultAdminRules(_delay, _owner) {
        _grantRole(BLOCKLIST_ADMIN_ROLE, _owner);
    }

    function addToBlocklist(
        address account
    ) external onlyRole(BLOCKLIST_ADMIN_ROLE) {
        require(
            !hasRole(BLOCKLIST_ADMIN_ROLE, account),
            "Account is a blocklist admin"
        );
        require(account != address(0), "Account is the zero address");

        _blocked[account] = true;

        emit AddedToBlocklist(account);
    }

    function addBatchToBlocklist(
        address[] memory accounts
    ) external onlyRole(BLOCKLIST_ADMIN_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blocked[accounts[i]] = true;
        }
    }

    function assignRoles(
        bytes32[] memory roles,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) rejectBlocked(account) {
        for (uint256 i = 0; i < roles.length; i++) {
            // Bypass DEFAULT_ADMIN_ROLE since it's managed by AccessControlDefaultAdminRules
            if (roles[i] == DEFAULT_ADMIN_ROLE) continue;

            grantRole(roles[i], account);
        }
    }

    function isBlocked(address account) public view returns (bool) {
        if (account == address(0)) {
            return _blocked[_msgSender()];
        }
        return _blocked[account];
    }

    function removeFromBlocklist(
        address account
    ) external onlyRole(BLOCKLIST_ADMIN_ROLE) {
        delete _blocked[account];

        emit RemovedFromBlocklist(account);
    }

    function removeBatchFromBlocklist(
        address[] memory accounts
    ) external onlyRole(BLOCKLIST_ADMIN_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blocked[accounts[i]] = false;
        }
    }

    function withdrawRoles(
        bytes32[] memory roles,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < roles.length; i++) {
            // Bypass DEFAULT_ADMIN_ROLE since it's managed by AccessControlDefaultAdminRules
            if (roles[i] == DEFAULT_ADMIN_ROLE) continue;

            revokeRole(roles[i], account);
        }
    }
}

abstract contract ChainCoreERC1155 is
    ERC1155,
    ChainPermissionManager,
    ReentrancyGuard
{
    // Distinct collection identifier, for multi-chain uniformity
    bytes32 public immutable COLLECTION_ID;

    // Permission identifiers
    bytes32 public constant ASSET_ADMIN_ROLE =
        keccak256("ASSET_ADMIN_ROLE");
    bytes32 public constant ASSET_CREATOR_ROLE = keccak256("ASSET_CREATOR_ROLE");
    bytes32 public constant ASSET_DESTROYER_ROLE = keccak256("ASSET_DESTROYER_ROLE");

    // Structure for asset core information
    struct CoreMetadata {
        uint256 id;
        bool active;
        bool destroyable;
        bool movable;
    }

    // Storage from asset ID to core information
    mapping(uint256 => CoreMetadata) private _metadata;

    // Sequential asset ID counter
    uint256 internal currentTokenId = 0;

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) ERC1155(_uri) ChainPermissionManager(_delay, _owner) {
        // Create a distinct collection identifier using keccak256 hash of the name
        COLLECTION_ID = keccak256(abi.encodePacked(_name, _version));

        // Assign all permissions to the contract deployer
        _grantRole(ASSET_ADMIN_ROLE, _owner);
        _grantRole(ASSET_CREATOR_ROLE, _owner);
        _grantRole(ASSET_DESTROYER_ROLE, _owner);
    }

    function isActive(uint256 id) public view returns (bool) {
        return _metadata[id].active;
    }

    function coreMetadataOf(
        uint256 id
    ) public view returns (CoreMetadata memory) {
        return _metadata[id];
    }

    function coreMetadataOfAll() public view returns (CoreMetadata[] memory) {
        CoreMetadata[] memory result = new CoreMetadata[](currentTokenId);
        for (uint256 i = 0; i < currentTokenId; i++) {
            result[i] = _metadata[i];
        }
        return result;
    }

    function coreMetadataOfBatch(
        uint256[] memory ids
    ) public view returns (CoreMetadata[] memory) {
        CoreMetadata[] memory result = new CoreMetadata[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _metadata[ids[i]];
        }
        return result;
    }

    function destroy(address from, uint256 id, uint256 amount) external {
        require(
            hasRole(ASSET_DESTROYER_ROLE, _msgSender()),
            "Unauthorized destroyer"
        );
        _burn(from, id, amount);
    }

    function isDestroyable(uint256 id) public view returns (bool) {
        return _metadata[id].destroyable;
    }

    function destroyBatch(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external {
        require(
            hasRole(ASSET_DESTROYER_ROLE, _msgSender()),
            "Unauthorized destroyer"
        );
        _burnBatch(from, ids, amounts);
    }

    function isApprovedForAll(
        address account,
        address operator
    ) public view virtual override returns (bool) {
        if (isBlocked(account) || isBlocked(operator)) {
            return false;
        }
        return super.isApprovedForAll(account, operator);
    }

    function create(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external {
        require(
            hasRole(ASSET_CREATOR_ROLE, _msgSender()),
            "Unauthorized creator"
        );
        _mint(to, id, amount, data);
    }

    function createBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        require(
            hasRole(ASSET_CREATOR_ROLE, _msgSender()),
            "Unauthorized creator"
        );
        _mintBatch(to, ids, amounts, data);
    }

    function isMovable(uint256 id) public view returns (bool) {
        return _metadata[id].movable;
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes memory data
    ) public virtual override {
        super.safeTransferFrom(from, to, id, value, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values,
        bytes memory data
    ) public virtual override {
        super.safeBatchTransferFrom(from, to, ids, values, data);
    }

    function setApprovalForAll(
        address operator,
        bool approved
    ) public virtual override rejectBlocked(operator) rejectBlockedSender {
        super.setApprovalForAll(operator, approved);
    }

    function setCoreMetadata(
        uint256 id,
        bool _active,
        bool _destroyable,
        bool _movable
    ) public {
        require(
            hasRole(ASSET_ADMIN_ROLE, _msgSender()),
            "Unauthorized asset admin"
        );
        require(id <= currentTokenId, "Invalid asset ID");

        _metadata[id] = CoreMetadata(id, _active, _destroyable, _movable);

        if (id == currentTokenId) {
            currentTokenId++;
        }
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC1155, AccessControlDefaultAdminRules)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    )
        internal
        virtual
        override
        rejectBlocked(from)
        rejectBlocked(to)
        rejectBlockedSender
    {
        for (uint256 i = 0; i < ids.length; i++) {
            // Creation
            if (from == address(0)) {
                require(isActive(ids[i]), "Asset is not active");
            }
            // Destruction
            else if (to == address(0)) {
                require(isDestroyable(ids[i]), "Asset is not destroyable");
            }
            // Movement
            else {
                require(isActive(ids[i]), "Asset is not active");
                require(isMovable(ids[i]), "Asset is not movable");
            }
        }

        super._update(from, to, ids, values);
    }
}

abstract contract ChainBuyableERC1155 is ChainCoreERC1155 {
    // Treasury address for collecting payments
    address public treasury;

    // Permission identifiers
    bytes32 public constant TREASURY_ADMIN_ROLE =
        keccak256("TREASURY_ADMIN_ROLE");

    // Storage from asset ID to cost
    mapping(uint256 => uint256) private _costs;

    // Notifications
    event FundsExtracted(address indexed treasury, uint256 amount);
    event TokenBought(
        address indexed account,
        uint256 indexed id,
        uint256 amount
    );
    event TreasuryChanged(address indexed oldTreasury, address indexed newTreasury);

    // Access restrictions
    modifier requireAvailable(uint256 id) {
        require(isAvailable(id), "Asset is not available");
        _;
    }

    modifier requireCost(uint256 id) {
        require(costOf(id) > 0, "Asset has no cost");
        _;
    }

    modifier requireValidTreasury(address account) {
        // Verify that the treasury address is not the zero address or this contract address
        require(account != address(0), "Invalid treasury address");
        require(account != address(this), "Invalid treasury address");
        _;
    }

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) ChainCoreERC1155(_name, _version, _uri, _delay, _owner) {
        // Assign all permissions to the contract deployer
        _grantRole(TREASURY_ADMIN_ROLE, _owner);

        // Initialize the treasury address to the deployer address
        treasury = _owner;
    }

    function isAvailable(uint256 id) public view returns (bool) {
        return isActive(id) && _costs[id] > 0;
    }

    function costOf(uint256 id) public view returns (uint256) {
        return _costs[id];
    }

    function costOfAll() public view returns (uint256[] memory result) {
        result = new uint256[](currentTokenId);
        for (uint256 i = 0; i < currentTokenId; i++) {
            result[i] = _costs[i];
        }
        return result;
    }

    function costOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory result) {
        result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _costs[ids[i]];
        }
        return result;
    }

    function buy(
        address account,
        uint256 id,
        uint256 amount
    )
        external
        payable
        nonReentrant
        rejectBlocked(account)
        rejectBlockedSender
        requireAvailable(id)
        requireValidTreasury(treasury)
    {
        // When account is zero, default to the caller's address
        if (account == address(0)) {
            account = _msgSender();
        }

        // Compute the total cost
        uint256 totalCost = costOf(id) * amount;
        require(msg.value >= totalCost, "Insufficient payment");

        // Return any overpayment
        uint256 refund = msg.value - totalCost;
        if (refund > 0) {
            payable(_msgSender()).transfer(refund);
        }

        // Send the payment to the treasury
        payable(treasury).transfer(totalCost);

        // Create the bought assets for the buyer
        _mint(account, id, amount, "");

        emit TokenBought(account, id, amount);
    }

    function setCostOf(
        uint256 id,
        uint256 cost
    ) public rejectBlockedSender {
        require(
            hasRole(TREASURY_ADMIN_ROLE, _msgSender()),
            "Unauthorized treasury admin"
        );
        _costs[id] = cost;
    }

    function setCostOfBatch(
        uint256[] memory ids,
        uint256[] memory costs
    ) external rejectBlockedSender {
        require(
            hasRole(TREASURY_ADMIN_ROLE, _msgSender()),
            "Unauthorized treasury admin"
        );
        require(ids.length == costs.length, "Array lengths do not match");
        for (uint256 i = 0; i < ids.length; i++) {
            _costs[ids[i]] = costs[i];
        }
    }

    function setTreasury(address value) external requireValidTreasury(value) {
        require(
            hasRole(TREASURY_ADMIN_ROLE, _msgSender()),
            "Unauthorized treasury admin"
        );
        address oldTreasury = treasury;
        treasury = value;
        emit TreasuryChanged(oldTreasury, value);
    }

    function extractFunds()
        external
        payable
        nonReentrant
        requireValidTreasury(treasury)
    {
        require(
            hasRole(TREASURY_ADMIN_ROLE, _msgSender()),
            "Unauthorized treasury admin"
        );

        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to extract");

        payable(treasury).transfer(balance);

        emit FundsExtracted(treasury, balance);
    }
}

abstract contract ChainTimedERC1155 is ChainBuyableERC1155 {
    // Collection of assets that expire simultaneously
    struct Batch {
        uint256 balance;
        uint256 expiresAt;
    }

    // Storage from holder -> asset ID -> Batch[]
    mapping(address => mapping(uint256 => Batch[])) private _batch;

    // Storage from asset ID to asset lifespan in seconds
    mapping(uint256 => uint256) private _lifespans;

    // Notifications
    event ExpiredTokensDestroyed(
        address indexed account,
        uint256 indexed id,
        uint256 amount
    );

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) ChainBuyableERC1155(_name, _version, _uri, _delay, _owner) {}

    function balanceOf(
        address account,
        uint256 id
    ) public view override returns (uint256) {
        Batch[] storage batches = _batch[account][id];
        uint256 netBalance = super.balanceOf(account, id);
        uint256 _now = block.timestamp;

        // Subtract expired asset balances
        for (uint256 i = 0; i < batches.length; i++) {
            if (batches[i].expiresAt <= _now) {
                netBalance -= batches[i].balance;
            }
        }

        return netBalance;
    }

    function balanceOfAll(
        address account
    ) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](currentTokenId);
        for (uint256 i = 0; i < currentTokenId; i++) {
            balances[i] = balanceOf(account, i);
        }
        return balances;
    }

    function balanceOfBatch(
        address[] memory accounts,
        uint256[] memory ids
    ) public view override returns (uint256[] memory) {
        require(accounts.length == ids.length, "Length mismatch");
        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; i++) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    function holdingDetailsOf(
        address account,
        uint256 id
    ) external view returns (Batch[] memory) {
        return _validBatches(account, id);
    }

    function holdingDetailsOfAll(
        address account
    ) external view returns (Batch[][] memory) {
        Batch[][] memory result = new Batch[][](currentTokenId);
        for (uint256 i = 0; i < currentTokenId; i++) {
            result[i] = _validBatches(account, i);
        }
        return result;
    }

    function holdingDetailsOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (Batch[][] memory result) {
        require(accounts.length == ids.length, "Length mismatch");
        result = new Batch[][](accounts.length);

        for (uint256 i = 0; i < accounts.length; i++) {
            result[i] = _validBatches(accounts[i], ids[i]);
        }

        return result;
    }

    function _destroyBatchBalances(
        address account,
        uint256 id,
        uint256 amount
    ) internal {
        Batch[] storage batches = _batch[account][id];
        uint256 _now = block.timestamp;
        uint256 debt = amount;

        uint256 i = 0;
        while (i < batches.length && debt > 0) {
            if (batches[i].expiresAt <= _now) {
                i++;
                continue;
            }

            if (batches[i].balance > debt) {
                // Destroy partial asset batch
                batches[i].balance -= debt;
                debt = 0;
            } else {
                // Destroy entire asset batch
                debt -= batches[i].balance;
                batches[i].balance = 0;
            }
            i++;
        }
    }

    function expiryFor(uint256 id) public view returns (uint256) {
        return lifespanOf(id) == 0 ? type(uint256).max : block.timestamp + lifespanOf(id);
    }

    function _cleanBatches(address account, uint256 id) internal {
        Batch[] storage batches = _batch[account][id];
        uint256 _now = block.timestamp;

        // Move valid batches to the front of the array
        uint256 index = 0;
        uint256 expiredAmount = 0;
        for (uint256 i = 0; i < batches.length; i++) {
            bool isValid = batches[i].balance > 0 && batches[i].expiresAt > _now;
            if (isValid) {
                if (i != index) {
                    batches[index] = batches[i];
                }
                index++;
            } else {
                expiredAmount += batches[i].balance;
            }
        }

        // Delete invalid batches from the end of the array
        while (batches.length > index) {
            batches.pop();
        }

        // When expired batches were removed, emit notification with total expired amount
        if (expiredAmount > 0) {
            emit ExpiredTokensDestroyed(account, id, expiredAmount);
        }
    }

    function _moveBatches(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal {
        // Return early when moving to same holder or when amount is zero
        if (from == to || amount == 0) return;

        Batch[] storage batches = _batch[from][id];
        uint256 _now = block.timestamp;
        uint256 debt = amount;

        // Initial pass: Deduct balances from sender's batches (FIFO sequence)
        for (uint256 i = 0; i < batches.length && debt > 0; i++) {
            // Bypass asset batches that are expired or empty
            if (batches[i].expiresAt <= _now || batches[i].balance == 0) {
                continue;
            }

            if (batches[i].balance > debt) {
                // Move partial asset batch
                _insertOrUpdateBatch(to, id, debt, batches[i].expiresAt);
                batches[i].balance -= debt;
                debt = 0;
            } else {
                // Move entire asset batch
                _insertOrUpdateBatch(to, id, batches[i].balance, batches[i].expiresAt);
                debt -= batches[i].balance;
                batches[i].balance = 0;
            }
        }

        // Remove from sender asset batches that are expired or empty
        _cleanBatches(from, id);
    }

    function setLifespan(uint256 id, uint256 value) public {
        require(
            hasRole(ASSET_ADMIN_ROLE, _msgSender()),
            "Unauthorized asset admin"
        );
        require(isDestroyable(id), "Asset is not destroyable, so it cannot expire");
        _lifespans[id] = value;
    }

    function lifespanOf(uint256 id) public view returns (uint256) {
        return _lifespans[id];
    }

    function lifespanOfAll() public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](currentTokenId);
        for (uint256 i = 0; i < currentTokenId; i++) {
            result[i] = _lifespans[i];
        }
        return result;
    }

    function lifespanOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _lifespans[ids[i]];
        }
        return result;
    }

    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) internal virtual override {
        super._update(from, to, ids, values);

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 _id = ids[i];
            uint256 _amount = values[i];

            // Creation
            if (from == address(0)) {
                address _account = to;
                uint256 _expiresAt = expiryFor(_id);
                _insertOrUpdateBatch(_account, _id, _amount, _expiresAt);
            }
            // Destruction
            else if (to == address(0)) {
                address _account = to;
                _destroyBatchBalances(_account, _id, _amount);
                _cleanBatches(_account, _id);
            }
            // Movement
            else {
                _moveBatches(from, to, _id, _amount);
            }
        }
    }

    function _insertOrUpdateBatch(
        address account,
        uint256 id,
        uint256 amount,
        uint256 expiresAt
    ) internal {
        Batch[] storage batches = _batch[account][id];

        // Locate the proper position to add the batch (sorted by expiry, earliest to latest)
        uint256 insertIndex = batches.length;
        for (uint256 i = 0; i < batches.length; i++) {
            // Determine whether this is an insertion or modification
            if (batches[i].expiresAt > expiresAt) {
                // Add the new asset batch at this position
                insertIndex = i;
                break;
            } else if (batches[i].expiresAt == expiresAt) {
                // When an asset batch with matching expiry exists, merge the balances and exit
                batches[i].balance += amount;
                return;
            }
        }

        // When the new asset batch expires after all others, append it to the array and exit
        if (insertIndex == batches.length) {
            batches.push(Batch({balance: amount, expiresAt: expiresAt}));
            return;
        }

        // Relocate array elements to accommodate the new asset batch
        batches.push(Batch({balance: 0, expiresAt: 0})); // Allocate space at the end
        for (uint256 i = batches.length - 1; i > insertIndex; i--) {
            batches[i] = batches[i - 1];
        }

        // Place the new Batch at the proper position
        batches[insertIndex] = Batch({balance: amount, expiresAt: expiresAt});
    }

    function _validBatches(
        address account,
        uint256 id
    ) internal view returns (Batch[] memory) {
        // Initially, verify whether the holder has any assets
        uint256 balance = super.balanceOf(account, id);
        if (balance == 0) {
            // Return an empty array
            return new Batch[](0);
        }

        Batch[] storage batches = _batch[account][id];
        uint256 _now = block.timestamp;

        // Tally the batches that are not expired and have a balance
        uint256 validBatchCount = 0;
        for (uint256 i = 0; i < batches.length; i++) {
            if (batches[i].expiresAt > _now && batches[i].balance > 0) {
                validBatchCount++;
            }
        }

        // Allocate a new array of the proper size for valid batches
        Batch[] memory details = new Batch[](validBatchCount);
        uint256 index = 0;

        // Populate the array with valid batches, in proper order (earliest expiry first)
        for (uint256 i = 0; i < batches.length; i++) {
            if (batches[i].expiresAt > _now && batches[i].balance > 0) {
                details[index] = batches[i];
                index++;
            }
        }

        return details;
    }
}

contract ChainAuth is ChainTimedERC1155 {
    // Structure for asset information, including cost and lifespan
    struct TokenInfo {
        uint256 id;
        bool active;
        bool destroyable;
        bool movable;
        uint256 cost;
        uint256 lifespan;
    }

    // Notifications
    event TokenInfoCreated(uint256 indexed id, TokenInfo info);
    event TokenInfoUpdated(
        uint256 indexed id,
        TokenInfo oldInfo,
        TokenInfo newInfo
    );

    constructor(
        string memory name,
        string memory version,
        string memory uri,
        uint48 delay,
        address owner
    ) ChainTimedERC1155(name, version, uri, delay, owner) {}

    function tokenInfoOf(uint256 id) public view returns (TokenInfo memory) {
        // Fetch the core asset information
        CoreMetadata memory coreMetadata = coreMetadataOf(id);

        // Fetch the cost and lifespan for the asset
        uint256 cost = costOf(id);
        uint256 lifespan = lifespanOf(id);

        // Merge all information into a single structure
        TokenInfo memory info = TokenInfo({
            id: coreMetadata.id,
            active: coreMetadata.active,
            destroyable: coreMetadata.destroyable,
            movable: coreMetadata.movable,
            cost: cost,
            lifespan: lifespan
        });

        return info;
    }

    function tokenInfoOfAll() public view returns (TokenInfo[] memory) {
        TokenInfo[] memory result = new TokenInfo[](currentTokenId);

        // Utilize *OfAll methods to efficiently gather information
        CoreMetadata[] memory coreMetadataArray = coreMetadataOfAll();
        uint256[] memory costArray = costOfAll();
        uint256[] memory lifespanArray = lifespanOfAll();

        // Merge all information into a single structure
        for (uint256 i = 0; i < currentTokenId; i++) {
            result[i] = TokenInfo({
                id: coreMetadataArray[i].id,
                active: coreMetadataArray[i].active,
                destroyable: coreMetadataArray[i].destroyable,
                movable: coreMetadataArray[i].movable,
                cost: costArray[i],
                lifespan: lifespanArray[i]
            });
        }

        return result;
    }

    function tokenInfoOfBatch(
        uint256[] memory ids
    ) public view returns (TokenInfo[] memory) {
        TokenInfo[] memory result = new TokenInfo[](ids.length);

        // Utilize *OfBatch methods to efficiently gather information
        CoreMetadata[] memory coreMetadataArray = coreMetadataOfBatch(ids);
        uint256[] memory costArray = costOfBatch(ids);
        uint256[] memory lifespanArray = lifespanOfBatch(ids);

        // Merge all information into a single structure
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = TokenInfo({
                id: coreMetadataArray[i].id,
                active: coreMetadataArray[i].active,
                destroyable: coreMetadataArray[i].destroyable,
                movable: coreMetadataArray[i].movable,
                cost: costArray[i],
                lifespan: lifespanArray[i]
            });
        }

        return result;
    }

    function setTokenInfo(
        uint256 id,
        bool _active,
        bool _destroyable,
        bool _movable,
        uint256 _cost,
        uint256 _lifespan
    ) external {
        require(
            hasRole(ASSET_ADMIN_ROLE, _msgSender()),
            "Unauthorized asset admin"
        );

        // When the asset ID already exists, capture its current state
        bool isUpdate = id < currentTokenId;
        TokenInfo memory oldInfo;
        if (isUpdate) {
            oldInfo = tokenInfoOf(id);
        }

        // Configure core asset information
        setCoreMetadata(id, _active, _destroyable, _movable);

        // Configure asset cost (requires TREASURY_ADMIN_ROLE)
        if (hasRole(TREASURY_ADMIN_ROLE, _msgSender())) {
            setCostOf(id, _cost);
        }

        // Configure asset lifespan (only when asset is destroyable)
        if (_destroyable) {
            setLifespan(id, _lifespan);
        }

        // Emit notification for asset information creation or update
        TokenInfo memory newInfo = tokenInfoOf(id);
        if (isUpdate) {
            emit TokenInfoUpdated(id, oldInfo, newInfo);
        } else {
            emit TokenInfoCreated(id, newInfo);
        }
    }

    function updateURI(string memory value) external {
        require(
            hasRole(ASSET_ADMIN_ROLE, _msgSender()),
            "Unauthorized asset admin"
        );
        _setURI(value);
    }
}
