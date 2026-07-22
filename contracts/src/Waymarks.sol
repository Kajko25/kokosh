// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title Waymarks
/// @notice Fully on-chain badge NFTs marking Kokosh program milestones for kajko24.base.eth.
contract Waymarks is ERC721 {
    address public immutable owner;
    uint256 public nextId = 1;

    mapping(uint256 => string) public stageName;

    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _owner) ERC721("Waymarks", "WAYMARK") {
        owner = _owner;
    }

    function mint(address to, string calldata name_) external onlyOwner returns (uint256 tokenId) {
        tokenId = nextId++;
        stageName[tokenId] = name_;
        _safeMint(to, tokenId);
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        string memory name_ = stageName[tokenId];
        string memory svg = _svg(tokenId, name_);
        string memory json = string(
            abi.encodePacked(
                '{"name":"Waymark #',
                Strings.toString(tokenId),
                " - ",
                name_,
                '","description":"Kokosh program stage badge for kajko24.base.eth.",',
                '"image":"data:image/svg+xml;base64,',
                Base64.encode(bytes(svg)),
                '"}'
            )
        );
        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
    }

    function _svg(uint256 tokenId, string memory name_) internal pure returns (string memory) {
        return string(
            abi.encodePacked(
                '<svg xmlns="http://www.w3.org/2000/svg" width="350" height="350">',
                '<rect width="100%" height="100%" fill="#1a1a2e"/>',
                '<text x="20" y="40" fill="#eee" font-size="24" font-family="monospace">Waymark #',
                Strings.toString(tokenId),
                "</text>",
                '<text x="20" y="80" fill="#39ff88" font-size="18" font-family="monospace">',
                name_,
                "</text>",
                '<text x="20" y="320" fill="#666" font-size="12" font-family="monospace">kajko24.base.eth</text>',
                "</svg>"
            )
        );
    }
}
