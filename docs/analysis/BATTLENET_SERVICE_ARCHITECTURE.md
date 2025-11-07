# BATTLE.NET SERVICE ARCHITECTURE ANALYSIS
## Diablo II Multiplayer Game Service - Design & Implementation

**Document Version**: 1.0  
**Analysis Date**: November 6, 2025  
**Game Version**: Diablo II v1.14d (Classic & Lord of Destruction)  
**Analysis Tool**: Ghidra 11.4.2 + Game.exe reverse engineering

---

## Executive Summary

This document analyzes the original Blizzard Battle.net service architecture for Diablo II (1999-2000) and provides a comprehensive blueprint for implementing a modern Battle.net-like multiplayer service. Based on reverse engineering of Game.exe, D2Client.dll, D2Multi.dll, and D2Net.dll, we reconstruct the client-server protocols, matchmaking systems, character management, and game session coordination that enabled millions of players to connect and play together.

**Key Components**:
- **Authentication Service** - Account creation, login, password validation
- **Realm Service** - Character management, storage, ladder rankings
- **Chat Service** - Lobby system, channels, friend lists, whispers
- **Matchmaking Service** - Game creation, browsing, joining
- **Game Coordinator** - Session management, player synchronization
- **Anti-Cheat Service** - Validation, detection, prevention

**Original Battle.net Design** (1999-2000):
- Centralized server architecture (useast, uswest, europe, asia realms)
- TCP-based protocol with custom binary packets
- Stateful session management with realm-locked characters
- Client-side simulation with server validation
- Single-server game sessions (8 player max per game)

**Modern Implementation** (2025):
- Microservices architecture with containerization
- REST APIs + WebSocket for real-time communication
- Distributed game servers with load balancing
- Cloud-native scalability (AWS/Azure/GCP)
- Modern security (OAuth2, JWT, TLS 1.3)
- Cross-platform support (PC, mobile, console)

---

## Table of Contents

1. [Original Battle.net Architecture](#original-battlenet-architecture)
2. [Client-Side Components](#client-side-components)
3. [Server-Side Components](#server-side-components)
4. [Network Protocol Analysis](#network-protocol-analysis)
5. [Authentication & Account Management](#authentication--account-management)
6. [Character Management & Realm System](#character-management--realm-system)
7. [Chat & Social Features](#chat--social-features)
8. [Matchmaking & Game Sessions](#matchmaking--game-sessions)
9. [Game Coordination & Synchronization](#game-coordination--synchronization)
10. [Anti-Cheat & Security](#anti-cheat--security)
11. [Modern Implementation Blueprint](#modern-implementation-blueprint)
12. [Technology Stack Recommendations](#technology-stack-recommendations)
13. [Deployment Architecture](#deployment-architecture)
14. [Scalability & Performance](#scalability--performance)
15. [Community Server Projects](#community-server-projects)

---

## Original Battle.net Architecture

### High-Level System Design (1999-2000)

```
┌─────────────────────────────────────────────────────────────────┐
│                     BLIZZARD BATTLE.NET SERVERS                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   US East   │  │   US West   │  │   Europe    │  ...      │
│  │   Realm     │  │   Realm     │  │   Realm     │           │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘           │
│         │                │                │                    │
│  ┌──────▼────────────────▼────────────────▼──────┐           │
│  │         Authentication Service                 │           │
│  │  - Account validation (bnacct/bnpass)         │           │
│  │  - CD-Key validation                           │           │
│  │  - Session token generation                    │           │
│  └────────────────────────────────────────────────┘           │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐          │
│  │         Character Database (Per-Realm)          │          │
│  │  - Character storage (.d2s files)               │          │
│  │  - Inventory, skills, quests                    │          │
│  │  - Ladder rankings                              │          │
│  │  - Realm-locked (no cross-realm)                │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐          │
│  │         Chat Server (Lobby System)              │          │
│  │  - Public channels (General, Trade, etc.)       │          │
│  │  - Private channels                             │          │
│  │  - Friend lists & whispers                      │          │
│  │  - Game list broadcasting                       │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐          │
│  │         Game Coordinator                        │          │
│  │  - Game creation & listing                      │          │
│  │  - Player matchmaking                           │          │
│  │  - Game server assignment                       │          │
│  │  - Session state management                     │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐          │
│  │         Game Servers (Per-Game Instance)        │          │
│  │  - 8 player max per game                        │          │
│  │  - Authoritative simulation                     │          │
│  │  - Anti-cheat validation                        │          │
│  │  - State synchronization                        │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ TCP Port 6112 (Battle.net)
                              │ TCP Port 4000 (Game sessions)
                              │
┌─────────────────────────────▼─────────────────────────────────┐
│                     CLIENT (Game.exe)                          │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Game.exe (Launcher)                                           │
│      │                                                          │
│      ├─ D2Multi.dll (Battle.net protocol layer)               │
│      │     - Authentication packets                            │
│      │     - Chat protocol                                     │
│      │     - Game list protocol                                │
│      │     - Friend list management                            │
│      │                                                          │
│      ├─ D2Client.dll (Multiplayer UI & logic)                 │
│      │     - Lobby interface                                   │
│      │     - Character selection                               │
│      │     - Game creation/joining UI                          │
│      │     - Chat rendering                                    │
│      │                                                          │
│      ├─ D2Net.dll (Network transport)                         │
│      │     - TCP socket management                             │
│      │     - Packet serialization                              │
│      │     - Connection pooling                                │
│      │     - Network error handling                            │
│      │                                                          │
│      └─ D2Game.dll (Game simulation)                          │
│            - Client-side prediction                            │
│            - Input handling                                    │
│            - State interpolation                               │
│            - Server reconciliation                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

**1. Thin Client Architecture**
- Game.exe is only 70KB, minimal logic
- DLL-based modular design for different modes
- Server authoritative for all game state
- Client renders and predicts, server validates

**2. Realm Isolation**
- Characters locked to realm (US East, US West, Europe, Asia)
- No cross-realm play or transfers
- Independent ladder rankings per realm
- Load distribution across geographic regions

**3. Single-Server Game Sessions**
- One game server per 8-player game instance
- Direct peer-aware communication (not true P2P)
- Server coordinates all player actions
- Host migration not supported (game ends if host leaves)

**4. Custom Binary Protocol**
- TCP-based with custom packet structure
- Binary serialization for efficiency
- No encryption (security through obscurity)
- Port 6112 for Battle.net, port 4000 for games

**5. Client-Side Simulation with Server Validation**
- Client predicts movement and actions
- Server validates and broadcasts authoritative state
- Rollback on disagreement (rubber-banding)
- Anti-cheat checks on server

---

## Client-Side Components

### D2Multi.dll - Battle.net Protocol Layer

**Purpose**: Implements Battle.net communication protocol, handling authentication, chat, game listing, and social features.

**Key Functions** (Inferred from Game.exe analysis):

```c
// Authentication
BOOL BnMulti_Connect(char* realm);                      // Connect to Battle.net realm
BOOL BnMulti_Login(char* username, char* password);     // Authenticate user
BOOL BnMulti_ValidateCDKey(char* cdkey);               // Validate CD-Key
void BnMulti_Disconnect();                              // Disconnect from Battle.net

// Character Management
BOOL BnMulti_GetCharacterList(CharacterInfo** chars);   // Retrieve character list
BOOL BnMulti_CreateCharacter(CharacterInfo* info);      // Create new character
BOOL BnMulti_DeleteCharacter(char* charName);           // Delete character
BOOL BnMulti_SelectCharacter(char* charName);           // Enter game with character

// Chat System
BOOL BnMulti_JoinChannel(char* channelName);            // Join chat channel
BOOL BnMulti_SendChatMessage(char* message);            // Send message to channel
BOOL BnMulti_SendWhisper(char* recipient, char* msg);   // Private message
void BnMulti_RegisterChatCallback(ChatCallback fn);     // Receive chat events

// Game Listing & Matchmaking
BOOL BnMulti_CreateGame(GameInfo* info);                // Create new game
GameInfo* BnMulti_GetGameList();                        // Retrieve available games
BOOL BnMulti_JoinGame(char* gameName, char* password);  // Join existing game
void BnMulti_RefreshGameList();                         // Update game list

// Friend List & Social
BOOL BnMulti_AddFriend(char* username);                 // Add to friend list
BOOL BnMulti_RemoveFriend(char* username);              // Remove from friend list
FriendInfo* BnMulti_GetFriendList();                    // Get friend list
BOOL BnMulti_GetFriendStatus(char* username);           // Check friend online status
```

**Battle.net Connection Sequence**:
```c
// 1. Establish TCP connection to realm server
SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
connect(sock, realmAddress, sizeof(realmAddress));

// 2. Send authentication packet
BnPacket authPacket = {
    .packetId = BN_PKT_AUTH_REQUEST,
    .username = username,
    .passwordHash = MD5(password),
    .cdkeyHash = SHA1(cdkey),
    .gameVersion = 0x0E,  // v1.14d
    .clientToken = GenerateRandomToken()
};
SendPacket(sock, &authPacket);

// 3. Receive authentication response
BnPacket response;
RecvPacket(sock, &response);
if (response.packetId == BN_PKT_AUTH_SUCCESS) {
    sessionToken = response.sessionToken;
    // Proceed to character selection
} else {
    // Display error: Invalid credentials, banned, etc.
}

// 4. Request character list
BnPacket charListReq = {
    .packetId = BN_PKT_CHAR_LIST_REQUEST,
    .sessionToken = sessionToken
};
SendPacket(sock, &charListReq);

// 5. Enter chat lobby
BnPacket joinChat = {
    .packetId = BN_PKT_JOIN_CHANNEL,
    .channelName = "General - 1"
};
SendPacket(sock, &joinChat);
```

**Command-Line Integration**:
```bash
# Game.exe command-line flags for Battle.net
Game.exe -skiptobnet              # Skip launcher, go directly to Battle.net
Game.exe -bnacct MyUsername       # Auto-fill username
Game.exe -bnpass MyPassword       # Auto-fill password (INSECURE!)
Game.exe -realm useast            # Select realm (useast, uswest, europe, asia)
```

### D2Client.dll - Multiplayer UI & Logic

**Purpose**: Handles multiplayer user interface, game session management, and client-side game logic for networked play.

**Key Responsibilities**:
- Render Battle.net lobby interface
- Display chat messages and game lists
- Handle character selection screen
- Manage game creation/joining UI
- Process player input and send to server
- Interpolate remote player positions
- Render other players' characters

**Multiplayer UI Components**:
```
┌─────────────────────────────────────────────────────────────┐
│  BATTLE.NET LOBBY INTERFACE                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐  ┌────────────────────────────┐  │
│  │  CHANNELS           │  │  CHAT WINDOW               │  │
│  │  ├─ General - 1     │  │  <PlayerA>: Trade game?   │  │
│  │  ├─ Trade - 1       │  │  <PlayerB>: WTB SOJ       │  │
│  │  ├─ PvP - 1         │  │  <PlayerC>: LF Baal run   │  │
│  │  └─ Support         │  │  ...                       │  │
│  └─────────────────────┘  └────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  GAME LIST                                          │  │
│  │  ┌──────────┬─────┬──────┬──────────────────────┐  │  │
│  │  │Game Name │Plrs │Lvl   │Description          │  │  │
│  │  ├──────────┼─────┼──────┼──────────────────────┤  │  │
│  │  │Baal-001  │7/8  │90-99 │Baal runs Hell       │  │  │
│  │  │Trade     │4/8  │1-99  │Trading              │  │  │
│  │  │Leveling  │2/8  │1-20  │Normal Act 1 runs    │  │  │
│  │  │PvP-Duel  │8/8  │80+   │FULL                 │  │  │
│  │  └──────────┴─────┴──────┴──────────────────────┘  │  │
│  │  [Create Game] [Join Game] [Refresh]              │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────────┐  ┌────────────────────────────┐  │
│  │  FRIENDS LIST       │  │  CHARACTER                 │  │
│  │  ├─ BobTheBarb ●    │  │  Name: Sorceress123       │  │
│  │  ├─ PaladinPete ●   │  │  Level: 85                │  │
│  │  └─ NecroJoe ○      │  │  Class: Sorceress         │  │
│  │  (● online ○ offline) │  │  [Change] [Stats]        │  │
│  └─────────────────────┘  └────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### D2Net.dll - Network Transport Layer

**Purpose**: Low-level network communication, socket management, packet serialization/deserialization.

**Key Features**:
- TCP socket pool management
- Packet queuing and prioritization
- Network bandwidth optimization
- Connection state monitoring
- Error recovery and reconnection

**Packet Structure** (Inferred):
```c
typedef struct BattleNetPacket {
    BYTE packetId;           // Packet type identifier
    WORD packetSize;         // Total size including header
    DWORD sequenceNumber;    // For ordering and loss detection
    DWORD timestamp;         // Client timestamp
    BYTE payload[];          // Variable-length payload
    WORD checksum;           // CRC16 for integrity
} BnPacket;

// Example packet IDs (reverse-engineered)
#define BN_PKT_AUTH_REQUEST         0x01
#define BN_PKT_AUTH_SUCCESS         0x02
#define BN_PKT_AUTH_FAILURE         0x03
#define BN_PKT_CHAR_LIST_REQUEST    0x10
#define BN_PKT_CHAR_LIST_RESPONSE   0x11
#define BN_PKT_CHAR_CREATE          0x12
#define BN_PKT_CHAR_DELETE          0x13
#define BN_PKT_JOIN_CHANNEL         0x20
#define BN_PKT_LEAVE_CHANNEL        0x21
#define BN_PKT_CHAT_MESSAGE         0x22
#define BN_PKT_WHISPER              0x23
#define BN_PKT_GAME_CREATE          0x30
#define BN_PKT_GAME_LIST_REQUEST    0x31
#define BN_PKT_GAME_LIST_RESPONSE   0x32
#define BN_PKT_GAME_JOIN            0x33
#define BN_PKT_GAME_LEAVE           0x34
#define BN_PKT_PLAYER_STATE         0x40
#define BN_PKT_PLAYER_MOVE          0x41
#define BN_PKT_PLAYER_ATTACK        0x42
#define BN_PKT_ITEM_DROP            0x43
#define BN_PKT_NPC_INTERACTION      0x44
```

---

## Server-Side Components

### Authentication Service

**Purpose**: Validate user credentials, manage sessions, enforce account policies.

**Core Functions**:
```python
# Modern Python implementation example
class AuthenticationService:
    def authenticate(self, username: str, password: str, cdkey: str) -> AuthResult:
        """
        Authenticates user credentials and CD-Key
        
        Returns:
            AuthResult with session token or error
        """
        # 1. Validate username format
        if not self.is_valid_username(username):
            return AuthResult(success=False, error="INVALID_USERNAME")
        
        # 2. Check if account exists
        account = self.db.get_account(username)
        if not account:
            return AuthResult(success=False, error="ACCOUNT_NOT_FOUND")
        
        # 3. Verify password hash
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if account.password_hash != password_hash:
            # Log failed attempt, implement rate limiting
            self.increment_failed_attempts(username)
            return AuthResult(success=False, error="INVALID_PASSWORD")
        
        # 4. Validate CD-Key
        if not self.validate_cdkey(cdkey):
            return AuthResult(success=False, error="INVALID_CDKEY")
        
        # 5. Check if already logged in
        if self.is_logged_in(username):
            # Option: Kick existing session or deny new login
            self.disconnect_existing_session(username)
        
        # 6. Check for bans
        if account.is_banned:
            return AuthResult(success=False, error="ACCOUNT_BANNED", 
                            ban_reason=account.ban_reason,
                            ban_expires=account.ban_expires)
        
        # 7. Generate session token
        session_token = self.generate_session_token(username)
        
        # 8. Store session
        self.session_store.set(session_token, {
            'username': username,
            'login_time': time.time(),
            'ip_address': self.get_client_ip(),
            'realm': 'useast'
        })
        
        # 9. Update last login timestamp
        self.db.update_last_login(username)
        
        return AuthResult(success=True, session_token=session_token)
    
    def validate_session(self, session_token: str) -> bool:
        """Verify session token is valid and not expired"""
        session = self.session_store.get(session_token)
        if not session:
            return False
        
        # Check expiration (e.g., 24 hour session)
        if time.time() - session['login_time'] > 86400:
            self.session_store.delete(session_token)
            return False
        
        return True
    
    def logout(self, session_token: str):
        """End user session"""
        self.session_store.delete(session_token)
```

**Database Schema (Modern SQL)**:
```sql
-- Accounts table
CREATE TABLE accounts (
    account_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(16) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,  -- SHA-256
    email VARCHAR(255),
    cdkey_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason TEXT,
    ban_expires TIMESTAMP,
    failed_login_attempts INT DEFAULT 0,
    last_failed_attempt TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Sessions table (or use Redis for speed)
CREATE TABLE sessions (
    session_token VARCHAR(64) PRIMARY KEY,
    account_id BIGINT NOT NULL,
    realm VARCHAR(16),
    ip_address VARCHAR(45),
    login_time TIMESTAMP,
    last_activity TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);

-- CD-Keys table
CREATE TABLE cdkeys (
    cdkey_hash VARCHAR(64) PRIMARY KEY,
    account_id BIGINT,
    game_type ENUM('D2', 'D2_LOD'),
    is_valid BOOLEAN DEFAULT TRUE,
    activation_date TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);
```

### Character Management & Realm System

**Purpose**: Store and manage player characters, inventories, stats, and progression.

**Character Storage**:
```python
class CharacterService:
    def create_character(self, account_id: int, char_info: CharacterInfo) -> Character:
        """
        Create new character for account
        
        Character is realm-locked and cannot be transferred
        """
        # Validate character name uniqueness per realm
        if self.db.character_exists(char_info.name, char_info.realm):
            raise ValueError("Character name already exists")
        
        # Validate character class
        valid_classes = ['Amazon', 'Sorceress', 'Necromancer', 'Paladin', 
                        'Barbarian', 'Druid', 'Assassin']
        if char_info.char_class not in valid_classes:
            raise ValueError("Invalid character class")
        
        # Check account character limit (max 8-18 depending on expansion)
        char_count = self.db.count_characters(account_id, char_info.realm)
        if char_count >= 18:  # LOD limit
            raise ValueError("Maximum character limit reached")
        
        # Create character record
        character = Character(
            account_id=account_id,
            name=char_info.name,
            char_class=char_info.char_class,
            realm=char_info.realm,
            level=1,
            experience=0,
            strength=20,  # Base stats by class
            dexterity=20,
            vitality=20,
            energy=20,
            created_at=time.time()
        )
        
        # Save to database
        char_id = self.db.insert_character(character)
        
        # Create default inventory
        self.create_default_inventory(char_id)
        
        return character
    
    def get_character_list(self, account_id: int, realm: str) -> List[CharacterSummary]:
        """Retrieve all characters for account in realm"""
        return self.db.get_characters_for_account(account_id, realm)
    
    def save_character(self, character: Character):
        """Persist character state to database"""
        # Save character stats
        self.db.update_character(character)
        
        # Save inventory
        self.db.update_inventory(character.id, character.inventory)
        
        # Save skill tree
        self.db.update_skills(character.id, character.skills)
        
        # Save quest progress
        self.db.update_quests(character.id, character.quests)
        
        # Update ladder ranking if applicable
        if character.is_ladder:
            self.update_ladder_ranking(character)
    
    def delete_character(self, account_id: int, char_name: str, realm: str):
        """Delete character (with optional grace period for recovery)"""
        character = self.db.get_character(char_name, realm)
        
        if character.account_id != account_id:
            raise PermissionError("Character does not belong to this account")
        
        # Soft delete with 30-day recovery period
        self.db.mark_character_deleted(character.id, 
                                       delete_time=time.time(),
                                       recoverable_until=time.time() + 2592000)
```

**Character Database Schema**:
```sql
-- Characters table
CREATE TABLE characters (
    character_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    account_id BIGINT NOT NULL,
    realm VARCHAR(16) NOT NULL,
    name VARCHAR(16) NOT NULL,
    char_class ENUM('Amazon', 'Sorceress', 'Necromancer', 'Paladin', 
                    'Barbarian', 'Druid', 'Assassin') NOT NULL,
    level INT DEFAULT 1,
    experience BIGINT DEFAULT 0,
    strength INT,
    dexterity INT,
    vitality INT,
    energy INT,
    life INT,
    mana INT,
    is_hardcore BOOLEAN DEFAULT FALSE,
    is_ladder BOOLEAN DEFAULT FALSE,
    is_expansion BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_played TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP,
    playtime_seconds INT DEFAULT 0,
    UNIQUE KEY unique_char_realm (name, realm),
    FOREIGN KEY (account_id) REFERENCES accounts(account_id),
    INDEX idx_account (account_id),
    INDEX idx_ladder (realm, is_ladder, level DESC)
);

-- Inventory table
CREATE TABLE character_inventory (
    inventory_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    character_id BIGINT NOT NULL,
    slot_type ENUM('equipment', 'inventory', 'stash', 'cube'),
    slot_index INT,
    item_id VARCHAR(32),  -- Unique item instance ID
    item_type VARCHAR(32),  -- e.g., "Ring", "Armor", "Weapon"
    item_quality ENUM('normal', 'magic', 'rare', 'unique', 'set', 'craft'),
    item_data JSON,  -- Full item properties (sockets, stats, etc.)
    FOREIGN KEY (character_id) REFERENCES characters(character_id)
);

-- Skills table
CREATE TABLE character_skills (
    skill_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    character_id BIGINT NOT NULL,
    skill_name VARCHAR(32),
    skill_level INT DEFAULT 0,
    FOREIGN KEY (character_id) REFERENCES characters(character_id)
);

-- Quest progress
CREATE TABLE character_quests (
    quest_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    character_id BIGINT NOT NULL,
    difficulty ENUM('normal', 'nightmare', 'hell'),
    quest_name VARCHAR(32),
    is_completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP,
    FOREIGN KEY (character_id) REFERENCES characters(character_id)
);

-- Ladder rankings
CREATE TABLE ladder_rankings (
    ranking_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    character_id BIGINT NOT NULL,
    realm VARCHAR(16),
    char_class VARCHAR(16),
    level INT,
    experience BIGINT,
    rank INT,
    updated_at TIMESTAMP,
    FOREIGN KEY (character_id) REFERENCES characters(character_id),
    INDEX idx_realm_rank (realm, rank)
);
```

### Chat Service & Social Features

**Purpose**: Real-time chat, channels, whispers, friend lists, presence.

**Chat Server Implementation**:
```python
class ChatService:
    def __init__(self):
        self.channels = {}  # channel_name -> set(user_sessions)
        self.user_channels = {}  # session_token -> channel_name
        self.friend_lists = {}  # account_id -> set(friend_account_ids)
    
    def join_channel(self, session_token: str, channel_name: str):
        """Add user to chat channel"""
        # Get user info from session
        session = self.session_store.get(session_token)
        username = session['username']
        
        # Leave current channel
        self.leave_current_channel(session_token)
        
        # Create channel if doesn't exist
        if channel_name not in self.channels:
            self.channels[channel_name] = set()
        
        # Add user to channel
        self.channels[channel_name].add(session_token)
        self.user_channels[session_token] = channel_name
        
        # Broadcast join message to channel
        self.broadcast_to_channel(channel_name, {
            'type': 'user_joined',
            'username': username,
            'timestamp': time.time()
        }, exclude=session_token)
        
        # Send channel user list to joining user
        user_list = [self.get_username(s) for s in self.channels[channel_name]]
        self.send_to_user(session_token, {
            'type': 'channel_users',
            'users': user_list
        })
    
    def send_message(self, session_token: str, message: str):
        """Send message to current channel"""
        session = self.session_store.get(session_token)
        username = session['username']
        channel_name = self.user_channels.get(session_token)
        
        if not channel_name:
            raise ValueError("User not in channel")
        
        # Validate message (length, profanity filter, etc.)
        if len(message) > 256:
            raise ValueError("Message too long")
        
        # Broadcast message to all channel users
        self.broadcast_to_channel(channel_name, {
            'type': 'chat_message',
            'username': username,
            'message': message,
            'timestamp': time.time()
        })
        
        # Log for moderation
        self.log_chat_message(username, channel_name, message)
    
    def send_whisper(self, session_token: str, recipient: str, message: str):
        """Send private message to another user"""
        session = self.session_store.get(session_token)
        sender = session['username']
        
        # Find recipient session
        recipient_session = self.find_user_session(recipient)
        if not recipient_session:
            self.send_to_user(session_token, {
                'type': 'whisper_error',
                'error': 'User not online'
            })
            return
        
        # Send whisper to recipient
        self.send_to_user(recipient_session, {
            'type': 'whisper_received',
            'from': sender,
            'message': message,
            'timestamp': time.time()
        })
        
        # Confirm to sender
        self.send_to_user(session_token, {
            'type': 'whisper_sent',
            'to': recipient,
            'message': message
        })
    
    def add_friend(self, account_id: int, friend_username: str):
        """Add user to friend list"""
        # Get friend account ID
        friend_account = self.db.get_account_by_username(friend_username)
        if not friend_account:
            raise ValueError("User not found")
        
        # Add to friend list
        if account_id not in self.friend_lists:
            self.friend_lists[account_id] = set()
        
        self.friend_lists[account_id].add(friend_account.id)
        
        # Save to database
        self.db.add_friend(account_id, friend_account.id)
        
        # Notify if friend is online
        if self.is_online(friend_account.id):
            session_token = self.get_session_for_account(account_id)
            self.send_to_user(session_token, {
                'type': 'friend_online',
                'username': friend_username
            })
    
    def get_friend_status(self, account_id: int) -> List[FriendStatus]:
        """Get online status of all friends"""
        friends = self.friend_lists.get(account_id, set())
        
        friend_status = []
        for friend_id in friends:
            friend_account = self.db.get_account(friend_id)
            is_online = self.is_online(friend_id)
            
            status = FriendStatus(
                username=friend_account.username,
                is_online=is_online,
                current_game=self.get_current_game(friend_id) if is_online else None,
                last_seen=friend_account.last_login
            )
            friend_status.append(status)
        
        return friend_status
```

### Matchmaking & Game Sessions

**Purpose**: Game creation, listing, joining, and session coordination.

**Game Coordinator**:
```python
class GameCoordinator:
    def __init__(self):
        self.active_games = {}  # game_id -> GameSession
        self.game_servers = []  # Available game server instances
    
    def create_game(self, session_token: str, game_info: GameInfo) -> str:
        """
        Create new game session
        
        Returns: game_id for joining
        """
        session = self.session_store.get(session_token)
        character = self.character_service.get_selected_character(session_token)
        
        # Validate game info
        if not self.is_valid_game_name(game_info.name):
            raise ValueError("Invalid game name")
        
        # Check if game name already exists
        if self.game_exists(game_info.name, game_info.realm):
            raise ValueError("Game name already in use")
        
        # Assign game server
        game_server = self.select_game_server()
        
        # Create game session
        game_id = self.generate_game_id()
        game_session = GameSession(
            game_id=game_id,
            name=game_info.name,
            realm=game_info.realm,
            difficulty=game_info.difficulty,
            max_players=8,
            is_password_protected=bool(game_info.password),
            password_hash=hashlib.sha256(game_info.password.encode()).hexdigest() if game_info.password else None,
            creator=character.name,
            creator_level=character.level,
            game_server=game_server,
            created_at=time.time(),
            players=[]
        )
        
        # Add creator to game
        game_session.players.append(PlayerInfo(
            character_id=character.id,
            character_name=character.name,
            character_class=character.char_class,
            level=character.level,
            is_host=True
        ))
        
        # Register game
        self.active_games[game_id] = game_session
        
        # Initialize game on game server
        game_server.initialize_game(game_session)
        
        # Add to game list
        self.broadcast_game_list_update()
        
        return game_id
    
    def get_game_list(self, realm: str, filters: GameFilters) -> List[GameInfo]:
        """Retrieve list of available games for realm"""
        games = [
            g for g in self.active_games.values()
            if g.realm == realm and len(g.players) < g.max_players
        ]
        
        # Apply filters
        if filters.min_level:
            games = [g for g in games if g.creator_level >= filters.min_level]
        if filters.max_level:
            games = [g for g in games if g.creator_level <= filters.max_level]
        if filters.difficulty:
            games = [g for g in games if g.difficulty == filters.difficulty]
        
        # Sort by creation time (newest first)
        games.sort(key=lambda g: g.created_at, reverse=True)
        
        # Return limited list (e.g., 50 most recent)
        return [self.game_to_info(g) for g in games[:50]]
    
    def join_game(self, session_token: str, game_name: str, password: str = None) -> GameJoinResult:
        """Join existing game"""
        session = self.session_store.get(session_token)
        character = self.character_service.get_selected_character(session_token)
        
        # Find game
        game = self.find_game_by_name(game_name, session['realm'])
        if not game:
            return GameJoinResult(success=False, error="Game not found")
        
        # Check if full
        if len(game.players) >= game.max_players:
            return GameJoinResult(success=False, error="Game is full")
        
        # Verify password
        if game.is_password_protected:
            if not password:
                return GameJoinResult(success=False, error="Password required")
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash != game.password_hash:
                return GameJoinResult(success=False, error="Incorrect password")
        
        # Check character compatibility (level range, etc.)
        if not self.is_character_compatible(character, game):
            return GameJoinResult(success=False, error="Character level out of range")
        
        # Add player to game
        game.players.append(PlayerInfo(
            character_id=character.id,
            character_name=character.name,
            character_class=character.char_class,
            level=character.level,
            is_host=False
        ))
        
        # Notify game server
        game.game_server.player_joined(game.game_id, character)
        
        # Notify other players
        self.broadcast_to_game(game.game_id, {
            'type': 'player_joined',
            'character': character.name,
            'class': character.char_class,
            'level': character.level
        }, exclude=session_token)
        
        # Update game list
        self.broadcast_game_list_update()
        
        # Return game server connection info
        return GameJoinResult(
            success=True,
            game_server_ip=game.game_server.ip,
            game_server_port=game.game_server.port,
            game_id=game.game_id,
            players=game.players
        )
    
    def leave_game(self, session_token: str):
        """Player leaves current game"""
        session = self.session_store.get(session_token)
        game = self.find_game_for_session(session_token)
        
        if not game:
            return
        
        # Remove player from game
        game.players = [p for p in game.players if p.session_token != session_token]
        
        # If host left, migrate host or end game
        if len(game.players) == 0:
            # Game empty, destroy it
            self.destroy_game(game.game_id)
        elif all(not p.is_host for p in game.players):
            # Assign new host (first remaining player)
            game.players[0].is_host = True
            self.broadcast_to_game(game.game_id, {
                'type': 'host_migration',
                'new_host': game.players[0].character_name
            })
        
        # Update game list
        self.broadcast_game_list_update()
    
    def select_game_server(self) -> GameServer:
        """Load balancing: select game server with lowest load"""
        if not self.game_servers:
            raise RuntimeError("No game servers available")
        
        # Simple load balancing: server with fewest active games
        return min(self.game_servers, key=lambda s: s.active_game_count)
```

### Game Server (Instance)

**Purpose**: Authoritative game simulation, state synchronization, anti-cheat validation.

**Game Server Architecture**:
```python
class GameServer:
    def __init__(self, server_id: str, ip: str, port: int):
        self.server_id = server_id
        self.ip = ip
        self.port = port
        self.active_games = {}  # game_id -> GameState
        self.active_game_count = 0
    
    def initialize_game(self, game_session: GameSession):
        """Initialize new game instance on this server"""
        game_state = GameState(
            game_id=game_session.game_id,
            difficulty=game_session.difficulty,
            act=1,
            map_seed=self.generate_map_seed(),
            players={},
            monsters={},
            items={},
            tick_count=0,
            last_tick_time=time.time()
        )
        
        self.active_games[game_session.game_id] = game_state
        self.active_game_count += 1
        
        # Start game simulation loop
        threading.Thread(target=self.game_loop, args=(game_state,), daemon=True).start()
    
    def game_loop(self, game_state: GameState):
        """
        Main game simulation loop
        
        Runs at 25 FPS (40ms per tick), synchronized with client
        """
        TICK_RATE = 0.040  # 40ms = 25 FPS
        
        while game_state.is_active:
            start_time = time.time()
            
            # Process player inputs
            self.process_player_inputs(game_state)
            
            # Update monster AI
            self.update_monsters(game_state)
            
            # Process collisions
            self.process_collisions(game_state)
            
            # Update projectiles
            self.update_projectiles(game_state)
            
            # Process buffs/debuffs
            self.update_effects(game_state)
            
            # Broadcast state updates to clients
            self.broadcast_state_update(game_state)
            
            # Increment tick
            game_state.tick_count += 1
            game_state.last_tick_time = start_time
            
            # Sleep to maintain consistent tick rate
            elapsed = time.time() - start_time
            if elapsed < TICK_RATE:
                time.sleep(TICK_RATE - elapsed)
    
    def process_player_inputs(self, game_state: GameState):
        """Process queued player actions"""
        for player_id, player in game_state.players.items():
            while player.input_queue:
                action = player.input_queue.pop(0)
                
                # Validate action is legal
                if not self.validate_action(game_state, player, action):
                    # Anti-cheat: flag suspicious action
                    self.flag_suspicious_action(player_id, action)
                    continue
                
                # Process action
                if action.type == 'MOVE':
                    self.move_player(game_state, player, action.destination)
                elif action.type == 'ATTACK':
                    self.process_attack(game_state, player, action.target)
                elif action.type == 'USE_SKILL':
                    self.use_skill(game_state, player, action.skill_id, action.target)
                elif action.type == 'PICKUP_ITEM':
                    self.pickup_item(game_state, player, action.item_id)
                elif action.type == 'DROP_ITEM':
                    self.drop_item(game_state, player, action.item_id)
    
    def validate_action(self, game_state: GameState, player: Player, action: Action) -> bool:
        """Anti-cheat: Validate player action is possible"""
        # Check player is alive
        if player.current_life <= 0:
            return False
        
        # Check cooldown
        if action.type == 'USE_SKILL':
            if player.skill_cooldowns.get(action.skill_id, 0) > game_state.tick_count:
                return False
        
        # Check distance for movement
        if action.type == 'MOVE':
            distance = self.calculate_distance(player.position, action.destination)
            max_distance_per_tick = player.walk_speed * 0.040  # 40ms tick
            if distance > max_distance_per_tick * 2:  # Allow some tolerance
                return False
        
        # Check inventory for item actions
        if action.type == 'PICKUP_ITEM':
            if not self.has_inventory_space(player):
                return False
        
        # Check mana cost for skills
        if action.type == 'USE_SKILL':
            skill = self.get_skill(action.skill_id)
            if player.current_mana < skill.mana_cost:
                return False
        
        return True
    
    def broadcast_state_update(self, game_state: GameState):
        """Send state update to all players in game"""
        # Create state snapshot
        state_update = {
            'tick': game_state.tick_count,
            'players': [self.serialize_player(p) for p in game_state.players.values()],
            'monsters': [self.serialize_monster(m) for m in game_state.monsters.values() if m.is_visible],
            'items': [self.serialize_item(i) for i in game_state.items.values() if i.is_on_ground],
            'projectiles': [self.serialize_projectile(p) for p in game_state.projectiles],
            'effects': game_state.active_effects
        }
        
        # Send to each player (can optimize with delta encoding)
        for player_id in game_state.players:
            self.send_to_player(player_id, state_update)
```

**Anti-Cheat Validation**:
```python
class AntiCheatService:
    def __init__(self):
        self.suspicious_actions = {}  # player_id -> list of flags
        self.ban_threshold = 10  # Auto-ban after 10 suspicious actions
    
    def validate_character_stats(self, character: Character) -> bool:
        """Verify character stats are legal"""
        # Check stat points allocated
        total_stats = (character.strength + character.dexterity + 
                      character.vitality + character.energy)
        expected_stats = 80 + (character.level - 1) * 5  # Base + level-up points
        
        if total_stats > expected_stats:
            return False
        
        # Check skill points
        total_skills = sum(s.level for s in character.skills)
        expected_skills = (character.level - 1)  # 1 skill point per level
        
        if total_skills > expected_skills:
            return False
        
        return True
    
    def validate_item_legitimacy(self, item: Item) -> bool:
        """Check if item properties are valid"""
        # Check if item can have those affixes
        if item.quality == 'rare':
            if len(item.affixes) > 6:  # Rares can have max 6 affixes
                return False
        
        # Check stat ranges
        for affix in item.affixes:
            min_val, max_val = self.get_affix_range(affix.name, item.item_type)
            if affix.value < min_val or affix.value > max_val:
                return False
        
        # Check for impossible item combinations
        if item.item_type == 'ring' and any(a.name == '+2 to All Skills' for a in item.affixes):
            return False  # Rings can't have +2 all skills
        
        return True
    
    def detect_speed_hack(self, player: Player, movement_history: List[Position]) -> bool:
        """Detect movement speed anomalies"""
        if len(movement_history) < 10:
            return False
        
        # Calculate average speed over last 10 ticks
        total_distance = 0
        for i in range(1, len(movement_history)):
            distance = self.calculate_distance(movement_history[i-1], movement_history[i])
            total_distance += distance
        
        avg_speed = total_distance / (len(movement_history) - 1)
        max_legal_speed = player.walk_speed * 1.2  # 20% tolerance
        
        return avg_speed > max_legal_speed
    
    def detect_maphack(self, player: Player, revealed_map: Set[Position]) -> bool:
        """Detect if player has revealed map areas they shouldn't see"""
        # Check if player has vision of areas far from their position
        for pos in revealed_map:
            distance = self.calculate_distance(player.position, pos)
            if distance > player.vision_range + 10:  # Tolerance
                return True
        
        return False
```

---

## Modern Implementation Blueprint

### Technology Stack (2025)

**Backend Services**:
```yaml
Authentication Service:
  - Language: Python 3.11 / Go 1.21
  - Framework: FastAPI / Gin
  - Database: PostgreSQL 15 (accounts, sessions)
  - Cache: Redis 7 (session store, rate limiting)
  - Security: OAuth2, JWT tokens, Argon2 password hashing

Character Service:
  - Language: Python 3.11 / C# .NET 8
  - Database: PostgreSQL 15 (characters, inventory)
  - Cache: Redis 7 (character cache)
  - Storage: S3-compatible (character snapshots)

Chat Service:
  - Language: Node.js 20 / Elixir
  - Framework: Socket.io / Phoenix Channels
  - Protocol: WebSocket
  - Database: PostgreSQL 15 (message history)
  - Cache: Redis 7 (presence, channels)

Game Coordinator:
  - Language: Go 1.21 / Rust
  - Database: PostgreSQL 15 (game sessions)
  - Cache: Redis 7 (game list, real-time state)
  - Message Queue: RabbitMQ / Apache Kafka

Game Server:
  - Language: C++ 20 / Rust
  - Simulation: Custom game engine (deterministic)
  - Networking: ENet / RakNet
  - Database: PostgreSQL 15 (persistence)
```

**Infrastructure**:
```yaml
Container Orchestration:
  - Kubernetes 1.28+
  - Docker 24+
  - Helm charts for deployment

Load Balancing:
  - NGINX Ingress Controller
  - HAProxy for TCP game traffic
  - Cloudflare for DDoS protection

Monitoring & Observability:
  - Prometheus + Grafana (metrics)
  - ELK Stack (logs)
  - Jaeger (distributed tracing)
  - Sentry (error tracking)

CI/CD:
  - GitHub Actions / GitLab CI
  - ArgoCD for GitOps
  - Automated testing (unit, integration, E2E)

Cloud Provider:
  - AWS / Azure / GCP
  - Multi-region deployment
  - Auto-scaling groups
  - CDN for static assets
```

**Client Integration**:
```yaml
Game Client:
  - Modify D2Multi.dll to point to custom server
  - REST API client for authentication
  - WebSocket client for chat (or keep TCP)
  - Binary protocol for game sessions (keep existing)

Web Client (Optional):
  - React + TypeScript
  - Character management dashboard
  - Ladder rankings viewer
  - Trade marketplace interface
```

### Modern API Design

**RESTful API Endpoints**:
```
# Authentication
POST   /api/v1/auth/register          # Create account
POST   /api/v1/auth/login             # Authenticate
POST   /api/v1/auth/logout            # End session
POST   /api/v1/auth/refresh           # Refresh JWT token
GET    /api/v1/auth/validate          # Validate session

# Characters
GET    /api/v1/characters             # List characters
POST   /api/v1/characters             # Create character
GET    /api/v1/characters/:id         # Get character details
PUT    /api/v1/characters/:id         # Update character
DELETE /api/v1/characters/:id         # Delete character
GET    /api/v1/characters/:id/stats   # Get character stats
GET    /api/v1/characters/:id/inventory  # Get inventory

# Games
GET    /api/v1/games                  # List available games
POST   /api/v1/games                  # Create game
GET    /api/v1/games/:id              # Get game details
POST   /api/v1/games/:id/join         # Join game
POST   /api/v1/games/:id/leave        # Leave game
DELETE /api/v1/games/:id              # Destroy game (host only)

# Chat (REST fallback, prefer WebSocket)
GET    /api/v1/chat/channels          # List channels
POST   /api/v1/chat/channels/:id/join # Join channel
POST   /api/v1/chat/messages          # Send message
GET    /api/v1/chat/messages/history  # Get message history

# Social
GET    /api/v1/friends                # Get friend list
POST   /api/v1/friends                # Add friend
DELETE /api/v1/friends/:id            # Remove friend
GET    /api/v1/friends/status         # Get online status

# Ladder
GET    /api/v1/ladder                 # Get ladder rankings
GET    /api/v1/ladder/:class          # Get class-specific ladder
```

**WebSocket Events**:
```
# Chat events
chat:join_channel      # Join chat channel
chat:leave_channel     # Leave channel
chat:message           # Send/receive chat message
chat:whisper           # Send/receive whisper
chat:user_joined       # User joined channel notification
chat:user_left         # User left channel notification

# Game events
game:list_updated      # Game list changed
game:player_joined     # Player joined game
game:player_left       # Player left game
game:host_changed      # Host migration notification

# Social events
friend:online          # Friend came online
friend:offline         # Friend went offline
friend:request         # Friend request received
```

### Deployment Architecture

**Multi-Region Deployment**:
```
                    ┌─────────────────────┐
                    │   Global CDN        │
                    │   (Cloudflare)      │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
    ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
    │   US East   │    │   US West   │    │   Europe    │
    │   Region    │    │   Region    │    │   Region    │
    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
           │                   │                   │
    ┌──────▼──────────────────────────────────────▼──────┐
    │         Kubernetes Cluster (per region)             │
    ├─────────────────────────────────────────────────────┤
    │                                                      │
    │  ┌────────────────┐  ┌────────────────┐           │
    │  │ Auth Service   │  │ Char Service   │           │
    │  │ (3 replicas)   │  │ (3 replicas)   │           │
    │  └────────────────┘  └────────────────┘           │
    │                                                      │
    │  ┌────────────────┐  ┌────────────────┐           │
    │  │ Chat Service   │  │ Game Coord     │           │
    │  │ (5 replicas)   │  │ (3 replicas)   │           │
    │  └────────────────┘  └────────────────┘           │
    │                                                      │
    │  ┌────────────────────────────────────────┐        │
    │  │ Game Servers (Auto-scaling 10-100)     │        │
    │  │ - Dedicated CPU pods                    │        │
    │  │ - 1 game per pod                        │        │
    │  │ - Scale based on demand                 │        │
    │  └────────────────────────────────────────┘        │
    │                                                      │
    │  ┌────────────────┐  ┌────────────────┐           │
    │  │ PostgreSQL     │  │ Redis Cluster  │           │
    │  │ (Primary +     │  │ (6 nodes)      │           │
    │  │  2 replicas)   │  │                │           │
    │  └────────────────┘  └────────────────┘           │
    │                                                      │
    └──────────────────────────────────────────────────────┘
```

**Auto-Scaling Configuration**:
```yaml
# Game Server Auto-Scaling
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: game-server-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: game-server
  minReplicas: 10
  maxReplicas: 100
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: active_games_per_pod
      target:
        type: AverageValue
        averageValue: "1"  # 1 game per pod
```

---

## Community Server Projects

**Existing Open-Source Implementations**:

1. **D2GS (Diablo 2 Game Server)**
   - C implementation of D2 game server
   - Reverse-engineered protocol
   - Linux-compatible
   - GitHub: Various forks available

2. **PvPGN (Player vs Player Gaming Network)**
   - Battle.net emulator for Diablo II, Starcraft, Warcraft
   - C++ implementation
   - Cross-platform
   - Active community
   - GitHub: pvpgn/pvpgn-server

3. **D2BS (Diablo 2 Bot Server)**
   - JavaScript automation framework
   - Includes server components
   - Protocol documentation
   - GitHub: noah-/d2bs

**Community Resources**:
- **PhrozenKeep**: Modding community with protocol documentation
- **D2Maniacs**: Private server hosting guides
- **Diablo Evolution**: Server emulation project

---

## Conclusion

Building a modern Battle.net-like service for Diablo II requires:

1. **Reverse Engineering**: Understanding original protocols from Game.exe/DLL analysis
2. **Modern Architecture**: Microservices, containers, cloud-native design
3. **Scalability**: Auto-scaling game servers, distributed databases
4. **Security**: Modern auth (OAuth2/JWT), anti-cheat, DDoS protection
5. **Performance**: Low-latency networking, optimized database queries
6. **Community**: Open-source collaboration, documentation

The original Battle.net (1999-2000) was revolutionary for its time, enabling millions to play together with commodity hardware. A modern implementation can improve on this foundation with:
- **Cloud scalability** (handle spikes during ladder resets)
- **Global reach** (low-latency servers worldwide)
- **Better security** (protect against modern exploits)
- **Enhanced features** (cross-realm play, better matchmaking)
- **Cost efficiency** (pay-per-use cloud resources)

**Total Estimated Cost** (AWS, moderate traffic):
- **Compute**: $500-2000/month (K8s cluster + game servers)
- **Database**: $200-500/month (RDS PostgreSQL)
- **Cache**: $100-300/month (ElastiCache Redis)
- **Bandwidth**: $200-1000/month (varies with player count)
- **Monitoring**: $100-200/month (observability tools)

**Total**: ~$1,100-4,000/month for 1,000-10,000 concurrent players

---

**Document End**
