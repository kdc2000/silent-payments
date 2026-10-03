"""Golden values for CHIP-0057 Test Vectors 1-4, with LEGACY recipient keys.

Canonical inputs (mnemonics + coin IDs) and the expected intermediate and final
values for four silent-payment test vectors: synthetic / scan / spend keys,
input hashes, shared secrets, output tweaks, one-time public keys, one-time
puzzle hashes, and the encoded one-time addresses. ``test_vectors.py`` drives
each value through the chia-wallet-sdk + glue and asserts equality against these
constants.

What these values are — and are not:

* They are deterministic test values, not on-chain data. The mnemonics are the
  public BIP-39 test mnemonics below and the coin IDs are SHA256 of fixed tags
  (``SHA256("test-vector-1-coin")`` and so on, as in the CHIP's Test Cases).
* The recipient scan/spend keys are LEGACY keys: they are derived from those
  mnemonics with the UNHARDENED paths m/12381/8444/12/0 (scan) and
  m/12381/8444/13/0 (spend). That is the derivation every silent payment address
  used before CHIP-0057 was revised to require hardened derivation, so these
  values pin exactly what a coin paid to such an address looks like. They are
  reproduced with ``sdk_adapter.legacy_unhardened_keys_from_mnemonic`` — the
  helper behind ``--legacy-keys`` — and never with ``keys_from_mnemonic``, which
  is hardened and yields different keys. The unhardened derivation must never be
  used for a new address.
* The CHIP's Test Vectors 1-7 take the same four key values as "given" keys
  (independent of any derivation path); Test Vector 8 covers the hardened
  derivation. Both are checked from the machine-readable vectors in
  ``test_chip0057_vectors.py``.
"""

# --- Canonical inputs (mnemonics + coin ids) ------------------------------

TV1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TV2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

# Coin ids: SHA256 of the named test-vector tags ("test-vector-1-coin", ...,
# "test-vector-4-coin-0", "test-vector-4-coin-1").
COIN_ID_TV1 = bytes.fromhex("5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175")
COIN_ID_TV2 = bytes.fromhex("b75c75c4787bade82b417272eff88ed90b3013a14b06c16be66b944856f378a2")
COIN_ID_TV3 = bytes.fromhex("4504f59ea184be18924f95244649287382ec6cdc13f333a8990f648c803a6dac")
COIN_ID_TV4_0 = bytes.fromhex("2b9857e0307ebfbe51829e3be8c992ae57f6a8debe06a5deab429ddae83a8c1a")
COIN_ID_TV4_1 = bytes.fromhex("209bb03a4cd165785e6149bc6dcb27e35829006f02ec927ab5a20521fd27d21a")

# ==========================================================================
# GOLDEN_* byte-truths for the CHIP test vectors.
# ==========================================================================

# --- Sender synthetic keys (TV1 derivation index 0; TV4 also uses index 1) -
GOLDEN_WALLET_SK_TV1_IDX0 = bytes.fromhex("6c8d1a9f97413f8d8e8c158f5bc875b58b498de05c9109b4dc240280d32e2a31")
GOLDEN_SYN_SK_TV1_IDX0 = bytes.fromhex("5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a")
GOLDEN_SYN_PK_TV1_IDX0 = bytes.fromhex("8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa")
GOLDEN_SYN_SK_TV1_IDX1 = bytes.fromhex("05fded8808216b65d439fc41cb07c7270e37ed743e0745652afe055cfe91cf0f")
GOLDEN_SYN_PK_TV1_IDX1 = bytes.fromhex("94c5c19f4343bc2655af729469285a392de9048851363b0b1329a4539a46ab4c6e8bfb39d32da25bffe4d9cdbe3e1061")

# --- Raw wallet pk + standard-wallet (m/12381/8444/2/<i>) puzzle hash (TV1 idx 0/1) -
GOLDEN_WALLET_SK_TV1_IDX1 = bytes.fromhex("2f8363418559dfc3a8df3f95aced6d80598e077977c65872eac2daba01f08959")
GOLDEN_WALLET_PK_TV1_IDX0 = bytes.fromhex("89e2f0cd40015e10ff92a1223acb5ce1de3c7d77163ee36896f095d6a1f118c797994291b7124c82d809802c5223d26c")
GOLDEN_WALLET_PK_TV1_IDX1 = bytes.fromhex("812fedcf029bf768677d5c376a192469b0fe00f080dcafe41697744af0668789d21eda8a7389d184dfaa67ddcd1fdd2c")
GOLDEN_STD_WALLET_PH_TV1_IDX0 = bytes.fromhex("792931431ba2976e36e3abc0b35c811948536bcf77f39a8d99ec2a15af0e84bc")
GOLDEN_STD_WALLET_PH_TV1_IDX1 = bytes.fromhex("a2c36282632ac4c1ec6125deca75c9928c65351ddab207655a45c3a4d921174c")

# --- TV1 recipient unlabeled silent-payment address (tspxch1…) -------------
# The SP (tspxch) address — distinct from GOLDEN_ADDRESS_TV1 (a txch one-time-PH address).
# NOTE (CHIP-0057 "Address Versioning"): this string is the PRE-VERSIONING
# encoding (no version character) of the legacy TV1 keys. Decoders reject it; the
# v0 encoding of the same two keys is CHIP Test Vector 5 (testnet).
GOLDEN_SP_ADDRESS_TV1 = "tspxch15p85qjlmlhynz9ek3x07xtfzwkasq7q52yxr2g6jjjr66atnvp6h8t0zp5cuw5g8kspnrllhntyfdzhutqqe9az04d3y7cfnd8me9mlnyg828j5z96urn2evjvy72f7m7me3ughqsvd62zyvj5nztf6uwsnlcstc"

# --- Send single-input one-time PH -----------------------------------------
# The single-input send fixture's recipient one-time puzzle hash
# (sender = TV1 wallet idx 0, coin parent bytes([1])*32 / amount 1000,
# recipient = TV1 SP address).
GOLDEN_SEND_ONETIME_PH_TV1_SINGLE = bytes.fromhex("cf4a72cea07550f6cb82b41cf211cfb56226bdea100c1df87cfe341144a19a60")

# --- Scan detection byte-truths (TV1 wallet-key senders) -------------------
# Offline scan fixtures: senders derived from TV1 wallet keys over a
# deterministic block; expected detection puzzle hash / one-time sk per scenario.
# SINGLE / change(m=0): sender idx0, parent "aa"*32 / amount 1_000_000, unlabeled.
GOLDEN_SCAN_SINGLE_PH = bytes.fromhex("2f0a9f89385aeb62aefe636d48eed907c56e8736955e1a76f7296a1c5ffccaa2")
GOLDEN_SCAN_SINGLE_ONETIME_SK = bytes.fromhex("5598c52c8cc85412322373ae59a2ef07b8aae9c107341241932f0f0bd7f93aa5")
# LABELED m=1: same single fixture but the recipient spend pk is B_m (m=1).
GOLDEN_SCAN_LABELED_M1_PH = bytes.fromhex("b53ca71a15ebc7b929872898e280e122b5e69a5cc8fa519e91c2e5c1d238b1ed")
GOLDEN_SCAN_LABELED_M1_ONETIME_SK = bytes.fromhex("2aa561e42fd3561a1a83205c22343ed31c63b009b1c6f43dc330e31f9c861f09")
# MULTI same-derivation-index (sp+sp, concurrent-spend SCC): senders [idx0, idx0].
GOLDEN_SCAN_SAME_INDEX_PH = bytes.fromhex("3020106a545d9689225864cb5677faf02ce235847407132d2b50e701f3c154a4")
# MULTI cross-derivation-index (idx0+idx1, opcode-64 concurrent-spend SCC): senders [idx0, idx1].
GOLDEN_SCAN_CONCURRENT_SPEND_PH = bytes.fromhex("d1c518a742653ed69a0c650ef172215cc8626977c1e6d6b92b68d7d60f34aa8a")
# Pollution defense: legit a<->b (idx0+idx1) vs polluted a+b+c (idx0+idx1+idx2).
GOLDEN_SCAN_POLLUTION_LEGIT_PH = bytes.fromhex("d1c518a742653ed69a0c650ef172215cc8626977c1e6d6b92b68d7d60f34aa8a")
GOLDEN_SCAN_POLLUTION_POLLUTED_PH = bytes.fromhex("c7e946668e5d203560f3a1d86672d5e002682937333e1c45d1ea0d09b1ec5ba0")

# --- Recipient keys --------------------------------------------------------
# These are the LEGACY keys: the UNHARDENED derivation (m/12381/8444/12/0 scan,
# m/12381/8444/13/0 spend) that addresses generated before the CHIP's
# hardened-derivation revision used. They are reproduced with
# sdk_adapter.legacy_unhardened_keys_from_mnemonic — NOT with keys_from_mnemonic,
# which is hardened. The CHIP's own vectors 1-7 use the same four values as
# "given" keys.
# TV1 recipient (mnemonic TV1): scan/spend sk+pk.
GOLDEN_SCAN_SK_TV1 = bytes.fromhex("132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6")
GOLDEN_SCAN_PK_TV1 = bytes.fromhex("a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896")
GOLDEN_SPEND_SK_TV1 = bytes.fromhex("53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087")
GOLDEN_SPEND_PK_TV1 = bytes.fromhex("8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74")
# TV2 recipient B (mnemonic TV2): scan/spend pk.
GOLDEN_SCAN_PK_TV2 = bytes.fromhex("904b64222fcc0bcf254bcfadcd579cf0530b4fba7ed454f3e6d85799cc9f54913f048f1fb393e4acf1bbe56d09d73108")
GOLDEN_SPEND_PK_TV2 = bytes.fromhex("99c454a391281b0c0c25ca8175d93ba9d6c4ce9dabe5a25e28b38c2e9ce66aabe50a73f64a477b212ce110dac1e79813")

# --- Input hashes (int) ----------------------------------------------------
GOLDEN_INPUT_HASH_TV1 = 0x38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411
GOLDEN_INPUT_HASH_TV2 = 0x42b39c642d50849aa93f23c34085d80bb6a236cad4e0edd2841d526838c92b22
GOLDEN_INPUT_HASH_TV3 = 0x58a1875602949aa6bfaf9cb4837957e7175ffb0b14422dbc8d371799f98e66f5
GOLDEN_INPUT_HASH_TV4 = 0x3f1071552b7f2f5e49b68166cb204f0a1b6a23b0c30a28bcba59a9c3f766e166

# --- TV1 single output (k=0) ----------------------------------------------
GOLDEN_SHARED_SECRET_TV1 = bytes.fromhex("d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6")
GOLDEN_OUTPUT_TWEAK_TV1 = 0x5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1
GOLDEN_ONETIME_PK_TV1 = bytes.fromhex("b671487c1d275842f529f7a73a63a32a9a1a49e1dbabcac4058cc48626b6db31f48dc49e769a6f8076a9111ff14e964d")
GOLDEN_ONETIME_PH_TV1 = bytes.fromhex("23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5")
GOLDEN_ADDRESS_TV1 = "txch1ywkm59yamyqq6e0qlr3pk6t4xextazdx8jh4v5ea7jmkvnppl06swd5m0t"
GOLDEN_ONETIME_SK_TV1 = bytes.fromhex("3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37")

# --- TV2 multi-output (two recipients, k=0) -------------------------------
# Recipient A (mnemonic TV1).
GOLDEN_SHARED_SECRET_TV2_A = bytes.fromhex("e9b20a7df882357c76abb4b5f87dcfc9a64cda6413c85f61efa1c4e81e1be50d")
GOLDEN_OUTPUT_TWEAK_TV2_A = 0x13682ff0957fce11761842863c1658c4cfe9dad4b312fb5fcd71f66567d33d9b
GOLDEN_ONETIME_PK_TV2_A = bytes.fromhex("97b332699dfd7741b3f0c8bf1e1a0edef3b4ad7a092a8f38d74f17216cfb1d0f5abe7d853f8e3223407be827c9c3aaa8")
GOLDEN_ONETIME_PH_TV2_A = bytes.fromhex("596275d286042c639d97e3765fe89d0e5554ac250e0fb4c594a9165017c0a9e5")
GOLDEN_ADDRESS_TV2_A = "txch1t938t55xqskx88vhudm9l6yape24ftp9pc8mf3v54yt9q97q48jsqly0xr"
# Recipient B (mnemonic TV2).
GOLDEN_SHARED_SECRET_TV2_B = bytes.fromhex("1450c748a04e4925bf34d0ef09e21fd1dab0eb0a3675efcb5b2da66d813c06e9")
GOLDEN_OUTPUT_TWEAK_TV2_B = 0x21d2901f3189dc8def5c5a29e84933a5543ceabd131653dd2ea1951523045976
GOLDEN_ONETIME_PK_TV2_B = bytes.fromhex("a2557b2b6029fcc6783e8447588311a06b5d3dcad132a318d40bf0d6114595dd3d14fd58fe6f6c88dfa190aaa6bef873")
GOLDEN_ONETIME_PH_TV2_B = bytes.fromhex("65249bcb907c9a6fac2e14499f6220cc24ba9359767d680c19405da06b69b263")
GOLDEN_ADDRESS_TV2_B = "txch1v5jfhjus0jdxltpwz3ye7c3qesjt4y6ewe7ksrqegpw6q6mfkf3s0xpfcj"

# --- TV3 labeled payment (m=1, k=0) ---------------------------------------
GOLDEN_LABEL_SCALAR_TV3 = 0x48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465
GOLDEN_LABEL_PK_TV3 = bytes.fromhex("a6dcff3646739745ef7f3ba8e51808dac13765fa9d5e73386d3fbd7841e0773e02a0f8d91baf57d337954322bd06d80c")
GOLDEN_LABELED_SPEND_PK_TV3 = bytes.fromhex("965250fb8503cff4c244f360ab84075bfe2da01091745d0e8ce36024ab12e96277d1f02fbbe01cee412dd2ce1b7414c2")
GOLDEN_SHARED_SECRET_TV3 = bytes.fromhex("3d1eabb622c40142d4b2557fc222a22cd93d98550255cecb2b6a84985f49215d")
GOLDEN_OUTPUT_TWEAK_TV3 = 0x301e842ace534f7de854dcc5a48a656d7e9a6d8b8f93db9fb8277f4d1889bdf1
GOLDEN_ONETIME_PK_TV3 = bytes.fromhex("97e7466509081a3ed6e50ba0231a6fa1b48d8c910ac6ec933e26cd5091569c615f299726c91a730dbf51a26cb249f17c")
GOLDEN_ONETIME_PH_TV3 = bytes.fromhex("ba271d218d487e8e5dc994a09a8580e1e8a0559a615bd5805cff11b5a343441c")
GOLDEN_ADDRESS_TV3 = "txch1hgn36gvdfplguhwfjjsf4pvqu852q4v6v9datqzulugmtg6rgswqpr9rsm"
GOLDEN_ONETIME_SK_BASE_TV3 = bytes.fromhex("10021d8ab756b398cb4c4732864c264981e39a898e1ff4ea487b8f39f1bb6e77")
GOLDEN_LABELED_ONETIME_SK_TV3 = bytes.fromhex("58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc")

# --- TV4 multi-input (2 sender coins, agg keys, k=0) ----------------------
GOLDEN_AGG_SK_TV4 = bytes.fromhex("5600d8781de32f0f3d86bc96b46a3a4ea56ae26da168b55dc66b503acbf95b89")
GOLDEN_AGG_PK_TV4 = bytes.fromhex("a223ab27f801044cd98c8314014b8073347b0e5aae43c69b78b5ca2a562ee9f799b8efad179b34da1b306ca4d62bad40")
GOLDEN_SHARED_SECRET_TV4 = bytes.fromhex("e729dea8c4732747d0e5e930607c52ddfce01ff7c72eaec9ee7c84131e078494")
GOLDEN_OUTPUT_TWEAK_TV4 = 0x18fafd6001bef3fece078f469731b40a5f362994795f9ff6b9339aa235fee312
GOLDEN_ONETIME_PK_TV4 = bytes.fromhex("b71f484e6d90a657b215ad7bff6f96a8d9bff07e0133d74917cc6c3ef6fa273a706aa56e1fd6da19ed5466f16450ccb1")
GOLDEN_ONETIME_PH_TV4 = bytes.fromhex("5d7fc7d7447c746cfb400e801a169fc7bfd1c13e03bc7866e6b743860a53ac6b")
GOLDEN_ADDRESS_TV4 = "txch1t4lu046y036xe76qp6qp595lc7larsf7qw78sehxkapcvzjn434s43wctu"
GOLDEN_ONETIME_SK_TV4 = bytes.fromhex("6ccc3e13145fd561e438d1bb82954cebb63cfa9577ea15404987aa8e0f309399")
