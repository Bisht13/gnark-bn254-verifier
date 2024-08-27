pub(crate) const ERR_BSB22_COMMITMENT_MISMATCH: &str = "BSB22 Commitment number mismatch";
pub(crate) const ERR_INVALID_WITNESS: &str = "Invalid witness";
pub(crate) const ERR_CHALLENGE_ALREADY_COMPUTED: &str = "Challenge already computed";
pub(crate) const ERR_CHALLENGE_NOT_FOUND: &str = "Challenge not found";
pub(crate) const ERR_PREVIOUS_CHALLENGE_NOT_COMPUTED: &str = "Previous challenge not computed";
pub(crate) const ERR_INVALID_NUMBER_OF_DIGESTS: &str = "Invalid number of digests";
pub(crate) const ERR_UNEXPECTED_GNARK_FLAG: &str = "Unexpected gnark flag";
pub(crate) const ERR_INVALID_GNARK_X_LENGTH: &str = "Invalid gnark x length";
pub(crate) const ERR_PAIRING_CHECK_FAILED: &str = "Pairing check failed";
pub(crate) const ERR_INVERSE_NOT_FOUND: &str = "Inverse not found";
pub(crate) const ERR_OPENING_POLY_MISMATCH: &str = "Opening linear polynomial mismatch";
pub(crate) const ERR_ELL_TOO_LARGE: &str = "ell too large";
pub(crate) const ERR_DST_TOO_LARGE: &str = "dst too large";

pub(crate) const GAMMA: &str = "gamma";
pub(crate) const BETA: &str = "beta";
pub(crate) const ALPHA: &str = "alpha";
pub(crate) const ZETA: &str = "zeta";

pub const GNARK_MASK: u8 = 0b11 << 6;
pub const GNARK_COMPRESSED_POSTIVE: u8 = 0b10 << 6;
pub const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

pub const ARK_MASK: u8 = 0b11 << 6;
pub const ARK_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
pub const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
pub const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;
