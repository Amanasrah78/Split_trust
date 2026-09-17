module split_trust_commitments::commitment_registry {
    use iota::event;

    const E_INVALID_TAG_LENGTH: u64 = 1;
    const E_INVALID_COMMITMENT_LENGTH: u64 = 2;
    const E_INVALID_SESSION_ID_LENGTH: u64 = 3;

    public struct CommitmentSubmitted has copy, drop {
        tag: vector<u8>,
        commitment: vector<u8>,
        session_id: vector<u8>,
    }

    public entry fun submit(
        tag: vector<u8>,
        commitment: vector<u8>,
        session_id: vector<u8>,
    ) {
        assert!(vector::length(&tag) == 16, E_INVALID_TAG_LENGTH);
        assert!(vector::length(&commitment) == 32, E_INVALID_COMMITMENT_LENGTH);
        assert!(vector::length(&session_id) == 32, E_INVALID_SESSION_ID_LENGTH);
        event::emit(CommitmentSubmitted { tag, commitment, session_id });
    }
}
