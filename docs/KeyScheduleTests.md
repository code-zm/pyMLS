#### Test Cases:
1. `test_derive_secret` Tests the `deriveSecret` method with a specific label and context.
    - Expected Outcome:
        - The derived secret has a length of 32 bytes.

2. `test_inject_pre_shared_key` Validates the injection of a pre-shared key into the key schedule.
    - Expected Outcome:
        - The `currentEpochSecret` is correctly updated with the PSK.

3. `test_export_secret` Tests exporting a secret with a label and context.
    - Expected Outcome:
        - The exported secret matches the expected derivation.

4. `test_derive_epoch_authenticator` Confirms the derivation of an epoch authenticator.
    - Expected Outcome:
        - The authenticator is derived correctly using the `confirmationKey`.

5. `test_next_epoch` Validates the transition to a new epoch.
    - Expected Outcome:
        - Secrets for the next epoch are correctly derived based on `commitSecret`, `context`, and transcript hash.

6. `test_get_epoch_secrets` Ensures all secrets for the current epoch are retrievable.
    - Expected Outcome:
        - The returned dictionary contains all required secrets.

7. `test_update_for_commit` Tests the `updateForCommit` method for advancing epochs.
    - Expected Outcome:
        - The `epoch` counter is incremented, and secrets are updated.
