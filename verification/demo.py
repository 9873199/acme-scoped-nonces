import unittest
from contract_checks import Contract
checks=[('test_single_badnonce_preserves_one_serialization', 'Payload is serialized once during retry'), ('test_post_as_get_has_empty_payload', 'POST-as-GET keeps an empty payload'), ('test_transport_error_is_not_retried', 'Transport error does not repeat the request'), ('test_pool_capacity_expiry_and_atomic_claim', 'Pool bounds and single-use claims'), ('test_scopes_do_not_mix_same_nonce_bytes', 'Directories keep separate nonce pools'), ('test_badnonce_duplicate_cannot_be_claimed_by_two_requests', 'Error retry keeps the nonce single-use'), ('test_base64url_padding_is_rejected', 'Nonce encoding rejects padding')]
print("Offline ACME nonce checks")
passed=0
for name,label in checks:
    result=unittest.TestResult()
    Contract(name).run(result)
    ok=result.wasSuccessful(); passed+=int(ok)
    print(("PASS  " if ok else "FAIL  ")+label,flush=True)
print("Passed:",passed," Failed:",len(checks)-passed)
raise SystemExit(0 if passed==len(checks) else 1)
